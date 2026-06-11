"""
Certior API Server - FastAPI application.

Provides REST and WebSocket endpoints for verified task execution,
compliance export, and real-time monitoring.

Mode selection:
  If ANTHROPIC_API_KEY or OPENAI_API_KEY is set → agentic mode (reactive LLM loop)
  Otherwise → legacy mode (plan-based orchestrator)
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from agentsafe.cloud import (
    StateStore, EventBus, ExecutorService,
    WebhookManager, ExecutionStream, TaskQueue, WorkflowStore,
)
from .api.routes import (
    agents,
    auth,
    compliance,
    executions,
    releases,
    settings,
    tasks,
    tokens,
    trust,
    usecases,
    workflows,
    ws,
)

log = logging.getLogger(__name__)

OPENAPI_TAGS = [
    {"name": "auth", "description": "API-key lifecycle and identity endpoints."},
    {"name": "tasks", "description": "Submit verified tasks with compliance-gated permissions."},
    {"name": "executions", "description": "Track, list, and cancel execution jobs."},
    {"name": "compliance", "description": "Compliance presets and exportable audit packages."},
    {"name": "settings", "description": "Runtime LLM provider/model selection and status."},
    {"name": "workflows", "description": "First-class sequential multi-agent workflow orchestration."},
    {"name": "websocket", "description": "Real-time execution event streams."},
    {"name": "use-cases", "description": "Production templates for single-agent and multi-agent workflows."},
    {"name": "releases", "description": "Release decision, promotion, and GitHub webhook ingestion."},
    {"name": "trust", "description": "Public trust badge for a repo's verification status."},
    {"name": "agents", "description": "Multi-agent delegation, verification, and glass-box audit records."},
]

# ---------------------------------------------------------------------------
# LLM / tool configuration
# ---------------------------------------------------------------------------

def _build_llm_config():
    """Build LLMConfig from environment - auto-detects provider."""
    try:
        from agentsafe.llm.config import LLMConfig
        config = LLMConfig.from_env()
        if config.is_configured:
            log.info(
                "LLM configured: provider=%s  model=%s  (agentic mode enabled)",
                config.provider, config.model,
            )
            return config
        log.info("No LLM API key found - running in legacy mode")
    except ImportError:
        pass
    return None


def _build_tool_registry():
    """Build default tool registry."""
    try:
        from agentsafe.tools import create_default_registry
        workspace = os.getenv("CERTIOR_WORKSPACE", "/tmp/certior-workspace")
        registry = create_default_registry(workspace=workspace)
        tool_names = [t.name for t in registry.list_all()]
        log.info("Tool registry: %s", tool_names)
        return registry, tool_names
    except ImportError:
        return None, []


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Build the configured FastAPI application."""

    # ── Persistence backend selection ──────────────────────────────
    #
    # Priority:  DATABASE_URL (PostgreSQL)
    #          > REDIS_URL    (Celery/Redis task queue)
    #          > CERTIOR_DATA_DIR (SQLite)
    #          > in-memory (tests / minimal)
    #
    # PostgreSQL provides state_store + event_bus.
    # Redis provides the task queue (otherwise in-process asyncio).
    # They combine: you can use PG state + Redis queue together.

    database_url = os.getenv("DATABASE_URL")
    redis_url = os.getenv("REDIS_URL")
    data_dir = os.getenv("CERTIOR_DATA_DIR")
    certior_env = os.getenv("CERTIOR_ENV", "development").lower()
    fail_fast_on_pg_error = bool(database_url) and certior_env == "production"

    state_store = None
    workflow_store = None
    event_bus = None
    queue = None

    # ── PostgreSQL state store + event bus ────────────────────────
    _pg_needs_init = False
    if database_url:
        try:
            from agentsafe.cloud.postgres_backend import PgStateStore, PgEventBus, PgWorkflowStore

            # Create objects but DON'T initialize yet - asyncpg pools
            # must be created inside the running event loop (lifespan).
            state_store = PgStateStore(database_url)
            workflow_store = PgWorkflowStore(database_url)
            event_bus = PgEventBus(database_url)
            _pg_needs_init = True
            log.info("PostgreSQL configured (%s) - pool starts at lifespan",
                      database_url.split("@")[-1])
        except Exception as exc:
            log.warning("PostgreSQL setup failed (%s), trying next backend", exc)

    # ── Redis / Celery task queue ────────────────────────────────
    if redis_url:
        try:
            from agentsafe.cloud.redis_backend import CeleryTaskQueue
            queue = CeleryTaskQueue(redis_url)
            log.info("Using Celery/Redis task queue (%s)", redis_url)
        except Exception as exc:
            log.warning("Redis queue init failed (%s), using in-process queue", exc)

    # ── SQLite fallback for state + events (if PG not used) ──────
    if state_store is None and data_dir:
        try:
            from agentsafe.cloud.sqlite_backend import (
                SQLiteStateStore, SQLiteTaskQueue, SQLiteEventBus, SQLiteWorkflowStore,
            )
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "certior_state.db")
            workflow_db_path = os.path.join(data_dir, "certior_workflows.db")

            def _init_sqlite():
                s = SQLiteStateStore(db_path)
                w = SQLiteWorkflowStore(workflow_db_path)
                q = SQLiteTaskQueue(os.path.join(data_dir, "certior_tasks.db"))
                b = SQLiteEventBus(os.path.join(data_dir, "certior_events.db"))
                for obj in (s, w, q, b):
                    obj._init_db_sync()
                return s, w, q, b

            _s, _w, _q, _b = _init_sqlite()
            state_store = _s
            workflow_store = _w
            event_bus = _b
            if queue is None:
                queue = _q
            log.info("Using SQLite persistence in %s", data_dir)
        except Exception as exc:
            log.warning("SQLite init failed (%s), falling back to in-memory", exc)

    # ── In-memory fallback ───────────────────────────────────────
    if state_store is None:
        state_store = StateStore()
    if workflow_store is None:
        workflow_store = WorkflowStore()
    if event_bus is None:
        event_bus = EventBus()
    if queue is None:
        queue = TaskQueue()

    webhook_mgr = WebhookManager()
    stream = ExecutionStream()
    runtime_llm_credentials: Dict[str, Dict[str, str]] = {}
    workflow_runtime_llm_credentials: Dict[str, Dict[str, Dict[str, str]]] = {}

    # LLM + tools
    llm_config = _build_llm_config()
    tool_registry, tool_names = _build_tool_registry()

    system_prompt = os.getenv("CERTIOR_SYSTEM_PROMPT", (
        "You are Certior, a verified AI agent. Every tool call you make is "
        "formally verified against capability tokens before execution. "
        "Use the available tools to complete the user's task accurately and safely."
    ))

    executor_svc = ExecutorService(
        state_store=state_store,
        event_bus=event_bus,
        webhook_manager=webhook_mgr,
        llm_config=llm_config,
        tool_registry=tool_registry,
        system_prompt=system_prompt,
        runtime_llm_credentials=runtime_llm_credentials,
    )

    mode = executor_svc.mode
    log.info("Certior starting in %s mode", mode)

    # Wire event bus → WebSocket stream
    async def _forward_event(event):
        from agentsafe.cloud.websocket import StreamUpdate
        await stream.emit(StreamUpdate(
            execution_id=event.execution_id,
            status=event.type.split(".")[-1] if "." in event.type else event.type,
            data=event.data,
        ))

    event_bus.subscribe("*", _forward_event)

    # Lifespan
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal state_store, workflow_store, event_bus

        # Initialize PostgreSQL pools in the running event loop
        if _pg_needs_init:
            try:
                await state_store.initialize()
                await workflow_store.initialize()
                await event_bus.initialize()
                log.info("PostgreSQL pools ready")
            except Exception as exc:
                log.error("PostgreSQL init failed at startup (%s) - falling back to in-memory", exc)
                if fail_fast_on_pg_error:
                    log.error("PostgreSQL init failed at startup (%s) - refusing to start in production", exc)
                    raise RuntimeError(
                        "DATABASE_URL is configured but PostgreSQL initialization failed in production. "
                        "Start PostgreSQL or correct DATABASE_URL before starting Certior."
                    ) from exc
                state_store = StateStore()
                workflow_store = WorkflowStore()
                event_bus = EventBus()
                app.state.state_store = state_store
                app.state.workflow_store = workflow_store
                app.state.event_bus = event_bus
                # Re-wire executor
                app.state.executor.state = state_store
                app.state.executor.events = event_bus

        await queue.start()
        yield
        await queue.stop()
        # Close pools if using PostgreSQL
        if hasattr(state_store, "close"):
            await state_store.close()
        if hasattr(event_bus, "close"):
            await event_bus.close()

    app = FastAPI(
        title="Certior Verified Agent API",
        summary="Mathematically verified agent orchestration platform.",
        description=(
            "**Certior** is a production runtime that enforces formal verification constraints on LLM agents. "
            "It intercepts every tool call and validates it against a **Lean 4** compliance lattice and **Z3** solver constraints "
            "before execution.\n\n"
            "## Key Capabilities\n"
            "* **Policy Ceilings**: Hard limits on agent permissions (HIPAA, SOX).\n"
            "* **Verified Execution**: Sub-millisecond constraint solving for every action.\n"
            "* **Audit Trails**: Immutable JSON/PDF proof certificates for all operations.\n\n"
            "## Getting Started\n"
            "1. **Authenticate**: Get an API Key via `/api/v1/auth/register` (or use admin key).\n"
            "2. **Configure**: Set your LLM provider via `/api/v1/settings/provider`.\n"
            "3. **Execute**: Submit tasks to `/api/v1/tasks` with a compliance policy.\n\n"
            "Authentication: use `Authorization: Bearer <ck-...>` or `X-API-Key: <ck-...>`."
        ),
        version="0.1.0a1",
        contact={"name": "Certior", "url": "https://github.com/paulinebourigault/certior/issues"},
        license_info={"name": "Apache-2.0"},
        terms_of_service="https://github.com/paulinebourigault/certior",
        openapi_tags=OPENAPI_TAGS,
        redoc_url="/redoc",
        swagger_ui_parameters={
            "displayRequestDuration": True,
            "docExpansion": "none",
            "defaultModelsExpandDepth": 1,
            "persistAuthorization": True,
        },
        lifespan=lifespan,
    )

    # Store on app state for route access
    app.state.state_store = state_store
    app.state.workflow_store = workflow_store
    app.state.event_bus = event_bus
    app.state.executor = executor_svc
    app.state.stream = stream
    app.state.queue = queue
    app.state.llm_config = llm_config
    app.state.tool_registry = tool_registry
    app.state.runtime_llm_credentials = runtime_llm_credentials
    app.state.workflow_runtime_llm_credentials = workflow_runtime_llm_credentials

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routes
    app.include_router(auth.router)
    app.include_router(tasks.router)
    app.include_router(executions.router)
    app.include_router(compliance.router)
    app.include_router(tokens.router)
    app.include_router(settings.router)
    app.include_router(workflows.router)
    app.include_router(ws.router)
    app.include_router(usecases.router)
    # Mount the additional API surface routers. The /api/v1/releases,
    # /api/v1/trust/badge, and /api/v1/agents/* namespaces are part of
    # the documented API and are exercised by the integration tests.
    app.include_router(releases.router)
    app.include_router(trust.router)
    app.include_router(agents.router)

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            summary=app.summary,
            description=app.description,
            routes=app.routes,
            contact=app.contact,
            license_info=app.license_info,
            terms_of_service=app.terms_of_service,
        )
        schema["servers"] = [
            {"url": "http://127.0.0.1:8000", "description": "Local development"},
        ]
        schema["externalDocs"] = {
            "description": "Production runbooks and operational guidance",
            "url": "/api/v1/use-cases/production/playbook/page",
        }
        schema["x-logo"] = {
            "url": "/favicon.ico",
            "altText": "Certior",
            "backgroundColor": "#04070d",
        }
        schema["x-tagGroups"] = [
            {"name": "Platform", "tags": ["auth", "settings", "tokens"]},
            {"name": "Execution", "tags": ["tasks", "executions", "workflows", "websocket"]},
            {"name": "Governance", "tags": ["compliance", "use-cases"]},
        ]
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    # Health
    @app.get("/health")
    async def health():
        providers_available = {}
        if os.getenv("ANTHROPIC_API_KEY"):
            providers_available["anthropic"] = True
        if os.getenv("OPENAI_API_KEY"):
            providers_available["openai"] = True

        return {
            "status": "ok",
            "version": "0.5.0",
            "mode": mode,
            "tools": tool_names,
            "llm_configured": llm_config is not None and llm_config.is_configured,
            "llm_provider": llm_config.provider if llm_config and llm_config.is_configured else None,
            "llm_model": llm_config.model if llm_config and llm_config.is_configured else None,
            "providers_available": providers_available,
        }

    # Root - minimal landing page with links
    @app.get("/", include_in_schema=False)
    async def root():
        from fastapi.responses import HTMLResponse
        studio_url = os.getenv("CERTIOR_STUDIO_URL", "http://127.0.0.1:3001")
        return HTMLResponse(
            f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Certior</title>
  <style>
        :root {{
            --bg-dark: #0e1619; --bg-card: #152127; --bg-card-hover: #1d2b33;
            --border: #253640; --text-main: #f5f7f4; --text-sub: #a6b6b0;
            --accent: #4ca8a0; --success: #64b489; --warn: #f1b768; --err: #dd7d67;
        }}
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:'Inter',system-ui,sans-serif;background:#0e1619;color:#d7e0db;display:flex;flex-direction:column;align-items:center;min-height:100vh;padding:2rem}}
        .container{{max-width:1000px;width:100%;display:grid;grid-template-columns:1fr 1fr;gap:4rem;align-items:center;margin-top:4rem}}
        .hero h1{{font-size:3rem;color:#f5f7f4;line-height:1.1;letter-spacing:-0.03em;margin-bottom:1.5rem}}
        .hero h1 span{{color:#4ca8a0}}
        .hero p{{font-size:1.15rem;color:#a6b6b0;line-height:1.6;margin-bottom:2.5rem;max-width:520px}}
        .btn{{display:inline-flex;align-items:center;justify-content:center;background:#4ca8a0;color:#0e1619;padding:0.9rem 1.8rem;border-radius:10px;font-weight:600;text-decoration:none;transition:all .2s;border:1px solid transparent}}
        .btn:hover{{background:#58b8af;transform:translateY(-1px)}}
        .btn-sec{{background:rgba(255,255,255,0.04);color:#f0f4f1;border:1px solid #253640;margin-left:1rem}}
        .btn-sec:hover{{background:rgba(255,255,255,0.08);border-color:#36505e}}
        .visual{{position:relative}}
        .card-stack{{background:#152127;border:1px solid #253640;border-radius:16px;padding:2rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}}
        .tech-row{{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;padding-bottom:1.5rem;border-bottom:1px solid #253640}}
        .tech-row:last-child{{margin-bottom:0;padding-bottom:0;border-bottom:none}}
        .tech-icon{{width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.2rem;background:#22333b;color:#fff}}
        .tech-info h3{{color:#f1f5f9;font-size:1rem;margin-bottom:0.25rem}}
        .tech-info p{{color:#7e938c;font-size:0.85rem}}
        .status-bar{{margin-top:6rem;width:100%;max-width:1000px;border-top:1px solid #253640;padding-top:2rem;display:flex;justify-content:space-between;align-items:center;color:#70847d;font-size:0.85rem}}
        .status-pill{{display:flex;align-items:center;gap:6px;background:rgba(100,180,137,.12);color:#64b489;padding:4px 10px;border-radius:99px;font-size:0.75rem;font-weight:600}}
        .status-pill svg{{width:12px;height:12px}}
        @media (max-width: 900px) {{ .container{{grid-template-columns:1fr;text-align:center;margin-top:2rem;gap:2rem}} .hero p{{margin:0 auto 2rem}} .status-bar{{flex-direction:column;gap:1rem}} }}
  </style>
</head>
<body>

  <div class="container">
    <div class="hero">
            <h1>Certior for <span>Verified Agents</span></h1>
            <p>Certior is the verified execution runtime. Launch Certior Studio for the primary web experience, or use the API directly for integration and automation.</p>
      <div>
                <a href="{studio_url}" class="btn">Launch Certior Studio &rarr;</a>
        <a href="/docs" class="btn btn-sec">API Docs</a>
      </div>
    </div>
    
    <div class="visual">
      <div class="card-stack">
        <div class="tech-row">
          <div class="tech-icon" style="background:rgba(168,85,247,0.1);color:#a855f7">L</div>
          <div class="tech-info">
            <h3>Lean 4 Logic</h3>
            <p>Formal verification of compliance lattices (HIPAA, SOX).</p>
          </div>
        </div>
        <div class="tech-row">
          <div class="tech-icon" style="background:rgba(245,158,11,0.1);color:#f59e0b">Z</div>
          <div class="tech-info">
            <h3>Z3 Solver</h3>
            <p>SMT-based constraint solving for budget & scope safety.</p>
          </div>
        </div>
        <div class="tech-row">
          <div class="tech-icon" style="background:rgba(236,72,153,0.1);color:#ec4899">D</div>
          <div class="tech-info">
            <h3>Dafny Safety</h3>
            <p>Verified systems code for low-level resource sandboxing.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <div class="status-bar">
    <div class="status-pill">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17l-5-5"/></svg>
      System Online v0.5.0
    </div>
    <div>
            Running in <strong>{mode}</strong> mode &middot; {len(tool_names)} tools active
    </div>
    <div>
      <a href="/health" style="color:#64748b;text-decoration:none">System Health</a>
    </div>
  </div>

</body>
</html>"""
        )

    # Favicon - inline SVG shield
    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        from fastapi.responses import Response
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"'
            ' stroke="#34d399" stroke-width="2"><path d="M12 2l7 3.5v5c0 5.25-3'
            ' 9.5-7 11-4-1.5-7-5.75-7-11v-5L12 2z"/><path d="M9 12l2 2 4-4"'
            ' stroke-linecap="round" stroke-linejoin="round"/></svg>'
        )
        return Response(content=svg, media_type="image/svg+xml")

    return app


def main() -> None:
    """Entry point for ``certior-server`` console script."""
    import uvicorn

    host = os.getenv("CERTIOR_HOST", "0.0.0.0")
    port = int(os.getenv("CERTIOR_PORT", "8000"))
    reload = os.getenv("CERTIOR_ENV", "development") == "development"

    # Use import string (not app object) so uvicorn reload works correctly.
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    main()
