"""
Certior Celery Worker Entry Point.

Registers the execute_verified_task handler so the Celery worker
can process queued tasks.

Usage:
    celery -A app.worker worker --loglevel=info --concurrency=4
"""
from __future__ import annotations

import asyncio
import logging
import os

log = logging.getLogger(__name__)

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

from agentsafe.cloud.redis_backend import CeleryTaskQueue  # noqa: E402

_queue = CeleryTaskQueue(redis_url)


def _build_executor():
    """Build ExecutorService inside an already-running event loop."""
    from agentsafe.cloud import StateStore, EventBus, ExecutorService, WebhookManager

    try:
        from agentsafe.llm.config import LLMConfig
        llm_config = LLMConfig.from_env()
    except Exception:
        llm_config = None

    try:
        from agentsafe.tools.registry import ToolRegistry
        tool_registry = ToolRegistry()
        tool_registry.register_builtins()
    except Exception:
        tool_registry = None

    database_url = os.getenv("DATABASE_URL")
    if database_url:
        try:
            from agentsafe.cloud.postgres_backend import PgStateStore, PgEventBus
            state_store = PgStateStore(database_url)
            event_bus = PgEventBus(database_url)
        except Exception as exc:
            log.warning("Worker: postgres unavailable (%s), in-memory fallback", exc)
            state_store = StateStore()
            event_bus = EventBus()
    else:
        state_store = StateStore()
        event_bus = EventBus()

    return ExecutorService(
        state_store=state_store,
        event_bus=event_bus,
        webhook_manager=WebhookManager(),
        llm_config=llm_config,
        tool_registry=tool_registry,
        system_prompt=os.getenv(
            "CERTIOR_SYSTEM_PROMPT",
            "You are Certior, a verified AI agent. Every tool call you make is "
            "formally verified against capability tokens before execution.",
        ),
    )


async def _run_execution(execution_id: str):
    """Fresh executor + asyncpg pool per task (safe for Celery prefork)."""
    executor = _build_executor()
    state = executor.state
    if hasattr(state, 'initialize') and getattr(state, '_pool', True) is None:
        await state.initialize()
    ev = executor.events
    if hasattr(ev, 'initialize') and getattr(ev, '_pool', True) is None:
        await ev.initialize()
    try:
        return await executor.execute(execution_id)
    finally:
        if hasattr(state, 'close'):
            await state.close()
        if hasattr(ev, 'close'):
            await ev.close()


def _execute_verified_task_handler(execution_id: str):
    """Sync wrapper - asyncio.run() creates a fresh event loop per task."""
    return asyncio.run(_run_execution(execution_id))


_queue.register("execute_verified_task", _execute_verified_task_handler)

# Module-level Celery app for `celery -A app.worker`
app = _queue._app
