"""
PostgreSQL persistence backend for Certior cloud layer.

Provides production-grade replacements for the in-memory StateStore
and EventBus using asyncpg (pure-Python async PostgreSQL driver).

Connection management:
  - asyncpg connection pool with configurable min/max connections
  - Automatic reconnection on transient failures
  - Clean shutdown via close()

Schema management:
  - initialize() creates tables and indexes idempotently (IF NOT EXISTS)
  - All writes use parameterised queries (SQL injection safe)
  - JSON fields stored as JSONB for efficient querying

Usage:
    store = PgStateStore("postgresql://certior:certior@localhost/certior")
    await store.initialize()

    bus = PgEventBus("postgresql://certior:certior@localhost/certior")
    await bus.initialize()

Or use the factory:
    store, bus = await create_pg_backend("postgresql://...")
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from .state_store import Execution, ExecutionStatus
from .workflow_store import Workflow, WorkflowStage, WorkflowStatus
from .event_bus import Event, EventHandler

log = logging.getLogger(__name__)

# ── Guard import ──────────────────────────────────────────────────────

try:
    import asyncpg  # type: ignore[import-untyped]
    _HAS_ASYNCPG = True
except ImportError:
    asyncpg = None  # type: ignore[assignment]
    _HAS_ASYNCPG = False


def _require_asyncpg() -> None:
    if not _HAS_ASYNCPG:
        raise ImportError(
            "asyncpg is required for PostgreSQL persistence. "
            "Install: pip install 'certior[postgres]' or pip install asyncpg"
        )


# ── SQL DDL ───────────────────────────────────────────────────────────

_EXECUTIONS_DDL = """\
CREATE TABLE IF NOT EXISTS executions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    task            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'queued',
    plan            JSONB,
    current_step    INTEGER NOT NULL DEFAULT 0,
    results         JSONB,
    certificates    JSONB NOT NULL DEFAULT '[]'::jsonb,
    error           TEXT NOT NULL DEFAULT '',
    webhook_url     TEXT NOT NULL DEFAULT '',
    created_at      DOUBLE PRECISION NOT NULL,
    updated_at      DOUBLE PRECISION NOT NULL,
    completed_at    DOUBLE PRECISION,
    token_id        TEXT NOT NULL DEFAULT '',
    cost_cents      INTEGER NOT NULL DEFAULT 0,
    token_data      JSONB,
    llm_provider    TEXT,
    llm_model       TEXT
);
CREATE INDEX IF NOT EXISTS idx_exec_user_status ON executions (user_id, status);
CREATE INDEX IF NOT EXISTS idx_exec_created     ON executions (created_at DESC);
"""

_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    type            TEXT NOT NULL,
    execution_id    TEXT NOT NULL DEFAULT '',
    data            JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp       DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evt_exec ON events (execution_id);
CREATE INDEX IF NOT EXISTS idx_evt_type ON events (type);
CREATE INDEX IF NOT EXISTS idx_evt_ts   ON events (timestamp DESC);
"""

_WORKFLOWS_DDL = """\
CREATE TABLE IF NOT EXISTS workflows (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    user_role           TEXT NOT NULL DEFAULT 'operator',
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    mode                TEXT NOT NULL DEFAULT 'sequential',
    status              TEXT NOT NULL DEFAULT 'queued',
    created_at          DOUBLE PRECISION NOT NULL,
    updated_at          DOUBLE PRECISION NOT NULL,
    completed_at        DOUBLE PRECISION,
    current_stage_index INTEGER NOT NULL DEFAULT 0,
    error               TEXT NOT NULL DEFAULT '',
    stages              JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_workflows_user_status ON workflows (user_id, status);
CREATE INDEX IF NOT EXISTS idx_workflows_created     ON workflows (created_at DESC);
"""


# ══════════════════════════════════════════════════════════════════════
#  PgStateStore
# ══════════════════════════════════════════════════════════════════════

class PgStateStore:
    """
    PostgreSQL-backed execution state store.

    Drop-in async replacement for the in-memory ``StateStore``.
    Uses asyncpg connection pool for high throughput.
    """

    def __init__(self, dsn: str, *, min_pool: int = 2, max_pool: int = 10):
        _require_asyncpg()
        self._dsn = dsn
        self._min_pool = min_pool
        self._max_pool = max_pool
        self._pool: Optional[asyncpg.Pool] = None

    # ── lifecycle ─────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Create pool and ensure schema exists."""
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_pool, max_size=self._max_pool,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_EXECUTIONS_DDL)
            await conn.execute("ALTER TABLE executions ADD COLUMN IF NOT EXISTS token_data JSONB")
            await conn.execute("ALTER TABLE executions ADD COLUMN IF NOT EXISTS llm_provider TEXT")
            await conn.execute("ALTER TABLE executions ADD COLUMN IF NOT EXISTS llm_model TEXT")
        log.info("PgStateStore ready (pool %d-%d)", self._min_pool, self._max_pool)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    # ── CRUD (matches StateStore interface) ───────────────────────

    async def create(self, execution: Execution) -> Execution:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO executions
                   (id,user_id,task,status,plan,current_step,results,
                    certificates,error,webhook_url,created_at,updated_at,
                          completed_at,token_id,cost_cents,token_data,llm_provider,llm_model)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)""",
                execution.id, execution.user_id, execution.task,
                execution.status.value,
                json.dumps(execution.plan) if execution.plan else None,
                execution.current_step,
                json.dumps(execution.results) if execution.results else None,
                json.dumps(execution.certificates),
                execution.error, execution.webhook_url,
                execution.created_at, execution.updated_at,
                execution.completed_at, execution.token_id, execution.cost_cents,
                json.dumps(execution.token_data) if execution.token_data else None,
                execution.llm_provider, execution.llm_model,
            )
        return execution

    async def get(self, execution_id: str) -> Optional[Execution]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM executions WHERE id = $1", execution_id
            )
        return self._to_exec(row) if row else None

    async def update(self, execution: Execution) -> Execution:
        execution.updated_at = time.time()
        async with self._pool.acquire() as conn:
            await conn.execute(
                """UPDATE executions SET
                     user_id=$2, task=$3, status=$4, plan=$5, current_step=$6,
                     results=$7, certificates=$8, error=$9, webhook_url=$10,
                     updated_at=$11, completed_at=$12, token_id=$13, cost_cents=$14,
                     token_data=$15, llm_provider=$16, llm_model=$17
                   WHERE id=$1""",
                execution.id, execution.user_id, execution.task,
                execution.status.value,
                json.dumps(execution.plan) if execution.plan else None,
                execution.current_step,
                json.dumps(execution.results) if execution.results else None,
                json.dumps(execution.certificates),
                execution.error, execution.webhook_url,
                execution.updated_at, execution.completed_at,
                execution.token_id, execution.cost_cents,
                json.dumps(execution.token_data) if execution.token_data else None,
                execution.llm_provider, execution.llm_model,
            )
        return execution

    async def list_by_user(
        self, user_id: str,
        status: Optional[ExecutionStatus] = None,
        limit: int = 20,
    ) -> List[Execution]:
        async with self._pool.acquire() as conn:
            if status:
                rows = await conn.fetch(
                    "SELECT * FROM executions WHERE user_id=$1 AND status=$2 "
                    "ORDER BY created_at DESC LIMIT $3",
                    user_id, status.value, limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM executions WHERE user_id=$1 "
                    "ORDER BY created_at DESC LIMIT $2",
                    user_id, limit,
                )
        return [self._to_exec(r) for r in rows]

    async def delete(self, execution_id: str) -> bool:
        async with self._pool.acquire() as conn:
            tag = await conn.execute(
                "DELETE FROM executions WHERE id=$1", execution_id
            )
        return tag == "DELETE 1"

    async def count(self, status: Optional[ExecutionStatus] = None) -> int:
        async with self._pool.acquire() as conn:
            if status:
                r = await conn.fetchrow(
                    "SELECT count(*) n FROM executions WHERE status=$1", status.value
                )
            else:
                r = await conn.fetchrow("SELECT count(*) n FROM executions")
        return r["n"]

    # ── row mapping ──────────────────────────────────────────────

    @staticmethod
    def _to_exec(row) -> Execution:
        def _json(v):
            return json.loads(v) if isinstance(v, str) else v

        certs = _json(row["certificates"])
        return Execution(
            id=row["id"], user_id=row["user_id"], task=row["task"],
            status=ExecutionStatus(row["status"]),
            plan=_json(row["plan"]),
            current_step=row["current_step"],
            results=_json(row["results"]),
            certificates=certs if certs else [],
            error=row["error"], webhook_url=row["webhook_url"],
            created_at=row["created_at"], updated_at=row["updated_at"],
            completed_at=row["completed_at"],
            token_id=row["token_id"], cost_cents=row["cost_cents"],
            token_data=_json(row["token_data"]),
            llm_provider=row["llm_provider"],
            llm_model=row["llm_model"],
        )


# ══════════════════════════════════════════════════════════════════════
#  PgEventBus
# ══════════════════════════════════════════════════════════════════════

class PgEventBus:
    """
    PostgreSQL-backed event bus.

    Events are persisted to ``events`` for compliance audit trail.
    In-memory handler dispatch is preserved for real-time WebSocket
    forwarding in the same process.
    """

    def __init__(self, dsn: str, *, min_pool: int = 2, max_pool: int = 10):
        _require_asyncpg()
        self._dsn = dsn
        self._min_pool = min_pool
        self._max_pool = max_pool
        self._pool: Optional[asyncpg.Pool] = None
        self._handlers: Dict[str, list] = {}

    async def initialize(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_pool, max_size=self._max_pool,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_EVENTS_DDL)
        log.info("PgEventBus ready")

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    def subscribe(self, event_type: str, handler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler) -> None:
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    async def emit(self, event: Event) -> None:
        # Persist
        if self._pool:
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO events (type,execution_id,data,timestamp) "
                        "VALUES ($1,$2,$3,$4)",
                        event.type, event.execution_id,
                        json.dumps(event.data), event.timestamp,
                    )
            except Exception as exc:
                log.warning("Failed to persist event: %s", exc)

        # Dispatch
        for h in list(self._handlers.get(event.type, [])) + \
                 list(self._handlers.get("*", [])):
            try:
                await h(event)
            except Exception:
                pass

    async def get_history(
        self, execution_id: Optional[str] = None,
        event_type: Optional[str] = None, limit: int = 100,
    ) -> List[Event]:
        conds, params, idx = [], [], 1
        if execution_id:
            conds.append(f"execution_id=${idx}"); params.append(execution_id); idx += 1
        if event_type:
            conds.append(f"type=${idx}"); params.append(event_type); idx += 1
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        params.append(limit)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ${idx}",
                *params,
            )
        events = []
        for r in rows:
            data = r["data"]
            if isinstance(data, str):
                data = json.loads(data)
            events.append(Event(
                type=r["type"], execution_id=r["execution_id"],
                data=data, timestamp=r["timestamp"],
            ))
        return events

    async def count(self, execution_id: Optional[str] = None) -> int:
        async with self._pool.acquire() as conn:
            if execution_id:
                r = await conn.fetchrow(
                    "SELECT count(*) n FROM events WHERE execution_id=$1",
                    execution_id,
                )
            else:
                r = await conn.fetchrow("SELECT count(*) n FROM events")
        return r["n"]


class PgWorkflowStore:
    def __init__(self, dsn: str, *, min_pool: int = 2, max_pool: int = 10):
        _require_asyncpg()
        self._dsn = dsn
        self._min_pool = min_pool
        self._max_pool = max_pool
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_pool, max_size=self._max_pool,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_WORKFLOWS_DDL)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def create(self, workflow: Workflow) -> Workflow:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO workflows
                   (id, user_id, user_role, name, description, mode, status,
                    created_at, updated_at, completed_at, current_stage_index, error, stages)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                workflow.id,
                workflow.user_id,
                workflow.user_role,
                workflow.name,
                workflow.description,
                workflow.mode,
                workflow.status.value,
                workflow.created_at,
                workflow.updated_at,
                workflow.completed_at,
                workflow.current_stage_index,
                workflow.error,
                json.dumps([stage.to_dict() for stage in workflow.stages]),
            )
        return workflow

    async def get(self, workflow_id: str) -> Optional[Workflow]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM workflows WHERE id = $1", workflow_id)
        return self._to_workflow(row) if row else None

    async def update(self, workflow: Workflow) -> Workflow:
        workflow.updated_at = time.time()
        async with self._pool.acquire() as conn:
            await conn.execute(
                """UPDATE workflows SET
                     user_id=$2, user_role=$3, name=$4, description=$5, mode=$6, status=$7,
                     created_at=$8, updated_at=$9, completed_at=$10, current_stage_index=$11,
                     error=$12, stages=$13
                   WHERE id=$1""",
                workflow.id,
                workflow.user_id,
                workflow.user_role,
                workflow.name,
                workflow.description,
                workflow.mode,
                workflow.status.value,
                workflow.created_at,
                workflow.updated_at,
                workflow.completed_at,
                workflow.current_stage_index,
                workflow.error,
                json.dumps([stage.to_dict() for stage in workflow.stages]),
            )
        return workflow

    async def list_by_user(
        self,
        user_id: str,
        status: Optional[WorkflowStatus] = None,
        limit: int = 20,
    ) -> List[Workflow]:
        async with self._pool.acquire() as conn:
            if status:
                rows = await conn.fetch(
                    "SELECT * FROM workflows WHERE user_id=$1 AND status=$2 ORDER BY created_at DESC LIMIT $3",
                    user_id, status.value, limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM workflows WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2",
                    user_id, limit,
                )
        return [self._to_workflow(row) for row in rows]

    async def delete(self, workflow_id: str) -> bool:
        async with self._pool.acquire() as conn:
            tag = await conn.execute("DELETE FROM workflows WHERE id=$1", workflow_id)
        return tag == "DELETE 1"

    @staticmethod
    def _to_workflow(row) -> Workflow:
        stages = row["stages"]
        if isinstance(stages, str):
            stages = json.loads(stages)
        return Workflow(
            id=row["id"],
            user_id=row["user_id"],
            user_role=row["user_role"],
            name=row["name"],
            description=row["description"],
            mode=row["mode"],
            status=WorkflowStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
            current_stage_index=row["current_stage_index"],
            error=row["error"],
            stages=[WorkflowStage.from_dict(stage) for stage in stages or []],
        )


# ══════════════════════════════════════════════════════════════════════
#  Factory
# ══════════════════════════════════════════════════════════════════════

async def create_pg_backend(
    dsn: str, *, min_pool: int = 2, max_pool: int = 10,
) -> tuple[PgStateStore, PgEventBus]:
    """Create and initialise PostgreSQL-backed state store + event bus."""
    store = PgStateStore(dsn, min_pool=min_pool, max_pool=max_pool)
    bus = PgEventBus(dsn, min_pool=min_pool, max_pool=max_pool)
    await store.initialize()
    await bus.initialize()
    return store, bus
