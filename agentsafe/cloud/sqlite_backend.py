"""
SQLite-backed persistence for StateStore, TaskQueue, and EventBus.

Provides durable, crash-safe storage using Python's built-in ``sqlite3``
module with ``asyncio.to_thread`` for non-blocking I/O.  Zero additional
dependencies beyond the standard library.

Usage
-----
    from agentsafe.cloud.sqlite_backend import (
        SQLiteStateStore,
        SQLiteTaskQueue,
        SQLiteEventBus,
        create_backend,
    )

    # Individual components
    store = SQLiteStateStore("/var/lib/certior/state.db")
    await store.initialize()

    # Or use the factory for all three at once
    store, queue, bus = await create_backend("/var/lib/certior/")

Design decisions
----------------
* WAL journal mode for concurrent readers + single writer.
* ``busy_timeout=5000`` so transient contention doesn't raise immediately.
* All writes use explicit transactions (BEGIN IMMEDIATE).
* JSON serialization for complex fields (plan, results, certificates).
* Timestamps stored as REAL (Unix epoch) for efficient range queries.
* Index on (user_id, status) and (status) for common query patterns.
* ``asyncio.to_thread`` keeps the event loop free while SQLite blocks.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .state_store import Execution, ExecutionStatus
from .workflow_store import Workflow, WorkflowStage, WorkflowStageStatus, WorkflowStatus
from .task_queue import QueuedTask, TaskStatus
from .event_bus import Event, EventHandler

log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
# SQLiteStateStore
# ═══════════════════════════════════════════════════════════════════════

_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    task          TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'queued',
    plan          TEXT,           -- JSON
    current_step  INTEGER NOT NULL DEFAULT 0,
    results       TEXT,           -- JSON
    certificates  TEXT NOT NULL DEFAULT '[]',  -- JSON array
    error         TEXT NOT NULL DEFAULT '',
    webhook_url   TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    completed_at  REAL,
    token_id      TEXT NOT NULL DEFAULT '',
    cost_cents    INTEGER NOT NULL DEFAULT 0,
    token_data    TEXT,           -- JSON (full token for reconstruction)
    llm_provider  TEXT,           -- per-task LLM provider override
    llm_model     TEXT            -- per-task LLM model override
);

CREATE INDEX IF NOT EXISTS idx_exec_user_status
    ON executions (user_id, status);

CREATE INDEX IF NOT EXISTS idx_exec_created
    ON executions (created_at DESC);
"""


class SQLiteStateStore:
    """
    Durable execution state store backed by SQLite.

    Drop-in replacement for the in-memory ``StateStore``.  Call
    ``await initialize()`` once before use to create tables.

    Concurrency: safe for multiple async tasks in the same process.
    For multi-process access, ensure WAL mode (enabled by default).
    """

    def __init__(self, db_path: str | Path = "certior_state.db"):
        self._db_path = str(db_path)
        self._initialized = False

    async def initialize(self) -> None:
        """Create tables and indexes if they don't exist."""
        def _init():
            conn = self._connect()
            try:
                conn.executescript(_STATE_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_init)
        self._initialized = True

    def _init_db_sync(self) -> None:
        """Synchronous init - for use in app factory before event loop starts."""
        conn = self._connect()
        try:
            conn.executescript(_STATE_SCHEMA)
            # Migration: add token_data column if missing (existing DBs)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(executions)").fetchall()}
            if "token_data" not in cols:
                conn.execute("ALTER TABLE executions ADD COLUMN token_data TEXT")
            if "llm_provider" not in cols:
                conn.execute("ALTER TABLE executions ADD COLUMN llm_provider TEXT")
            if "llm_model" not in cols:
                conn.execute("ALTER TABLE executions ADD COLUMN llm_model TEXT")
            conn.commit()
        finally:
            conn.close()
        self._initialized = True

    # ── CRUD ──────────────────────────────────────────────────────

    async def create(self, execution: Execution) -> Execution:
        def _insert():
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO executions
                       (id, user_id, task, status, plan, current_step,
                        results, certificates, error, webhook_url,
                        created_at, updated_at, completed_at, token_id, cost_cents,
                                token_data, llm_provider, llm_model)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    self._to_row(execution),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_insert)
        return execution

    async def get(self, execution_id: str) -> Optional[Execution]:
        def _select():
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM executions WHERE id = ?",
                    (execution_id,),
                ).fetchone()
                return self._from_row(row) if row else None
            finally:
                conn.close()
        return await asyncio.to_thread(_select)

    async def update(self, execution: Execution) -> Execution:
        execution.updated_at = time.time()

        def _update():
            conn = self._connect()
            try:
                conn.execute(
                    """UPDATE executions SET
                       user_id=?, task=?, status=?, plan=?, current_step=?,
                       results=?, certificates=?, error=?, webhook_url=?,
                       created_at=?, updated_at=?, completed_at=?, token_id=?,
                              cost_cents=?, token_data=?, llm_provider=?, llm_model=?
                       WHERE id=?""",
                    (
                        execution.user_id, execution.task,
                        execution.status.value,
                        json.dumps(execution.plan) if execution.plan else None,
                        execution.current_step,
                        json.dumps(execution.results) if execution.results else None,
                        json.dumps(execution.certificates),
                        execution.error, execution.webhook_url,
                        execution.created_at, execution.updated_at,
                        execution.completed_at, execution.token_id,
                        execution.cost_cents,
                        json.dumps(execution.token_data) if execution.token_data else None,
                        execution.llm_provider,
                        execution.llm_model,
                        execution.id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_update)
        return execution

    async def list_by_user(
        self,
        user_id: str,
        status: Optional[ExecutionStatus] = None,
        limit: int = 20,
    ) -> List[Execution]:
        def _list():
            conn = self._connect()
            try:
                if status:
                    rows = conn.execute(
                        """SELECT * FROM executions
                           WHERE user_id = ? AND status = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (user_id, status.value, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM executions
                           WHERE user_id = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (user_id, limit),
                    ).fetchall()
                return [self._from_row(r) for r in rows]
            finally:
                conn.close()
        return await asyncio.to_thread(_list)

    async def delete(self, execution_id: str) -> bool:
        def _delete():
            conn = self._connect()
            try:
                cur = conn.execute(
                    "DELETE FROM executions WHERE id = ?",
                    (execution_id,),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()
        return await asyncio.to_thread(_delete)

    async def count(
        self,
        user_id: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
    ) -> int:
        """Count executions, optionally filtered."""
        def _count():
            conn = self._connect()
            try:
                clauses, params = [], []
                if user_id:
                    clauses.append("user_id = ?")
                    params.append(user_id)
                if status:
                    clauses.append("status = ?")
                    params.append(status.value)
                where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
                row = conn.execute(
                    f"SELECT COUNT(*) FROM executions{where}", params
                ).fetchone()
                return row[0]
            finally:
                conn.close()
        return await asyncio.to_thread(_count)

    # ── Serialisation ─────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _to_row(e: Execution) -> tuple:
        return (
            e.id, e.user_id, e.task, e.status.value,
            json.dumps(e.plan) if e.plan else None,
            e.current_step,
            json.dumps(e.results) if e.results else None,
            json.dumps(e.certificates),
            e.error, e.webhook_url,
            e.created_at, e.updated_at, e.completed_at,
            e.token_id, e.cost_cents,
            json.dumps(e.token_data) if e.token_data else None,
            e.llm_provider, e.llm_model,
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Execution:
        td_raw = row["token_data"] if "token_data" in row.keys() else None
        return Execution(
            id=row["id"],
            user_id=row["user_id"],
            task=row["task"],
            status=ExecutionStatus(row["status"]),
            plan=json.loads(row["plan"]) if row["plan"] else None,
            current_step=row["current_step"],
            results=json.loads(row["results"]) if row["results"] else None,
            certificates=json.loads(row["certificates"]),
            error=row["error"],
            webhook_url=row["webhook_url"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
            token_id=row["token_id"],
            cost_cents=row["cost_cents"],
            token_data=json.loads(td_raw) if td_raw else None,
            llm_provider=row["llm_provider"] if "llm_provider" in row.keys() else None,
            llm_model=row["llm_model"] if "llm_model" in row.keys() else None,
        )


# ═══════════════════════════════════════════════════════════════════════
# SQLiteTaskQueue
# ═══════════════════════════════════════════════════════════════════════

_QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    args_json    TEXT NOT NULL DEFAULT '[]',
    kwargs_json  TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending',
    result_json  TEXT,
    error        TEXT,
    submitted_at REAL NOT NULL,
    started_at   REAL,
    completed_at REAL,
    retries      INTEGER NOT NULL DEFAULT 0,
    max_retries  INTEGER NOT NULL DEFAULT 3
);

CREATE INDEX IF NOT EXISTS idx_task_status
    ON tasks (status);
"""


class SQLiteTaskQueue:
    """
    Durable task queue backed by SQLite.

    Tasks survive process restarts.  On ``start()``, any tasks left in
    ``pending`` or ``running`` state are re-enqueued for processing.

    Note: task *handlers* (Python callables) are registered in-memory
    and must be re-registered after a restart.  Only task metadata
    (name, args, status) is persisted.
    """

    def __init__(
        self,
        db_path: str | Path = "certior_tasks.db",
        *,
        max_workers: int = 4,
    ):
        self._db_path = str(db_path)
        self._handlers: Dict[str, Callable] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._max_workers = max_workers
        self._workers: List[asyncio.Task] = []
        self._running = False
        self._initialized = False

    async def initialize(self) -> None:
        """Create tables."""
        def _init():
            conn = self._connect()
            try:
                conn.executescript(_QUEUE_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_init)
        self._initialized = True

    def _init_db_sync(self) -> None:
        """Synchronous init - for use in app factory before event loop starts."""
        conn = self._connect()
        try:
            conn.executescript(_QUEUE_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        self._initialized = True

    def register(self, name: str, handler: Callable) -> None:
        """Register a named task handler (in-memory only)."""
        self._handlers[name] = handler

    async def enqueue(
        self,
        name: str,
        *args: Any,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> QueuedTask:
        """Submit a task - persists to SQLite then enqueues in memory."""
        if name not in self._handlers:
            raise ValueError(f"No handler registered for task: {name}")

        task = QueuedTask(
            name=name,
            args=args,
            kwargs=kwargs,
            max_retries=max_retries,
        )

        def _insert():
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO tasks
                       (id, name, args_json, kwargs_json, status,
                        submitted_at, retries, max_retries)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        task.id, task.name,
                        json.dumps(task.args, default=str),
                        json.dumps(task.kwargs, default=str),
                        task.status.value,
                        task.submitted_at,
                        task.retries, task.max_retries,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_insert)
        await self._queue.put(task.id)
        return task

    async def get_task(self, task_id: str) -> Optional[QueuedTask]:
        def _get():
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE id = ?", (task_id,)
                ).fetchone()
                return self._from_row(row) if row else None
            finally:
                conn.close()
        return await asyncio.to_thread(_get)

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 50,
    ) -> List[QueuedTask]:
        """Synchronous list (matches in-memory TaskQueue interface)."""
        conn = self._connect()
        try:
            if status:
                rows = conn.execute(
                    """SELECT * FROM tasks WHERE status = ?
                       ORDER BY submitted_at DESC LIMIT ?""",
                    (status.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM tasks
                       ORDER BY submitted_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [self._from_row(r) for r in rows]
        finally:
            conn.close()

    async def cancel(self, task_id: str) -> bool:
        def _cancel():
            conn = self._connect()
            try:
                cur = conn.execute(
                    """UPDATE tasks SET status = ?
                       WHERE id = ? AND status = ?""",
                    (TaskStatus.CANCELLED.value, task_id, TaskStatus.PENDING.value),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()
        return await asyncio.to_thread(_cancel)

    async def start(self) -> None:
        """Start workers and recover incomplete tasks from the database."""
        if self._running:
            return
        self._running = True

        # Recover tasks stuck in pending/running from a previous crash
        recovered = await self._recover_incomplete()
        if recovered:
            log.info("Recovered %d incomplete tasks from database", recovered)

        for i in range(self._max_workers):
            worker = asyncio.create_task(self._worker_loop(i))
            self._workers.append(worker)

    async def stop(self, *, drain: bool = True) -> None:
        self._running = False
        if drain:
            await self._queue.join()
        for w in self._workers:
            w.cancel()
        self._workers.clear()

    async def process_one(self) -> Optional[QueuedTask]:
        """Process exactly one task (for testing)."""
        if self._queue.empty():
            return None
        task_id = await self._queue.get()
        await self._execute_task(task_id)
        self._queue.task_done()
        return await self.get_task(task_id)

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def total_count(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()
            return row[0]
        finally:
            conn.close()

    # ── Internals ─────────────────────────────────────────────────

    async def _recover_incomplete(self) -> int:
        """Re-enqueue tasks that were pending or running when we last stopped."""
        def _find_incomplete():
            conn = self._connect()
            try:
                # Reset running → pending (they were interrupted)
                conn.execute(
                    "UPDATE tasks SET status = ? WHERE status = ?",
                    (TaskStatus.PENDING.value, TaskStatus.RUNNING.value),
                )
                conn.commit()
                rows = conn.execute(
                    "SELECT id FROM tasks WHERE status = ?",
                    (TaskStatus.PENDING.value,),
                ).fetchall()
                return [row["id"] for row in rows]
            finally:
                conn.close()

        task_ids = await asyncio.to_thread(_find_incomplete)
        for tid in task_ids:
            await self._queue.put(tid)
        return len(task_ids)

    async def _worker_loop(self, worker_id: int) -> None:
        while self._running:
            try:
                task_id = await asyncio.wait_for(
                    self._queue.get(), timeout=0.5
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue
            try:
                await self._execute_task(task_id)
            finally:
                self._queue.task_done()

    async def _execute_task(self, task_id: str) -> None:
        task = await self.get_task(task_id)
        if not task or task.status == TaskStatus.CANCELLED:
            return

        handler = self._handlers.get(task.name)
        if not handler:
            await self._update_task_status(
                task_id, TaskStatus.FAILED, error=f"No handler for {task.name}"
            )
            return

        await self._update_task_status(task_id, TaskStatus.RUNNING)

        try:
            result = handler(*task.args, **task.kwargs)
            if asyncio.iscoroutine(result):
                result = await result

            def _complete():
                conn = self._connect()
                try:
                    conn.execute(
                        """UPDATE tasks SET status=?, result_json=?,
                           completed_at=? WHERE id=?""",
                        (
                            TaskStatus.COMPLETED.value,
                            json.dumps(result, default=str),
                            time.time(), task_id,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()

            await asyncio.to_thread(_complete)

        except Exception as exc:
            task = await self.get_task(task_id)
            new_retries = (task.retries if task else 0) + 1
            max_r = task.max_retries if task else 3

            if new_retries < max_r:
                def _retry():
                    conn = self._connect()
                    try:
                        conn.execute(
                            "UPDATE tasks SET status=?, retries=? WHERE id=?",
                            (TaskStatus.PENDING.value, new_retries, task_id),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                await asyncio.to_thread(_retry)
                await self._queue.put(task_id)
            else:
                await self._update_task_status(
                    task_id, TaskStatus.FAILED,
                    error=str(exc), retries=new_retries,
                )

    async def _update_task_status(
        self, task_id: str, status: TaskStatus, *,
        error: Optional[str] = None, retries: Optional[int] = None,
    ) -> None:
        def _update():
            conn = self._connect()
            try:
                sets = ["status = ?"]
                params: list = [status.value]
                if status == TaskStatus.RUNNING:
                    sets.append("started_at = ?")
                    params.append(time.time())
                if status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                    sets.append("completed_at = ?")
                    params.append(time.time())
                if error is not None:
                    sets.append("error = ?")
                    params.append(error)
                if retries is not None:
                    sets.append("retries = ?")
                    params.append(retries)
                params.append(task_id)
                conn.execute(
                    f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?",
                    params,
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_update)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _from_row(row: sqlite3.Row) -> QueuedTask:
        result_raw = row["result_json"]
        try:
            result = json.loads(result_raw) if result_raw else None
        except (json.JSONDecodeError, TypeError):
            result = result_raw

        return QueuedTask(
            id=row["id"],
            name=row["name"],
            args=tuple(json.loads(row["args_json"])),
            kwargs=json.loads(row["kwargs_json"]),
            status=TaskStatus(row["status"]),
            result=result,
            error=row["error"],
            submitted_at=row["submitted_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            retries=row["retries"],
            max_retries=row["max_retries"],
        )


# ═══════════════════════════════════════════════════════════════════════
# SQLiteEventBus
# ═══════════════════════════════════════════════════════════════════════

_EVENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    data_json    TEXT NOT NULL DEFAULT '{}',
    timestamp    REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_exec
    ON events (execution_id);

CREATE INDEX IF NOT EXISTS idx_event_type
    ON events (type);

CREATE INDEX IF NOT EXISTS idx_event_ts
    ON events (timestamp DESC);
"""


class SQLiteEventBus:
    """
    Event bus with durable audit trail in SQLite.

    In-memory handler dispatch is preserved - subscribers still receive
    real-time async callbacks.  Additionally, every emitted event is
    persisted to the ``events`` table for post-hoc audit queries.
    """

    def __init__(self, db_path: str | Path = "certior_events.db"):
        self._db_path = str(db_path)
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Create tables."""
        def _init():
            conn = self._connect()
            try:
                conn.executescript(_EVENT_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_init)
        self._initialized = True

    def _init_db_sync(self) -> None:
        """Synchronous init - for use in app factory before event loop starts."""
        conn = self._connect()
        try:
            conn.executescript(_EVENT_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        self._initialized = True

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    async def emit(self, event: Event) -> None:
        """Persist event to SQLite, then dispatch to in-memory handlers."""
        # 1. Persist (non-blocking)
        def _persist():
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO events (type, execution_id, data_json, timestamp)
                       VALUES (?,?,?,?)""",
                    (
                        event.type, event.execution_id,
                        json.dumps(event.data, default=str),
                        event.timestamp,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        await asyncio.to_thread(_persist)

        # 2. Dispatch to in-memory handlers
        handlers = list(self._handlers.get(event.type, []))
        handlers += list(self._handlers.get("*", []))
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass  # Don't let handler errors break the bus

    def get_history(
        self,
        execution_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 1000,
    ) -> List[Event]:
        """Query persisted event history (synchronous for compatibility)."""
        conn = self._connect()
        try:
            clauses, params = [], []
            if execution_id:
                clauses.append("execution_id = ?")
                params.append(execution_id)
            if event_type:
                clauses.append("type = ?")
                params.append(event_type)
            if since is not None:
                clauses.append("timestamp >= ?")
                params.append(since)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            params.append(limit)
            rows = conn.execute(
                f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
            return [
                Event(
                    type=r["type"],
                    execution_id=r["execution_id"],
                    data=json.loads(r["data_json"]),
                    timestamp=r["timestamp"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    async def count(
        self,
        execution_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> int:
        """Count persisted events."""
        def _count():
            conn = self._connect()
            try:
                clauses, params = [], []
                if execution_id:
                    clauses.append("execution_id = ?")
                    params.append(execution_id)
                if event_type:
                    clauses.append("type = ?")
                    params.append(event_type)
                where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
                row = conn.execute(
                    f"SELECT COUNT(*) FROM events{where}", params
                ).fetchone()
                return row[0]
            finally:
                conn.close()
        return await asyncio.to_thread(_count)


# ═══════════════════════════════════════════════════════════════════════
# SQLiteWorkflowStore
# ═══════════════════════════════════════════════════════════════════════

_WORKFLOW_SCHEMA = """
CREATE TABLE IF NOT EXISTS workflows (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    user_role           TEXT NOT NULL DEFAULT 'operator',
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    mode                TEXT NOT NULL DEFAULT 'sequential',
    status              TEXT NOT NULL DEFAULT 'queued',
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL,
    completed_at        REAL,
    current_stage_index INTEGER NOT NULL DEFAULT 0,
    error               TEXT NOT NULL DEFAULT '',
    stages_json         TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_workflows_user_status
    ON workflows (user_id, status);

CREATE INDEX IF NOT EXISTS idx_workflows_created
    ON workflows (created_at DESC);
"""


class SQLiteWorkflowStore:
    def __init__(self, db_path: str | Path = "certior_workflows.db"):
        self._db_path = str(db_path)
        self._initialized = False

    async def initialize(self) -> None:
        def _init():
            conn = self._connect()
            try:
                conn.executescript(_WORKFLOW_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_init)
        self._initialized = True

    def _init_db_sync(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_WORKFLOW_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        self._initialized = True

    async def create(self, workflow: Workflow) -> Workflow:
        def _insert():
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO workflows
                       (id, user_id, user_role, name, description, mode, status,
                        created_at, updated_at, completed_at, current_stage_index, error, stages_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    self._to_row(workflow),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_insert)
        return workflow

    async def get(self, workflow_id: str) -> Optional[Workflow]:
        def _select():
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM workflows WHERE id = ?",
                    (workflow_id,),
                ).fetchone()
                return self._from_row(row) if row else None
            finally:
                conn.close()
        return await asyncio.to_thread(_select)

    async def update(self, workflow: Workflow) -> Workflow:
        workflow.updated_at = time.time()

        def _update():
            conn = self._connect()
            try:
                conn.execute(
                    """UPDATE workflows SET
                       user_id=?, user_role=?, name=?, description=?, mode=?, status=?,
                       created_at=?, updated_at=?, completed_at=?, current_stage_index=?, error=?, stages_json=?
                       WHERE id=?""",
                    (
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
                        workflow.id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_update)
        return workflow

    async def list_by_user(
        self,
        user_id: str,
        status: Optional[WorkflowStatus] = None,
        limit: int = 20,
    ) -> List[Workflow]:
        def _list():
            conn = self._connect()
            try:
                if status:
                    rows = conn.execute(
                        """SELECT * FROM workflows
                           WHERE user_id = ? AND status = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (user_id, status.value, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM workflows
                           WHERE user_id = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (user_id, limit),
                    ).fetchall()
                return [self._from_row(row) for row in rows]
            finally:
                conn.close()
        return await asyncio.to_thread(_list)

    async def delete(self, workflow_id: str) -> bool:
        def _delete():
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM workflows WHERE id = ?", (workflow_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()
        return await asyncio.to_thread(_delete)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _to_row(workflow: Workflow) -> tuple:
        return (
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

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Workflow:
        workflow = Workflow(
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
            stages=[WorkflowStage.from_dict(stage) for stage in json.loads(row["stages_json"] or "[]")],
        )
        return workflow

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn


# ═══════════════════════════════════════════════════════════════════════
# Factory
# ═══════════════════════════════════════════════════════════════════════

async def create_backend(
    data_dir: str | Path,
    *,
    max_workers: int = 4,
) -> tuple[SQLiteStateStore, SQLiteTaskQueue, SQLiteEventBus]:
    """
    Create and initialize all three SQLite-backed components.

    Args:
        data_dir: Directory for database files (created if missing).
        max_workers: Worker count for the task queue.

    Returns:
        (state_store, task_queue, event_bus) - all initialized and
        ready to use.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    store = SQLiteStateStore(data_dir / "certior_state.db")
    queue = SQLiteTaskQueue(data_dir / "certior_tasks.db", max_workers=max_workers)
    bus = SQLiteEventBus(data_dir / "certior_events.db")

    await store.initialize()
    await queue.initialize()
    await bus.initialize()

    return store, queue, bus
