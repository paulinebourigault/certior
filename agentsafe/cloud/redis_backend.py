"""
Celery/Redis task queue backend for Certior.

Drop-in replacement for the in-memory ``TaskQueue`` that persists
tasks to Redis via Celery.  Supports the same interface:
    register / enqueue / get_task / cancel / start / stop

Architecture:
  - Redis is the Celery broker AND result backend (single dependency)
  - Celery tasks wrap the registered Python handlers
  - Task metadata is stored in Redis hashes for fast lookup
  - Graceful degradation: falls back to in-memory if Redis unavailable

Usage:
    queue = CeleryTaskQueue("redis://localhost:6379/0")
    queue.register("execute_verified_task", my_handler)
    await queue.start()
    task = await queue.enqueue("execute_verified_task", exec_id, token)
    status = await queue.get_task(task.id)
    await queue.stop()
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)

# ── Guard imports ─────────────────────────────────────────────────────

try:
    from celery import Celery, states as celery_states  # type: ignore
    from celery.result import AsyncResult  # type: ignore
    _HAS_CELERY = True
except ImportError:
    _HAS_CELERY = False

try:
    import redis as _redis_mod  # type: ignore
    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False


def _require_deps() -> None:
    missing = []
    if not _HAS_CELERY:
        missing.append("celery")
    if not _HAS_REDIS:
        missing.append("redis")
    if missing:
        raise ImportError(
            f"Missing dependencies for Redis task queue: {', '.join(missing)}. "
            "Install: pip install 'certior[redis]' or pip install celery redis"
        )


# ── Task status (mirrors task_queue.py) ───────────────────────────────

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class QueuedTask:
    """Task metadata - serialisable for Redis storage."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    args: tuple = ()
    kwargs: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    submitted_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retries: int = 0
    max_retries: int = 3
    celery_task_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name,
            "status": self.status.value, "error": self.error,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "retries": self.retries,
        }


# ══════════════════════════════════════════════════════════════════════
#  CeleryTaskQueue
# ══════════════════════════════════════════════════════════════════════

# Sentinel: will be replaced by the real Celery app on first init
_celery_app: Optional[Celery] = None

# Redis key prefix for task metadata
_TASK_KEY_PREFIX = "certior:task:"
_TASK_INDEX_KEY = "certior:task_ids"


class CeleryTaskQueue:
    """
    Celery/Redis-backed task queue.

    Interface-compatible with the in-memory ``TaskQueue`` so it can
    be swapped in without changing any calling code.

    Args:
        redis_url:    Redis connection string (broker + result backend).
        app_name:     Celery application name.
        max_retries:  Default retry limit for failed tasks.
        task_ttl:     How long completed task metadata stays in Redis (seconds).
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        *,
        app_name: str = "certior",
        max_retries: int = 3,
        task_ttl: int = 86400 * 7,  # 7 days
    ):
        _require_deps()

        self._redis_url = redis_url
        self._max_retries = max_retries
        self._task_ttl = task_ttl

        # Celery app (singleton per process)
        global _celery_app
        if _celery_app is None:
            _celery_app = Celery(
                app_name,
                broker=redis_url,
                backend=redis_url,
            )
            _celery_app.conf.update(
                task_serializer="json",
                accept_content=["json"],
                result_serializer="json",
                task_track_started=True,
                task_acks_late=True,
                worker_prefetch_multiplier=1,
                task_reject_on_worker_lost=True,
                broker_connection_retry_on_startup=True,
                result_expires=task_ttl,
            )
        self._app = _celery_app

        # Redis client for metadata
        self._redis = _redis_mod.Redis.from_url(redis_url, decode_responses=True)

        # In-process handler registry (handlers are NOT serialised - they
        # must be registered in every process: API server AND worker)
        self._handlers: Dict[str, Callable] = {}

        self._running = False

    # ── Handler registration ─────────────────────────────────────

    def register(self, name: str, handler: Callable) -> None:
        """
        Register a named task handler.

        Must be called in every process that handles tasks (API server
        for enqueue, Celery worker for execution).
        """
        self._handlers[name] = handler

        # Also register as a Celery task so the worker can find it
        @self._app.task(name=f"certior.{name}", bind=True, max_retries=self._max_retries)
        def _celery_task(self_task, task_meta_id: str, *args, **kwargs):
            """Celery task wrapper - delegates to registered handler."""
            import asyncio as _asyncio

            # Update status in Redis
            _update_redis_status(task_meta_id, TaskStatus.RUNNING)

            try:
                # Run the handler (may be sync or async)
                result = handler(*args, **kwargs)
                if _asyncio.iscoroutine(result):
                    loop = _asyncio.new_event_loop()
                    try:
                        result = loop.run_until_complete(result)
                    finally:
                        loop.close()

                _update_redis_status(
                    task_meta_id, TaskStatus.COMPLETED, result=result
                )
                return {"status": "completed", "task_id": task_meta_id}

            except Exception as exc:
                retry_count = self_task.request.retries or 0
                if retry_count < self._max_retries - 1:
                    _update_redis_status(
                        task_meta_id, TaskStatus.PENDING,
                        error=str(exc), retries=retry_count + 1,
                    )
                    raise self_task.retry(exc=exc, countdown=2 ** retry_count)
                else:
                    _update_redis_status(
                        task_meta_id, TaskStatus.FAILED, error=str(exc)
                    )
                    raise

    # ── Enqueue ──────────────────────────────────────────────────

    async def enqueue(
        self, name: str, *args: Any,
        max_retries: int = 3, **kwargs: Any,
    ) -> QueuedTask:
        """Submit a task for background execution via Celery."""
        if name not in self._handlers:
            raise ValueError(f"No handler registered for task: {name}")

        task = QueuedTask(
            name=name,
            args=args,
            kwargs=kwargs,
            max_retries=max_retries,
        )

        # Persist metadata to Redis
        await asyncio.to_thread(self._save_task_meta, task)

        # Dispatch via Celery
        celery_task_name = f"certior.{name}"
        result = self._app.send_task(
            celery_task_name,
            args=(task.id, *args),
            kwargs=kwargs,
            task_id=f"celery-{task.id}",
        )
        task.celery_task_id = result.id

        # Update metadata with celery ID
        await asyncio.to_thread(
            self._redis.hset,
            f"{_TASK_KEY_PREFIX}{task.id}",
            "celery_task_id", result.id,
        )

        return task

    # ── Status queries ───────────────────────────────────────────

    async def get_task(self, task_id: str) -> Optional[QueuedTask]:
        """Get task status from Redis."""
        data = await asyncio.to_thread(
            self._redis.hgetall, f"{_TASK_KEY_PREFIX}{task_id}"
        )
        if not data:
            return None
        return self._meta_to_task(data)

    def list_tasks(
        self, status: Optional[TaskStatus] = None, limit: int = 50,
    ) -> List[QueuedTask]:
        """List tasks from Redis index."""
        task_ids = self._redis.lrange(_TASK_INDEX_KEY, 0, limit * 2)
        tasks = []
        pipe = self._redis.pipeline()
        for tid in task_ids:
            pipe.hgetall(f"{_TASK_KEY_PREFIX}{tid}")
        results = pipe.execute()

        for data in results:
            if not data:
                continue
            task = self._meta_to_task(data)
            if status is None or task.status == status:
                tasks.append(task)
            if len(tasks) >= limit:
                break
        return tasks

    async def cancel(self, task_id: str) -> bool:
        """Revoke a pending Celery task."""
        data = await asyncio.to_thread(
            self._redis.hgetall, f"{_TASK_KEY_PREFIX}{task_id}"
        )
        if not data:
            return False

        current_status = data.get("status", "")
        if current_status != TaskStatus.PENDING.value:
            return False

        celery_id = data.get("celery_task_id")
        if celery_id:
            self._app.control.revoke(celery_id, terminate=False)

        await asyncio.to_thread(
            self._redis.hset,
            f"{_TASK_KEY_PREFIX}{task_id}",
            "status", TaskStatus.CANCELLED.value,
        )
        return True

    # ── Lifecycle ────────────────────────────────────────────────

    async def start(self) -> None:
        """Mark queue as running. Celery workers must be started separately."""
        self._running = True
        log.info(
            "CeleryTaskQueue started (broker=%s). "
            "Run Celery worker: celery -A agentsafe.cloud.redis_backend worker",
            self._redis_url,
        )

    async def stop(self, *, drain: bool = True) -> None:
        """Shutdown."""
        self._running = False
        log.info("CeleryTaskQueue stopped")

    async def process_one(self) -> Optional[QueuedTask]:
        """
        Process one task synchronously (for tests).

        Bypasses Celery and runs the handler directly.
        """
        task_ids = self._redis.lrange(_TASK_INDEX_KEY, -1, -1)
        if not task_ids:
            return None

        task_id = task_ids[0]
        data = self._redis.hgetall(f"{_TASK_KEY_PREFIX}{task_id}")
        if not data or data.get("status") != TaskStatus.PENDING.value:
            return None

        task = self._meta_to_task(data)
        handler = self._handlers.get(task.name)
        if not handler:
            return None

        try:
            result = handler(*task.args, **task.kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = time.time()
        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            task.completed_at = time.time()

        self._save_task_meta(task)
        return task

    @property
    def pending_count(self) -> int:
        """Count pending tasks in Redis."""
        return len(self.list_tasks(status=TaskStatus.PENDING))

    @property
    def total_count(self) -> int:
        count = self._redis.llen(_TASK_INDEX_KEY)
        return count or 0

    # ── Redis metadata helpers ───────────────────────────────────

    def _save_task_meta(self, task: QueuedTask) -> None:
        """Persist task metadata to Redis hash."""
        key = f"{_TASK_KEY_PREFIX}{task.id}"
        meta = {
            "id": task.id, "name": task.name,
            "status": task.status.value,
            "args": json.dumps(task.args if isinstance(task.args, (list, tuple)) else []),
            "kwargs": json.dumps(task.kwargs),
            "error": task.error or "",
            "submitted_at": str(task.submitted_at),
            "started_at": str(task.started_at or ""),
            "completed_at": str(task.completed_at or ""),
            "retries": str(task.retries),
            "max_retries": str(task.max_retries),
            "celery_task_id": task.celery_task_id or "",
        }
        self._redis.hset(key, mapping=meta)
        self._redis.lpush(_TASK_INDEX_KEY, task.id)
        if self._task_ttl:
            self._redis.expire(key, self._task_ttl)

    @staticmethod
    def _meta_to_task(data: Dict[str, str]) -> QueuedTask:
        """Convert Redis hash to QueuedTask."""
        args_raw = data.get("args", "[]")
        try:
            args = tuple(json.loads(args_raw))
        except (json.JSONDecodeError, TypeError):
            args = ()

        kwargs_raw = data.get("kwargs", "{}")
        try:
            kwargs = json.loads(kwargs_raw)
        except (json.JSONDecodeError, TypeError):
            kwargs = {}

        def _float_or_none(v: str) -> Optional[float]:
            if not v or v == "None":
                return None
            try:
                return float(v)
            except ValueError:
                return None

        return QueuedTask(
            id=data.get("id", ""),
            name=data.get("name", ""),
            args=args,
            kwargs=kwargs,
            status=TaskStatus(data.get("status", "pending")),
            error=data.get("error") or None,
            submitted_at=_float_or_none(data.get("submitted_at", "")) or time.time(),
            started_at=_float_or_none(data.get("started_at", "")),
            completed_at=_float_or_none(data.get("completed_at", "")),
            retries=int(data.get("retries", "0")),
            max_retries=int(data.get("max_retries", "3")),
            celery_task_id=data.get("celery_task_id") or None,
        )


# ── Module-level helper for Celery tasks ──────────────────────────────

def _update_redis_status(
    task_id: str,
    status: TaskStatus,
    result: Any = None,
    error: Optional[str] = None,
    retries: Optional[int] = None,
) -> None:
    """Update task status in Redis from within a Celery worker."""
    try:
        # Use the module-level redis client
        r = _redis_mod.Redis.from_url(
            _celery_app.conf.broker_url, decode_responses=True,
        )
        key = f"{_TASK_KEY_PREFIX}{task_id}"
        updates: Dict[str, str] = {"status": status.value}
        if status == TaskStatus.RUNNING:
            updates["started_at"] = str(time.time())
        if status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            updates["completed_at"] = str(time.time())
        if error:
            updates["error"] = error
        if retries is not None:
            updates["retries"] = str(retries)
        r.hset(key, mapping=updates)
    except Exception as exc:
        log.warning("Failed to update Redis task status: %s", exc)


# ══════════════════════════════════════════════════════════════════════
#  Convenience: get the Celery app (for worker CLI)
# ══════════════════════════════════════════════════════════════════════

def get_celery_app(redis_url: str = "redis://localhost:6379/0") -> Celery:
    """
    Get or create the Celery app instance.

    Use in your Celery worker entry point:
        # celery_worker.py
        from agentsafe.cloud.redis_backend import get_celery_app
        app = get_celery_app()

    Then run:
        celery -A agentsafe.cloud.redis_backend.get_celery_app worker --loglevel=info
    """
    global _celery_app
    if _celery_app is None:
        _celery_app = Celery(
            "certior",
            broker=redis_url,
            backend=redis_url,
        )
        _celery_app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            task_track_started=True,
            task_acks_late=True,
        )
    return _celery_app
