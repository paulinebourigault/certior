"""
Task queue for async execution dispatch.

Provides an in-process asyncio-based queue that can be swapped for
Celery, RQ, or any other broker in production.  The interface is
deliberately minimal so that the executor_service doesn't couple
to a specific backend.
"""
from __future__ import annotations
import asyncio
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class QueuedTask:
    """Represents a task submitted to the queue."""
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "error": self.error,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "retries": self.retries,
        }


class TaskQueue:
    """
    In-process async task queue.

    Supports:
    - Registering named task handlers
    - Enqueueing tasks with args/kwargs
    - Concurrent worker processing
    - Retry on failure (up to max_retries)
    - Task status tracking
    - Graceful drain/shutdown

    Swap this for CeleryTaskQueue or RQTaskQueue in production.
    """

    def __init__(self, *, max_workers: int = 4):
        self._handlers: Dict[str, Callable] = {}
        self._tasks: Dict[str, QueuedTask] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._max_workers = max_workers
        self._workers: List[asyncio.Task] = []
        self._running = False

    def register(self, name: str, handler: Callable):
        """Register a named task handler."""
        self._handlers[name] = handler

    async def enqueue(
        self,
        name: str,
        *args: Any,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> QueuedTask:
        """Submit a task for background execution."""
        if name not in self._handlers:
            raise ValueError(f"No handler registered for task: {name}")

        task = QueuedTask(
            name=name,
            args=args,
            kwargs=kwargs,
            max_retries=max_retries,
        )
        self._tasks[task.id] = task
        await self._queue.put(task.id)
        return task

    async def get_task(self, task_id: str) -> Optional[QueuedTask]:
        return self._tasks.get(task_id)

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 50,
    ) -> List[QueuedTask]:
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        tasks.sort(key=lambda t: t.submitted_at, reverse=True)
        return tasks[:limit]

    async def cancel(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            return True
        return False

    async def start(self):
        """Start worker loops."""
        if self._running:
            return
        self._running = True
        for i in range(self._max_workers):
            worker = asyncio.create_task(self._worker_loop(i))
            self._workers.append(worker)

    async def stop(self, *, drain: bool = True):
        """Stop workers.  If drain=True, finish pending tasks first."""
        self._running = False
        if drain:
            await self._queue.join()
        for w in self._workers:
            w.cancel()
        self._workers.clear()

    async def process_one(self):
        """Process exactly one task synchronously (useful for tests)."""
        if self._queue.empty():
            return None
        task_id = await self._queue.get()
        await self._execute_task(task_id)
        self._queue.task_done()
        return self._tasks.get(task_id)

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def total_count(self) -> int:
        return len(self._tasks)

    # ── internals ──

    async def _worker_loop(self, worker_id: int):
        while self._running:
            try:
                task_id = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue
            try:
                await self._execute_task(task_id)
            finally:
                self._queue.task_done()

    async def _execute_task(self, task_id: str):
        task = self._tasks.get(task_id)
        if not task or task.status == TaskStatus.CANCELLED:
            return

        handler = self._handlers.get(task.name)
        if not handler:
            task.status = TaskStatus.FAILED
            task.error = f"No handler for {task.name}"
            return

        task.status = TaskStatus.RUNNING
        task.started_at = time.time()

        try:
            result = handler(*task.args, **task.kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
        except Exception as exc:
            task.retries += 1
            if task.retries < task.max_retries:
                task.status = TaskStatus.PENDING
                await self._queue.put(task_id)
            else:
                task.status = TaskStatus.FAILED
                task.error = str(exc)
                task.completed_at = time.time()
