"""
Tests for Redis/Celery task queue backend.

Requires REDIS_URL env var pointing to a running Redis instance.
Skipped automatically when Redis is not available.

In CI, Redis is provided as a GitHub Actions service container.
Locally: docker run -d -p6379:6379 redis:7-alpine
"""
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

REDIS_URL = os.getenv("REDIS_URL")
_skip_reason = None
if not REDIS_URL:
    _skip_reason = "REDIS_URL not set - skipping Redis tests"
else:
    try:
        import redis as _redis_mod
        import celery as _celery_mod
    except ImportError as e:
        _skip_reason = f"Missing dependency: {e}"

pytestmark = pytest.mark.skipif(_skip_reason is not None, reason=_skip_reason or "")


@pytest.fixture
def redis_client():
    """Raw Redis client for verification."""
    import redis
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    yield r
    r.close()


@pytest.fixture
def queue(redis_client):
    """Fresh CeleryTaskQueue with clean Redis state."""
    from agentsafe.cloud.redis_backend import CeleryTaskQueue

    # Flush all certior keys
    for key in redis_client.keys("certior:*"):
        redis_client.delete(key)

    q = CeleryTaskQueue(REDIS_URL)

    # Register a simple test handler
    async def _echo_handler(task_id: str, value: str = "default"):
        return {"echoed": value, "task_id": task_id}

    q.register("echo_task", _echo_handler)

    # Register a failing handler
    async def _fail_handler(task_id: str):
        raise ValueError("intentional failure")

    q.register("fail_task", _fail_handler)

    yield q


# ══════════════════════════════════════════════════════════════════════
#  Core interface
# ══════════════════════════════════════════════════════════════════════

class TestCeleryTaskQueueInterface:
    """Tests that CeleryTaskQueue satisfies the TaskQueue interface."""

    @pytest.mark.asyncio
    async def test_register_handler(self, queue):
        assert "echo_task" in queue._handlers
        assert "fail_task" in queue._handlers

    @pytest.mark.asyncio
    async def test_register_unknown_raises(self, queue):
        with pytest.raises(ValueError, match="No handler"):
            await queue.enqueue("nonexistent_task", "arg1")

    @pytest.mark.asyncio
    async def test_enqueue_creates_metadata(self, queue, redis_client):
        task = await queue.enqueue("echo_task", "exec-123", value="hello")

        assert task.id is not None
        assert task.name == "echo_task"
        assert task.status.value == "pending"

        # Verify Redis metadata
        key = f"certior:task:{task.id}"
        meta = redis_client.hgetall(key)
        assert meta["name"] == "echo_task"
        assert meta["status"] == "pending"

    @pytest.mark.asyncio
    async def test_get_task(self, queue):
        task = await queue.enqueue("echo_task", "exec-1")

        fetched = await queue.get_task(task.id)
        assert fetched is not None
        assert fetched.id == task.id
        assert fetched.name == "echo_task"

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, queue):
        result = await queue.get_task("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_tasks(self, queue):
        for i in range(5):
            await queue.enqueue("echo_task", f"exec-{i}")

        tasks = queue.list_tasks()
        assert len(tasks) == 5
        assert all(t.name == "echo_task" for t in tasks)

    @pytest.mark.asyncio
    async def test_list_tasks_with_status_filter(self, queue):
        from agentsafe.cloud.redis_backend import TaskStatus

        t1 = await queue.enqueue("echo_task", "exec-1")
        t2 = await queue.enqueue("echo_task", "exec-2")

        pending = queue.list_tasks(status=TaskStatus.PENDING)
        assert len(pending) == 2

    @pytest.mark.asyncio
    async def test_cancel_pending_task(self, queue):
        task = await queue.enqueue("echo_task", "exec-1")

        assert await queue.cancel(task.id) is True

        fetched = await queue.get_task(task.id)
        assert fetched.status.value == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_returns_false(self, queue):
        assert await queue.cancel("nonexistent") is False

    @pytest.mark.asyncio
    async def test_total_count(self, queue):
        assert queue.total_count == 0
        await queue.enqueue("echo_task", "exec-1")
        await queue.enqueue("echo_task", "exec-2")
        assert queue.total_count == 2


# ══════════════════════════════════════════════════════════════════════
#  Direct execution (bypass Celery broker)
# ══════════════════════════════════════════════════════════════════════

class TestDirectExecution:
    """Test process_one which bypasses Celery for local testing."""

    @pytest.mark.asyncio
    async def test_process_one_success(self, queue):
        task = await queue.enqueue("echo_task", "exec-1", value="world")

        processed = await queue.process_one()
        assert processed is not None
        assert processed.status.value == "completed"

    @pytest.mark.asyncio
    async def test_process_one_empty_queue(self, queue):
        result = await queue.process_one()
        assert result is None

    @pytest.mark.asyncio
    async def test_process_one_failure(self, queue):
        await queue.enqueue("fail_task", "exec-1")

        processed = await queue.process_one()
        assert processed is not None
        assert processed.status.value == "failed"
        assert "intentional failure" in processed.error


# ══════════════════════════════════════════════════════════════════════
#  Start / stop lifecycle
# ══════════════════════════════════════════════════════════════════════

class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop(self, queue):
        await queue.start()
        assert queue._running is True

        await queue.stop()
        assert queue._running is False

    @pytest.mark.asyncio
    async def test_start_idempotent(self, queue):
        await queue.start()
        await queue.start()  # no error
        assert queue._running is True
        await queue.stop()


# ══════════════════════════════════════════════════════════════════════
#  Redis metadata serialisation
# ══════════════════════════════════════════════════════════════════════

class TestMetadataSerialization:
    """Verify task metadata survives Redis round-trip."""

    @pytest.mark.asyncio
    async def test_args_round_trip(self, queue):
        task = await queue.enqueue(
            "echo_task", "exec-1", value="complex data"
        )

        fetched = await queue.get_task(task.id)
        assert fetched.name == "echo_task"
        # args are serialised as JSON list
        assert "exec-1" in fetched.args

    @pytest.mark.asyncio
    async def test_timestamps_persisted(self, queue):
        before = time.time()
        task = await queue.enqueue("echo_task", "exec-1")
        after = time.time()

        fetched = await queue.get_task(task.id)
        assert before <= fetched.submitted_at <= after


# ══════════════════════════════════════════════════════════════════════
#  Celery app
# ══════════════════════════════════════════════════════════════════════

class TestCeleryApp:
    def test_get_celery_app(self):
        from agentsafe.cloud.redis_backend import get_celery_app

        app = get_celery_app(REDIS_URL)
        assert app is not None
        assert app.main == "certior"

    def test_get_celery_app_singleton(self):
        from agentsafe.cloud.redis_backend import get_celery_app

        app1 = get_celery_app(REDIS_URL)
        app2 = get_celery_app(REDIS_URL)
        assert app1 is app2
