"""Tests for agentsafe.cloud.task_queue - TaskQueue."""
import asyncio
import pytest
from agentsafe.cloud.task_queue import TaskQueue, QueuedTask, TaskStatus


@pytest.fixture
def queue():
    return TaskQueue(max_workers=2)


class TestQueuedTask:
    def test_defaults(self):
        t = QueuedTask(name="test")
        assert t.status == TaskStatus.PENDING
        assert t.id
        assert t.max_retries == 3

    def test_to_dict(self):
        t = QueuedTask(name="job", retries=1)
        d = t.to_dict()
        assert d["name"] == "job"
        assert d["status"] == "pending"
        assert d["retries"] == 1


class TestTaskQueue:
    @pytest.mark.asyncio
    async def test_register_and_enqueue(self, queue):
        queue.register("greet", lambda name: f"hello {name}")
        task = await queue.enqueue("greet", "world")
        assert task.status == TaskStatus.PENDING
        assert queue.pending_count == 1

    @pytest.mark.asyncio
    async def test_enqueue_unknown_handler(self, queue):
        with pytest.raises(ValueError, match="No handler"):
            await queue.enqueue("missing")

    @pytest.mark.asyncio
    async def test_process_one_sync(self, queue):
        results = []
        queue.register("add", lambda a, b: results.append(a + b) or (a + b))
        await queue.enqueue("add", 2, 3)
        task = await queue.process_one()
        assert task.status == TaskStatus.COMPLETED
        assert task.result == 5

    @pytest.mark.asyncio
    async def test_process_one_async(self, queue):
        async def slow_add(a, b):
            return a + b

        queue.register("slow_add", slow_add)
        await queue.enqueue("slow_add", 10, 20)
        task = await queue.process_one()
        assert task.status == TaskStatus.COMPLETED
        assert task.result == 30

    @pytest.mark.asyncio
    async def test_process_one_empty(self, queue):
        result = await queue.process_one()
        assert result is None

    @pytest.mark.asyncio
    async def test_task_failure_retries(self, queue):
        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("fail")
            return "ok"

        queue.register("flaky", flaky)
        await queue.enqueue("flaky", max_retries=3)

        # First attempt → fail → re-queue
        t = await queue.process_one()
        assert t.status == TaskStatus.PENDING  # re-queued
        assert t.retries == 1

        # Second attempt → fail → re-queue
        t = await queue.process_one()
        assert t.status == TaskStatus.PENDING
        assert t.retries == 2

        # Third attempt → success
        t = await queue.process_one()
        assert t.status == TaskStatus.COMPLETED
        assert t.result == "ok"

    @pytest.mark.asyncio
    async def test_task_failure_max_retries_exceeded(self, queue):
        queue.register("always_fail", lambda: 1 / 0)
        await queue.enqueue("always_fail", max_retries=2)

        await queue.process_one()  # retry 1
        t = await queue.process_one()  # retry 2 = max → fail
        assert t.status == TaskStatus.FAILED
        assert "division by zero" in t.error

    @pytest.mark.asyncio
    async def test_cancel_pending(self, queue):
        queue.register("noop", lambda: None)
        task = await queue.enqueue("noop")
        ok = await queue.cancel(task.id)
        assert ok is True
        assert task.status == TaskStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_completed_fails(self, queue):
        queue.register("fast", lambda: 42)
        task = await queue.enqueue("fast")
        await queue.process_one()
        ok = await queue.cancel(task.id)
        assert ok is False

    @pytest.mark.asyncio
    async def test_get_task(self, queue):
        queue.register("x", lambda: None)
        task = await queue.enqueue("x")
        fetched = await queue.get_task(task.id)
        assert fetched is task

    @pytest.mark.asyncio
    async def test_get_missing_task(self, queue):
        assert await queue.get_task("nonexistent") is None

    @pytest.mark.asyncio
    async def test_list_tasks(self, queue):
        queue.register("a", lambda: None)
        await queue.enqueue("a")
        await queue.enqueue("a")
        assert len(queue.list_tasks()) == 2

    @pytest.mark.asyncio
    async def test_list_tasks_filter_status(self, queue):
        queue.register("a", lambda: 1)
        await queue.enqueue("a")
        await queue.process_one()
        await queue.enqueue("a")
        completed = queue.list_tasks(status=TaskStatus.COMPLETED)
        assert len(completed) == 1

    @pytest.mark.asyncio
    async def test_total_count(self, queue):
        queue.register("a", lambda: None)
        await queue.enqueue("a")
        await queue.enqueue("a")
        assert queue.total_count == 2

    @pytest.mark.asyncio
    async def test_cancelled_task_not_executed(self, queue):
        executed = []
        queue.register("track", lambda: executed.append(1))
        task = await queue.enqueue("track")
        await queue.cancel(task.id)
        await queue.process_one()
        assert len(executed) == 0

    @pytest.mark.asyncio
    async def test_start_stop(self, queue):
        results = []
        queue.register("bg", lambda v: results.append(v) or v)
        await queue.enqueue("bg", "a")
        await queue.enqueue("bg", "b")
        await queue.start()
        # Give workers time to process
        await asyncio.sleep(0.3)
        await queue.stop(drain=False)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_start_idempotent(self, queue):
        queue.register("x", lambda: None)
        await queue.start()
        await queue.start()  # should not double-start
        await queue.stop(drain=False)
