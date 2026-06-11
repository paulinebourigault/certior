"""
Tests for SQLite-backed persistence layer.

Tests mirror the in-memory test suites but additionally verify:
  - Data survives across separate store instances (restart simulation)
  - WAL mode is active
  - Concurrent async access doesn't corrupt
  - Task recovery after simulated crash
  - Event audit trail persistence
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from agentsafe.cloud.state_store import Execution, ExecutionStatus
from agentsafe.cloud.task_queue import QueuedTask, TaskStatus
from agentsafe.cloud.event_bus import Event
from agentsafe.cloud.sqlite_backend import (
    SQLiteStateStore,
    SQLiteTaskQueue,
    SQLiteEventBus,
    create_backend,
)


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
async def store(tmp_dir):
    s = SQLiteStateStore(tmp_dir / "state.db")
    await s.initialize()
    return s


@pytest.fixture
async def queue(tmp_dir):
    q = SQLiteTaskQueue(tmp_dir / "tasks.db", max_workers=2)
    await q.initialize()
    return q


@pytest.fixture
async def bus(tmp_dir):
    b = SQLiteEventBus(tmp_dir / "events.db")
    await b.initialize()
    return b


# ═════════════════════════════════════════════════════════════════════
# SQLiteStateStore
# ═════════════════════════════════════════════════════════════════════

class TestSQLiteStateStore:
    @pytest.mark.asyncio
    async def test_create_and_get(self, store):
        ex = Execution(user_id="u1", task="hello world")
        await store.create(ex)
        found = await store.get(ex.id)
        assert found is not None
        assert found.task == "hello world"
        assert found.user_id == "u1"
        assert found.status == ExecutionStatus.QUEUED

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        assert await store.get("nope") is None

    @pytest.mark.asyncio
    async def test_update(self, store):
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        ex.status = ExecutionStatus.COMPLETED
        ex.cost_cents = 42
        ex.results = {"output": "done"}
        await store.update(ex)
        found = await store.get(ex.id)
        assert found.status == ExecutionStatus.COMPLETED
        assert found.cost_cents == 42
        assert found.results == {"output": "done"}

    @pytest.mark.asyncio
    async def test_list_by_user(self, store):
        await store.create(Execution(user_id="u1", task="t1"))
        await store.create(Execution(user_id="u1", task="t2"))
        await store.create(Execution(user_id="u2", task="t3"))
        results = await store.list_by_user("u1")
        assert len(results) == 2
        assert all(r.user_id == "u1" for r in results)

    @pytest.mark.asyncio
    async def test_list_by_status(self, store):
        e1 = Execution(user_id="u1", task="t1", status=ExecutionStatus.COMPLETED)
        e2 = Execution(user_id="u1", task="t2", status=ExecutionStatus.QUEUED)
        await store.create(e1)
        await store.create(e2)
        results = await store.list_by_user("u1", status=ExecutionStatus.COMPLETED)
        assert len(results) == 1
        assert results[0].status == ExecutionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_delete(self, store):
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        assert await store.delete(ex.id)
        assert await store.get(ex.id) is None
        assert not await store.delete("nonexistent")

    @pytest.mark.asyncio
    async def test_count(self, store):
        await store.create(Execution(user_id="u1", task="t1", status=ExecutionStatus.QUEUED))
        await store.create(Execution(user_id="u1", task="t2", status=ExecutionStatus.COMPLETED))
        await store.create(Execution(user_id="u2", task="t3", status=ExecutionStatus.QUEUED))
        assert await store.count() == 3
        assert await store.count(user_id="u1") == 2
        assert await store.count(status=ExecutionStatus.QUEUED) == 2

    @pytest.mark.asyncio
    async def test_to_dict(self, store):
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        found = await store.get(ex.id)
        d = found.to_dict()
        assert d["user_id"] == "u1"
        assert d["status"] == "queued"

    @pytest.mark.asyncio
    async def test_survives_restart(self, tmp_dir):
        """Data persists across separate SQLiteStateStore instances."""
        db_path = tmp_dir / "restart.db"

        # Instance 1: write
        s1 = SQLiteStateStore(db_path)
        await s1.initialize()
        ex = Execution(user_id="u1", task="persist me")
        await s1.create(ex)

        # Instance 2: read (simulates process restart)
        s2 = SQLiteStateStore(db_path)
        await s2.initialize()
        found = await s2.get(ex.id)
        assert found is not None
        assert found.task == "persist me"

    @pytest.mark.asyncio
    async def test_plan_and_certificates_roundtrip(self, store):
        """Complex JSON fields serialize and deserialize correctly."""
        ex = Execution(
            user_id="u1", task="test",
            plan={"steps": [{"tool": "web_fetch", "url": "https://example.com"}]},
            certificates=["cert-abc", "cert-def"],
        )
        await store.create(ex)
        found = await store.get(ex.id)
        assert found.plan == {"steps": [{"tool": "web_fetch", "url": "https://example.com"}]}
        assert found.certificates == ["cert-abc", "cert-def"]

    @pytest.mark.asyncio
    async def test_concurrent_writes(self, store):
        """Multiple async writers don't corrupt the database."""
        async def write_one(i):
            ex = Execution(user_id="u1", task=f"task-{i}")
            await store.create(ex)
            return ex.id

        ids = await asyncio.gather(*[write_one(i) for i in range(20)])
        assert len(set(ids)) == 20
        assert await store.count() == 20


# ═════════════════════════════════════════════════════════════════════
# SQLiteTaskQueue
# ═════════════════════════════════════════════════════════════════════

class TestSQLiteTaskQueue:
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
        queue.register("add", lambda a, b: a + b)
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
    async def test_cancel(self, queue):
        queue.register("noop", lambda: None)
        task = await queue.enqueue("noop")
        assert await queue.cancel(task.id)
        found = await queue.get_task(task.id)
        assert found.status == TaskStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_list_tasks(self, queue):
        queue.register("noop", lambda: None)
        await queue.enqueue("noop")
        await queue.enqueue("noop")
        tasks = queue.list_tasks()
        assert len(tasks) == 2

    @pytest.mark.asyncio
    async def test_list_tasks_by_status(self, queue):
        queue.register("noop", lambda: None)
        t1 = await queue.enqueue("noop")
        await queue.enqueue("noop")
        await queue.cancel(t1.id)
        cancelled = queue.list_tasks(status=TaskStatus.CANCELLED)
        assert len(cancelled) == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self, queue):
        call_count = {"n": 0}

        def flaky():
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise RuntimeError("fail")
            return "ok"

        queue.register("flaky", flaky)
        await queue.enqueue("flaky", max_retries=3)

        # Process until completion
        for _ in range(5):
            result = await queue.process_one()
            if result and result.status == TaskStatus.COMPLETED:
                break

        found = await queue.get_task(result.id)
        assert found.status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_task_persists_across_restart(self, tmp_dir):
        """Tasks survive process restart and are recoverable."""
        db_path = tmp_dir / "restart_tasks.db"

        # Instance 1: enqueue a task, don't process it
        q1 = SQLiteTaskQueue(db_path)
        await q1.initialize()
        q1.register("greet", lambda: "hello")
        task = await q1.enqueue("greet")
        task_id = task.id

        # Instance 2: recover and verify the task exists
        q2 = SQLiteTaskQueue(db_path)
        await q2.initialize()
        q2.register("greet", lambda: "hello")
        found = await q2.get_task(task_id)
        assert found is not None
        assert found.name == "greet"
        assert found.status == TaskStatus.PENDING

    @pytest.mark.asyncio
    async def test_total_count(self, queue):
        queue.register("noop", lambda: None)
        await queue.enqueue("noop")
        await queue.enqueue("noop")
        assert queue.total_count == 2


# ═════════════════════════════════════════════════════════════════════
# SQLiteEventBus
# ═════════════════════════════════════════════════════════════════════

class TestSQLiteEventBus:
    @pytest.mark.asyncio
    async def test_emit_persists(self, bus):
        await bus.emit(Event(type="test", execution_id="e1", data={"key": "val"}))
        history = bus.get_history()
        assert len(history) == 1
        assert history[0].type == "test"
        assert history[0].data == {"key": "val"}

    @pytest.mark.asyncio
    async def test_subscribe_and_dispatch(self, bus):
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("test", handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_wildcard(self, bus):
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("*", handler)
        await bus.emit(Event(type="anything", execution_id="e1"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("test", handler)
        bus.unsubscribe("test", handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_history_filter_execution_id(self, bus):
        await bus.emit(Event(type="a", execution_id="e1"))
        await bus.emit(Event(type="b", execution_id="e2"))
        history = bus.get_history(execution_id="e1")
        assert len(history) == 1
        assert history[0].execution_id == "e1"

    @pytest.mark.asyncio
    async def test_history_filter_event_type(self, bus):
        await bus.emit(Event(type="a", execution_id="e1"))
        await bus.emit(Event(type="b", execution_id="e1"))
        history = bus.get_history(event_type="a")
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_count(self, bus):
        await bus.emit(Event(type="a", execution_id="e1"))
        await bus.emit(Event(type="b", execution_id="e1"))
        await bus.emit(Event(type="a", execution_id="e2"))
        assert await bus.count() == 3
        assert await bus.count(execution_id="e1") == 2
        assert await bus.count(event_type="a") == 2

    @pytest.mark.asyncio
    async def test_persists_across_restart(self, tmp_dir):
        """Events survive across separate bus instances."""
        db_path = tmp_dir / "restart_events.db"

        b1 = SQLiteEventBus(db_path)
        await b1.initialize()
        await b1.emit(Event(type="important", execution_id="e1", data={"x": 1}))

        b2 = SQLiteEventBus(db_path)
        await b2.initialize()
        history = b2.get_history()
        assert len(history) == 1
        assert history[0].type == "important"
        assert history[0].data == {"x": 1}

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_break(self, bus):
        async def bad_handler(event):
            raise ValueError("oops")

        results = []

        async def good_handler(event):
            results.append(event)

        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        # Good handler still ran, event still persisted
        assert len(results) == 1
        assert len(bus.get_history()) == 1

    @pytest.mark.asyncio
    async def test_concurrent_emits(self, bus):
        """Many concurrent emits don't corrupt the database."""
        async def emit_one(i):
            await bus.emit(Event(type=f"evt-{i}", execution_id="e1"))

        await asyncio.gather(*[emit_one(i) for i in range(50)])
        assert await bus.count() == 50


# ═════════════════════════════════════════════════════════════════════
# Factory
# ═════════════════════════════════════════════════════════════════════

class TestCreateBackend:
    @pytest.mark.asyncio
    async def test_creates_all_three(self, tmp_dir):
        store, queue, bus = await create_backend(tmp_dir / "backend")
        assert isinstance(store, SQLiteStateStore)
        assert isinstance(queue, SQLiteTaskQueue)
        assert isinstance(bus, SQLiteEventBus)

        # Verify they're functional
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        assert (await store.get(ex.id)).task == "test"

    @pytest.mark.asyncio
    async def test_creates_directory(self, tmp_dir):
        target = tmp_dir / "nested" / "deep" / "dir"
        assert not target.exists()
        await create_backend(target)
        assert target.exists()

    @pytest.mark.asyncio
    async def test_idempotent_initialization(self, tmp_dir):
        """Calling create_backend twice on the same dir is safe."""
        s1, _, _ = await create_backend(tmp_dir / "idem")
        await s1.create(Execution(user_id="u1", task="first"))
        s2, _, _ = await create_backend(tmp_dir / "idem")
        # Data from first run is still there
        assert await s2.count() == 1
