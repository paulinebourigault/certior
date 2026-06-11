"""
Tests for PostgreSQL persistence backend.

Requires DATABASE_URL env var pointing to a running PostgreSQL instance.
Skipped automatically when PostgreSQL is not available.

In CI, PostgreSQL is provided as a GitHub Actions service container.
Locally: docker run -d -p5432:5432 -e POSTGRES_PASSWORD=certior postgres:16-alpine
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

# Skip entire module if no DATABASE_URL or asyncpg unavailable
DATABASE_URL = os.getenv("DATABASE_URL")
_skip_reason = None
if not DATABASE_URL:
    _skip_reason = "DATABASE_URL not set - skipping PostgreSQL tests"
else:
    try:
        import asyncpg
    except ImportError:
        _skip_reason = "asyncpg not installed"

pytestmark = pytest.mark.skipif(_skip_reason is not None, reason=_skip_reason or "")


@pytest.fixture
async def pg_store():
    """Fresh PgStateStore with clean table."""
    from agentsafe.cloud.postgres_backend import PgStateStore

    store = PgStateStore(DATABASE_URL, min_pool=1, max_pool=3)
    await store.initialize()

    # Truncate for isolation
    async with store._pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE executions")

    yield store
    await store.close()


@pytest.fixture
async def pg_bus():
    """Fresh PgEventBus with clean table."""
    from agentsafe.cloud.postgres_backend import PgEventBus

    bus = PgEventBus(DATABASE_URL, min_pool=1, max_pool=3)
    await bus.initialize()

    async with bus._pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE events")

    yield bus
    await bus.close()


# ══════════════════════════════════════════════════════════════════════
#  PgStateStore
# ══════════════════════════════════════════════════════════════════════

class TestPgStateStore:
    """Tests for PostgreSQL execution state store."""

    @pytest.mark.asyncio
    async def test_create_and_get(self, pg_store):
        from agentsafe.cloud.state_store import Execution, ExecutionStatus

        ex = Execution(
            user_id="user-1", task="test task",
            status=ExecutionStatus.QUEUED,
        )
        await pg_store.create(ex)

        fetched = await pg_store.get(ex.id)
        assert fetched is not None
        assert fetched.id == ex.id
        assert fetched.user_id == "user-1"
        assert fetched.task == "test task"
        assert fetched.status == ExecutionStatus.QUEUED

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_none(self, pg_store):
        result = await pg_store.get("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_update(self, pg_store):
        from agentsafe.cloud.state_store import Execution, ExecutionStatus

        ex = Execution(user_id="u1", task="t1")
        await pg_store.create(ex)

        ex.status = ExecutionStatus.COMPLETED
        ex.cost_cents = 500
        ex.results = {"output": "done"}
        ex.completed_at = time.time()
        await pg_store.update(ex)

        fetched = await pg_store.get(ex.id)
        assert fetched.status == ExecutionStatus.COMPLETED
        assert fetched.cost_cents == 500
        assert fetched.results == {"output": "done"}
        assert fetched.completed_at is not None

    @pytest.mark.asyncio
    async def test_list_by_user(self, pg_store):
        from agentsafe.cloud.state_store import Execution, ExecutionStatus

        for i in range(5):
            ex = Execution(
                user_id="user-list",
                task=f"task-{i}",
                status=ExecutionStatus.COMPLETED if i % 2 == 0 else ExecutionStatus.FAILED,
            )
            await pg_store.create(ex)
            await asyncio.sleep(0.01)  # ensure ordering

        # All
        all_items = await pg_store.list_by_user("user-list")
        assert len(all_items) == 5

        # Filtered
        completed = await pg_store.list_by_user("user-list", status=ExecutionStatus.COMPLETED)
        assert len(completed) == 3  # 0, 2, 4
        assert all(e.status == ExecutionStatus.COMPLETED for e in completed)

        # Limit
        limited = await pg_store.list_by_user("user-list", limit=2)
        assert len(limited) == 2

    @pytest.mark.asyncio
    async def test_delete(self, pg_store):
        from agentsafe.cloud.state_store import Execution

        ex = Execution(user_id="u1", task="t1")
        await pg_store.create(ex)

        assert await pg_store.delete(ex.id) is True
        assert await pg_store.get(ex.id) is None
        assert await pg_store.delete(ex.id) is False

    @pytest.mark.asyncio
    async def test_count(self, pg_store):
        from agentsafe.cloud.state_store import Execution, ExecutionStatus

        assert await pg_store.count() == 0

        for status in [ExecutionStatus.QUEUED, ExecutionStatus.COMPLETED, ExecutionStatus.QUEUED]:
            await pg_store.create(Execution(user_id="u", task="t", status=status))

        assert await pg_store.count() == 3
        assert await pg_store.count(status=ExecutionStatus.QUEUED) == 2
        assert await pg_store.count(status=ExecutionStatus.COMPLETED) == 1

    @pytest.mark.asyncio
    async def test_json_fields_roundtrip(self, pg_store):
        from agentsafe.cloud.state_store import Execution

        ex = Execution(
            user_id="u1", task="t1",
            plan={"steps": [{"tool": "web", "args": {"url": "https://x.com"}}]},
            results={"output": [1, 2, 3], "nested": {"key": "val"}},
            certificates=["cert-1", "cert-2"],
        )
        await pg_store.create(ex)

        fetched = await pg_store.get(ex.id)
        assert fetched.plan == ex.plan
        assert fetched.results == ex.results
        assert fetched.certificates == ["cert-1", "cert-2"]

    @pytest.mark.asyncio
    async def test_concurrent_writes(self, pg_store):
        from agentsafe.cloud.state_store import Execution

        async def _create(i):
            await pg_store.create(Execution(user_id="concurrent", task=f"t-{i}"))

        await asyncio.gather(*[_create(i) for i in range(20)])
        assert await pg_store.count() == 20


# ══════════════════════════════════════════════════════════════════════
#  PgEventBus
# ══════════════════════════════════════════════════════════════════════

class TestPgEventBus:
    """Tests for PostgreSQL event bus."""

    @pytest.mark.asyncio
    async def test_emit_and_get_history(self, pg_bus):
        from agentsafe.cloud.event_bus import Event

        await pg_bus.emit(Event(
            type="execution.created", execution_id="ex-1",
            data={"task": "hello"},
        ))
        await pg_bus.emit(Event(
            type="execution.completed", execution_id="ex-1",
            data={"cost": 100},
        ))

        history = await pg_bus.get_history(execution_id="ex-1")
        assert len(history) == 2

        by_type = await pg_bus.get_history(event_type="execution.completed")
        assert len(by_type) == 1
        assert by_type[0].data["cost"] == 100

    @pytest.mark.asyncio
    async def test_handler_dispatch(self, pg_bus):
        from agentsafe.cloud.event_bus import Event

        received = []

        async def _handler(event: Event):
            received.append(event)

        pg_bus.subscribe("test.event", _handler)

        await pg_bus.emit(Event(type="test.event", execution_id="x", data={"v": 1}))
        assert len(received) == 1
        assert received[0].data == {"v": 1}

        # Unrelated events don't dispatch
        await pg_bus.emit(Event(type="other.event", execution_id="x"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_wildcard_handler(self, pg_bus):
        from agentsafe.cloud.event_bus import Event

        received = []
        pg_bus.subscribe("*", lambda e: received.append(e) or asyncio.sleep(0))

        # Need an actual async handler
        async def _handler(e):
            received.append(e)

        pg_bus.subscribe("*", _handler)

        await pg_bus.emit(Event(type="any.event", execution_id="x"))
        assert len(received) >= 1

    @pytest.mark.asyncio
    async def test_count(self, pg_bus):
        from agentsafe.cloud.event_bus import Event

        assert await pg_bus.count() == 0
        await pg_bus.emit(Event(type="a", execution_id="e1"))
        await pg_bus.emit(Event(type="b", execution_id="e1"))
        await pg_bus.emit(Event(type="c", execution_id="e2"))

        assert await pg_bus.count() == 3
        assert await pg_bus.count(execution_id="e1") == 2


# ══════════════════════════════════════════════════════════════════════
#  Factory
# ══════════════════════════════════════════════════════════════════════

class TestFactory:
    @pytest.mark.asyncio
    async def test_create_pg_backend(self):
        from agentsafe.cloud.postgres_backend import create_pg_backend

        store, bus = await create_pg_backend(DATABASE_URL, min_pool=1, max_pool=2)
        try:
            assert store._pool is not None
            assert bus._pool is not None
        finally:
            await store.close()
            await bus.close()
