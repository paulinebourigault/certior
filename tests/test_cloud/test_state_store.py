"""Tests for state store."""
import pytest
from agentsafe.cloud.state_store import StateStore, Execution, ExecutionStatus


class TestStateStore:
    @pytest.mark.asyncio
    async def test_create_and_get(self):
        store = StateStore()
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        found = await store.get(ex.id)
        assert found is not None
        assert found.task == "test"

    @pytest.mark.asyncio
    async def test_update(self):
        store = StateStore()
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        ex.status = ExecutionStatus.COMPLETED
        await store.update(ex)
        found = await store.get(ex.id)
        assert found.status == ExecutionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_list_by_user(self):
        store = StateStore()
        await store.create(Execution(user_id="u1", task="t1"))
        await store.create(Execution(user_id="u1", task="t2"))
        await store.create(Execution(user_id="u2", task="t3"))
        results = await store.list_by_user("u1")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_list_by_status(self):
        store = StateStore()
        e1 = Execution(user_id="u1", task="t1", status=ExecutionStatus.COMPLETED)
        e2 = Execution(user_id="u1", task="t2", status=ExecutionStatus.QUEUED)
        await store.create(e1)
        await store.create(e2)
        results = await store.list_by_user("u1", status=ExecutionStatus.COMPLETED)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_delete(self):
        store = StateStore()
        ex = Execution(user_id="u1", task="test")
        await store.create(ex)
        assert await store.delete(ex.id)
        assert await store.get(ex.id) is None
        assert not await store.delete("nonexistent")

    def test_to_dict(self):
        ex = Execution(user_id="u1", task="test")
        d = ex.to_dict()
        assert d["user_id"] == "u1"
        assert d["status"] == "queued"
