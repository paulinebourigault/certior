"""Tests for agentsafe.cloud.websocket - ExecutionStream."""
import asyncio
import pytest
from agentsafe.cloud.websocket import ExecutionStream, StreamUpdate


@pytest.fixture
def stream():
    return ExecutionStream(history_limit=10)


class TestStreamUpdate:
    def test_to_dict(self):
        u = StreamUpdate(execution_id="e1", status="running", data={"step": 1})
        d = u.to_dict()
        assert d["execution_id"] == "e1"
        assert d["status"] == "running"
        assert d["data"]["step"] == 1
        assert "timestamp" in d

    def test_to_json(self):
        u = StreamUpdate(execution_id="e1", status="done")
        j = u.to_json()
        import json
        parsed = json.loads(j)
        assert parsed["execution_id"] == "e1"


class TestExecutionStream:
    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self, stream):
        received = []

        async def cb(update):
            received.append(update)

        unsub = await stream.subscribe("ex1", cb)
        await stream.emit(StreamUpdate(execution_id="ex1", status="planning"))
        assert len(received) == 1
        assert received[0].status == "planning"
        unsub()

    @pytest.mark.asyncio
    async def test_unsubscribe(self, stream):
        received = []
        unsub = await stream.subscribe("ex1", lambda u: received.append(u))
        unsub()
        await stream.emit(StreamUpdate(execution_id="ex1", status="running"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, stream):
        r1, r2 = [], []
        await stream.subscribe("ex1", lambda u: r1.append(u))
        await stream.subscribe("ex1", lambda u: r2.append(u))
        await stream.emit(StreamUpdate(execution_id="ex1", status="done"))
        assert len(r1) == 1
        assert len(r2) == 1

    @pytest.mark.asyncio
    async def test_no_cross_execution(self, stream):
        received = []
        await stream.subscribe("ex1", lambda u: received.append(u))
        await stream.emit(StreamUpdate(execution_id="ex2", status="running"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_emit_status_convenience(self, stream):
        received = []
        await stream.subscribe("ex1", lambda u: received.append(u))
        await stream.emit_status("ex1", "executing", step=3)
        assert received[0].data["step"] == 3

    @pytest.mark.asyncio
    async def test_history(self, stream):
        await stream.emit(StreamUpdate(execution_id="ex1", status="a"))
        await stream.emit(StreamUpdate(execution_id="ex1", status="b"))
        h = stream.get_history("ex1")
        assert len(h) == 2
        assert h[0].status == "a"

    @pytest.mark.asyncio
    async def test_history_limit(self, stream):
        for i in range(15):
            await stream.emit(StreamUpdate(execution_id="ex1", status=f"s{i}"))
        h = stream.get_history("ex1")
        assert len(h) == 10  # history_limit=10

    @pytest.mark.asyncio
    async def test_history_since(self, stream):
        import time
        t0 = time.time()
        await stream.emit(StreamUpdate(execution_id="ex1", status="old", timestamp=t0 - 100))
        await stream.emit(StreamUpdate(execution_id="ex1", status="new", timestamp=t0))
        h = stream.get_history("ex1", since=t0 - 1)
        assert len(h) == 1
        assert h[0].status == "new"

    @pytest.mark.asyncio
    async def test_global_listener(self, stream):
        received = []
        stream.add_global_listener(lambda u: received.append(u))
        await stream.emit(StreamUpdate(execution_id="ex1", status="x"))
        await stream.emit(StreamUpdate(execution_id="ex2", status="y"))
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_subscriber_count(self, stream):
        assert stream.subscriber_count == 0
        await stream.subscribe("ex1", lambda u: None)
        await stream.subscribe("ex2", lambda u: None)
        assert stream.subscriber_count == 2

    @pytest.mark.asyncio
    async def test_execution_ids(self, stream):
        await stream.emit(StreamUpdate(execution_id="ex1", status="a"))
        await stream.subscribe("ex2", lambda u: None)
        ids = stream.execution_ids()
        assert "ex1" in ids
        assert "ex2" in ids

    @pytest.mark.asyncio
    async def test_clear_single(self, stream):
        await stream.subscribe("ex1", lambda u: None)
        await stream.emit(StreamUpdate(execution_id="ex1", status="a"))
        stream.clear("ex1")
        assert stream.subscriber_count == 0
        assert len(stream.get_history("ex1")) == 0

    @pytest.mark.asyncio
    async def test_clear_all(self, stream):
        await stream.subscribe("ex1", lambda u: None)
        await stream.emit(StreamUpdate(execution_id="ex2", status="b"))
        stream.add_global_listener(lambda u: None)
        stream.clear()
        assert stream.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_broken_subscriber_doesnt_block(self, stream):
        """A subscriber that raises should not prevent others from receiving."""
        ok_received = []

        async def bad(u):
            raise RuntimeError("boom")

        await stream.subscribe("ex1", bad)
        await stream.subscribe("ex1", lambda u: ok_received.append(u))

        await stream.emit(StreamUpdate(execution_id="ex1", status="fine"))
        assert len(ok_received) == 1
