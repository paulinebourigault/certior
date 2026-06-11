"""Tests for event bus."""
import pytest
from agentsafe.cloud.event_bus import EventBus, Event


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("test", handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_wildcard(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("*", handler)
        await bus.emit(Event(type="anything", execution_id="e1"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe("test", handler)
        bus.unsubscribe("test", handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_history(self):
        bus = EventBus()
        await bus.emit(Event(type="a", execution_id="e1"))
        await bus.emit(Event(type="b", execution_id="e2"))
        assert len(bus.get_history()) == 2
        assert len(bus.get_history(execution_id="e1")) == 1
        assert len(bus.get_history(event_type="b")) == 1

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_break(self):
        bus = EventBus()

        async def bad_handler(event):
            raise ValueError("oops")

        async def good_handler(event):
            pass

        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)
        await bus.emit(Event(type="test", execution_id="e1"))
        # Should not raise
