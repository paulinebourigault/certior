"""
Event bus for execution status updates.
"""
from __future__ import annotations
import asyncio
from typing import Dict, Any, List, Callable, Optional, Awaitable
from dataclasses import dataclass, field
import time


@dataclass
class Event:
    type: str
    execution_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """Async event bus for execution updates."""

    def __init__(self):
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._history: List[Event] = []

    def subscribe(self, event_type: str, handler: EventHandler):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler):
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    async def emit(self, event: Event):
        self._history.append(event)
        handlers = self._handlers.get(event.type, [])
        handlers += self._handlers.get("*", [])  # wildcard
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                pass  # Don't let handler errors break the bus

    def get_history(
        self, execution_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Event]:
        events = self._history
        if execution_id:
            events = [e for e in events if e.execution_id == execution_id]
        if event_type:
            events = [e for e in events if e.type == event_type]
        return events
