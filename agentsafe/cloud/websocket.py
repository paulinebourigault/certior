"""
WebSocket streaming for real-time execution updates.

Provides an in-process connection manager that tracks subscribers per execution
and broadcasts status updates. Works standalone for testing and integrates
with FastAPI's WebSocket support in the API layer.
"""
from __future__ import annotations
import asyncio
import json
import time
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class StreamUpdate:
    """A single update pushed to subscribers."""
    execution_id: str
    status: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "data": self.data,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class ExecutionStream:
    """
    Manages WebSocket-style subscriptions for execution updates.

    Subscribers register an async callback per execution_id.
    When an update is emitted, all subscribers for that execution
    receive the update concurrently.

    This is a pure-Python implementation that works without FastAPI
    for testing, while the API layer wraps real WebSocket objects
    as subscriber callbacks.
    """

    def __init__(self, *, history_limit: int = 100):
        # execution_id -> list of async callbacks
        self._subscribers: Dict[str, List[Callable]] = {}
        # execution_id -> recent updates (bounded ring buffer)
        self._history: Dict[str, List[StreamUpdate]] = {}
        self._history_limit = history_limit
        self._global_listeners: List[Callable] = []

    async def subscribe(
        self,
        execution_id: str,
        callback: Callable[[StreamUpdate], Any],
    ) -> Callable:
        """
        Subscribe to updates for an execution.

        Args:
            execution_id: The execution to watch.
            callback: Async callable invoked with each StreamUpdate.

        Returns:
            An unsubscribe function.
        """
        if execution_id not in self._subscribers:
            self._subscribers[execution_id] = []
        self._subscribers[execution_id].append(callback)

        def unsubscribe():
            subs = self._subscribers.get(execution_id, [])
            if callback in subs:
                subs.remove(callback)
            if not subs:
                self._subscribers.pop(execution_id, None)

        return unsubscribe

    def add_global_listener(self, callback: Callable[[StreamUpdate], Any]):
        """Add listener that receives ALL updates across all executions."""
        self._global_listeners.append(callback)

    async def emit(self, update: StreamUpdate):
        """Broadcast an update to all subscribers of the execution."""
        eid = update.execution_id

        # Store in history
        if eid not in self._history:
            self._history[eid] = []
        self._history[eid].append(update)
        if len(self._history[eid]) > self._history_limit:
            self._history[eid] = self._history[eid][-self._history_limit:]

        # Notify execution subscribers
        tasks = []
        for cb in list(self._subscribers.get(eid, [])):
            tasks.append(self._safe_call(cb, update))

        # Notify global listeners
        for cb in list(self._global_listeners):
            tasks.append(self._safe_call(cb, update))

        if tasks:
            await asyncio.gather(*tasks)

    async def emit_status(
        self,
        execution_id: str,
        status: str,
        **extra: Any,
    ):
        """Convenience: emit a status update with optional extra data."""
        await self.emit(StreamUpdate(
            execution_id=execution_id,
            status=status,
            data=extra,
        ))

    def get_history(
        self,
        execution_id: str,
        since: Optional[float] = None,
    ) -> List[StreamUpdate]:
        """Return stored history for an execution, optionally filtered by time."""
        history = self._history.get(execution_id, [])
        if since is not None:
            history = [u for u in history if u.timestamp >= since]
        return list(history)

    @property
    def subscriber_count(self) -> int:
        return sum(len(v) for v in self._subscribers.values())

    def execution_ids(self) -> Set[str]:
        return set(self._subscribers.keys()) | set(self._history.keys())

    def clear(self, execution_id: Optional[str] = None):
        """Clear history and subscribers for one or all executions."""
        if execution_id:
            self._subscribers.pop(execution_id, None)
            self._history.pop(execution_id, None)
        else:
            self._subscribers.clear()
            self._history.clear()
            self._global_listeners.clear()

    @staticmethod
    async def _safe_call(cb: Callable, update: StreamUpdate):
        try:
            result = cb(update)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            pass  # Don't let one subscriber break others
