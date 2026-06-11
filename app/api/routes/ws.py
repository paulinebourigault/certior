"""
WebSocket /ws/executions/{id} - real-time execution updates.
"""
from __future__ import annotations
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/executions/{execution_id}")
async def execution_ws(websocket: WebSocket, execution_id: str):
    """
    Stream execution updates over WebSocket.

    On connect the client receives any buffered history, then
    receives live updates until the execution completes or the
    client disconnects.
    """
    await websocket.accept()
    stream = websocket.app.state.stream

    # Send buffered history
    for update in stream.get_history(execution_id):
        await websocket.send_json(update.to_dict())

    # Subscribe to live updates
    async def _forward(update):
        try:
            await websocket.send_json(update.to_dict())
        except Exception:
            pass

    unsub = await stream.subscribe(execution_id, _forward)

    try:
        while True:
            # Keep connection alive; client may send pings or commands
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        unsub()
