#!/usr/bin/env python3
"""
Example 5: WebSocket Real-Time Streaming
==========================================

Submits a task and watches execution events arrive in real time
over a WebSocket connection.  This is how a frontend would show
live progress: verification events, tool calls, and results.

Run:
    python examples/05_websocket_stream.py

Prerequisites:
    ./run.sh   (in another terminal)
    pip install websockets   (auto-installed with certior[all])
"""
import sys
import os
import json
import asyncio
import time

sys.path.insert(0, os.path.dirname(__file__))
from _helpers import get_base_url, get_api_key, heading

heading("Example 5: WebSocket Real-Time Streaming")


async def run():
    import httpx

    base = get_base_url()
    key = get_api_key(base)
    headers = {"Authorization": f"Bearer {key}"}

    # ── Submit task ───────────────────────────────────────────────
    async with httpx.AsyncClient(base_url=base, headers=headers, timeout=30) as client:
        # Check health
        health = (await client.get("/health")).json()
        print(f"  Server mode: {health['mode']}")
        print(f"  LLM active:  {health['llm_configured']}")
        print()

        task = "Calculate the sum of the first 20 prime numbers using Python"
        print(f"  Submitting: \"{task}\"")

        resp = await client.post("/api/v1/tasks", json={
            "task": task,
            "compliance_policy": "default",
            "budget_cents": 5000,
        })
        resp.raise_for_status()
        submit = resp.json()

        execution_id = submit["execution_id"]
        ws_url = submit["websocket_url"]

        print(f"  Execution ID:  {execution_id}")
        print(f"  WebSocket:     {ws_url}")

    # ── Connect WebSocket and listen ──────────────────────────────
    print(f"\n  Connecting to WebSocket for live events...\n")

    try:
        import websockets
    except ImportError:
        print("  websockets package not installed.")
        print("  Install with: pip install websockets")
        print()
        print("  Falling back to polling mode...")
        await _poll_fallback(base, key, execution_id)
        return

    events_received = 0
    start = time.time()

    try:
        async with websockets.connect(ws_url, extra_headers=headers) as ws:
            # Set a timeout for the whole stream
            deadline = time.time() + 90

            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    event = json.loads(raw)
                    events_received += 1
                    elapsed = time.time() - start

                    status = event.get("status", "?")
                    data = event.get("data", {})

                    # Format based on event type
                    if status == "planning":
                        print(f"  [{elapsed:5.1f}s] 📋 Planning task...")
                    elif status == "verifying":
                        tool = data.get("tool", "?")
                        print(f"  [{elapsed:5.1f}s] 🔍 Verifying: {tool}")
                    elif status == "executing":
                        tool = data.get("tool", "?")
                        print(f"  [{elapsed:5.1f}s] ⚡ Executing: {tool}")
                    elif status == "tool_result":
                        tool = data.get("tool", "?")
                        snippet = str(data.get("result", ""))[:80]
                        print(f"  [{elapsed:5.1f}s] ✅ Result from {tool}: {snippet}")
                    elif status in ("completed", "failed"):
                        label = "✅" if status == "completed" else "❌"
                        print(f"  [{elapsed:5.1f}s] {label} {status.upper()}")
                        break
                    else:
                        print(f"  [{elapsed:5.1f}s] 📡 {status}: {json.dumps(data)[:80]}")

                except asyncio.TimeoutError:
                    # No event in 2s - check if execution finished
                    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
                        resp = await client.get(f"/api/v1/executions/{execution_id}")
                        if resp.json().get("status") in ("completed", "failed", "cancelled"):
                            break
                    continue

    except Exception as e:
        print(f"  WebSocket error: {e}")
        print("  Falling back to polling...")
        await _poll_fallback(base, key, execution_id)
        return

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n  Events received: {events_received}")
    print(f"  Total time:      {time.time() - start:.1f}s")

    # Fetch final state
    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
        resp = await client.get(f"/api/v1/executions/{execution_id}")
        execution = resp.json()
        print(f"  Final status:    {execution['status']}")
        print(f"  Cost:            {execution.get('cost_cents', 0)}¢")


async def _poll_fallback(base: str, key: str, execution_id: str):
    """Fallback: poll REST API instead of WebSocket."""
    import httpx

    headers = {"Authorization": f"Bearer {key}"}
    start = time.time()
    last_status = ""

    async with httpx.AsyncClient(base_url=base, headers=headers) as client:
        for _ in range(90):
            resp = await client.get(f"/api/v1/executions/{execution_id}")
            execution = resp.json()
            status = execution["status"]

            if status != last_status:
                elapsed = time.time() - start
                print(f"  [{elapsed:5.1f}s] Status: {status}")
                last_status = status

            if status in ("completed", "failed", "cancelled"):
                if status == "completed":
                    print(f"\n  ✅ Task completed (cost: {execution.get('cost_cents', 0)}¢)")
                else:
                    print(f"\n  ❌ Task {status}: {execution.get('error', '')}")
                break

            await asyncio.sleep(1.0)


heading("Done - real-time event streaming demonstrated!")
print("Key takeaways:")
print("  • WebSocket delivers events as they happen")
print("  • Each verification/execution step is a separate event")
print("  • Frontend can show live progress bars and verification badges")
print("  • Falls back gracefully to REST polling if WS unavailable")
print()


if __name__ == "__main__":
    asyncio.run(run())
