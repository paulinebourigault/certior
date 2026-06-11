#!/usr/bin/env python3
"""
Example 2: Verified Task Execution
====================================

Submits a task to Certior and watches it execute.  Every tool call
the agent makes is Z3-verified before execution - if verification
fails, the call is blocked.

This example shows the full lifecycle:
  1. Submit task via POST /api/v1/tasks
  2. Poll execution status
  3. Retrieve results with proof certificates

Run:
    python examples/02_verified_task.py

Prerequisites:
    ./run.sh   (in another terminal)
    ANTHROPIC_API_KEY set for full agent mode (optional)
"""
import sys
import os
import time
sys.path.insert(0, os.path.dirname(__file__))
from _helpers import make_client, check_server, heading

heading("Example 2: Verified Task Execution")

client, base = make_client(timeout=120.0)
health = check_server(client)

# ── Submit a task ─────────────────────────────────────────────────────
task = "Write a haiku about computer security and save it to a file called haiku.txt"

print(f"Submitting task: \"{task}\"")
print(f"  Mode:    {health['mode']}")
print(f"  Policy:  default")
print()

resp = client.post("/api/v1/tasks", json={
    "task": task,
    "compliance_policy": "default",
    "budget_cents": 5000,
})
resp.raise_for_status()
submit = resp.json()

execution_id = submit["execution_id"]
print(f"  Execution ID:    {execution_id}")
print(f"  Status:          {submit['status']}")
print(f"  WebSocket URL:   {submit['websocket_url']}")

# ── Poll for completion ───────────────────────────────────────────────
print("\nWaiting for execution to complete...")
deadline = time.time() + 90
last_status = ""

while time.time() < deadline:
    resp = client.get(f"/api/v1/executions/{execution_id}")
    resp.raise_for_status()
    execution = resp.json()
    status = execution["status"]

    if status != last_status:
        elapsed = time.time() - (deadline - 90)
        print(f"  [{elapsed:5.1f}s] Status: {status}")
        last_status = status

    if status in ("completed", "failed", "cancelled"):
        break

    time.sleep(1.0)
else:
    print("  Timed out waiting for completion.")
    sys.exit(1)

# ── Display results ───────────────────────────────────────────────────
print()
if execution["status"] == "completed":
    print("✅ Task completed successfully!")
    print(f"  Cost:          {execution.get('cost_cents', 0)} cents")
    print(f"  Certificates:  {execution.get('certificate_count', 0)}")

    # Show the compliance export
    resp = client.get(f"/api/v1/compliance/{execution_id}/export?preset=default")
    if resp.status_code == 200:
        export = resp.json()
        print(f"\n  Compliance export:")
        print(f"    Policy:      {export.get('policy', {}).get('name', 'N/A')}")
        print(f"    Audit trail: {len(export.get('audit_trail', []))} entries")
        if export.get("certificates"):
            print(f"    Proof certs: {len(export['certificates'])}")
else:
    print(f"❌ Task {execution['status']}: {execution.get('error', 'unknown')}")

heading("Done - every tool call was Z3-verified before execution!")
