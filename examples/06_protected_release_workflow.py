#!/usr/bin/env python3
"""
Example 6: Protected Release Workflow
=====================================

Demonstrates a real safety boundary that an LLM alone cannot enforce:
attempted disclosure of sensitive clinical data to a public audience.

This example submits two real tasks to the running Certior API:

  1. A protected-release request that tries to publish raw patient data.
     Certior classifies it as a release workflow and rejects it unless
     an upstream reviewer execution is supplied.

  2. A de-identified public summary request.
     Certior allows it under the dedicated public-safe summary profile,
     then exports proof-backed compliance evidence.

Run:
    CERTIOR_ENV=production ./run.sh   # separate terminal
    python examples/06_protected_release_workflow.py

Prerequisites:
    - Running API server
    - LLM configured if you want the allowed path to execute fully
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from _helpers import make_client, check_server, heading  # noqa: E402


def _workspace_path() -> Path:
    workspace = os.getenv("CERTIOR_WORKSPACE")
    if workspace:
        return Path(workspace)
    return Path(__file__).resolve().parent.parent / ".workspace"


def _write_fixture() -> Path:
    workspace = _workspace_path()
    workspace.mkdir(parents=True, exist_ok=True)
    fixture = workspace / "patient_release_note.txt"
    fixture.write_text(
        "Patient: Jane Doe\n"
        "DOB: 1987-04-12\n"
        "MRN: 00482917\n"
        "Diagnosis: NSTEMI secondary to LAD stenosis\n"
        "Hospital course: Successful PCI with drug-eluting stent placement.\n"
        "Follow-up: Cardiology in 2 weeks.\n",
        encoding="utf-8",
    )
    return fixture


def _poll_execution(client, execution_id: str, timeout: float = 120.0) -> dict:
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        resp = client.get(f"/api/v1/executions/{execution_id}")
        resp.raise_for_status()
        execution = resp.json()
        status = execution["status"]
        if status != last_status:
            print(f"  Status: {status}")
            last_status = status
        if status in {"completed", "failed", "cancelled", "blocked"}:
            return execution
        time.sleep(1.0)
    raise TimeoutError(f"Execution {execution_id} did not finish in time")


heading("Example 6: Protected Release Workflow")
client, _ = make_client(timeout=180.0)
health = check_server(client)
fixture = _write_fixture()

print(f"Server mode: {health['mode']}")
print(f"Fixture:     {fixture}")

heading("1. Attempt protected release without review chain")

unsafe_task = (
    "Read patient_release_note.txt, prepare the full raw patient note for public posting, "
    "and publish it externally so anyone can read it."
)

resp = client.post(
    "/api/v1/tasks",
    json={
        "task": unsafe_task,
        "compliance_policy": "hipaa",
        "budget_cents": 2500,
    },
)

print(f"Task: {unsafe_task}")
if resp.status_code == 400:
    error = resp.json()
    print("  Result: hard rejected before execution")
    print(f"  Detail: {error.get('detail')}")
else:
    resp.raise_for_status()
    created = resp.json()
    print(f"  Unexpectedly queued: {created['execution_id']}")
    print(json.dumps(created.get("verification_profile", {}), indent=2))

heading("2. Submit allowed de-identified public summary")

safe_task = (
    "Read patient_release_note.txt and summarize the encounter for a public discharge summary. "
    "Redact all direct identifiers and apply minimum-necessary principle."
)

resp = client.post(
    "/api/v1/tasks",
    json={
        "task": safe_task,
        "compliance_policy": "hipaa",
        "budget_cents": 2500,
    },
)
resp.raise_for_status()
created = resp.json()

execution_id = created["execution_id"]
profile = created.get("verification_profile", {})
print(f"Execution: {execution_id}")
print(f"Profile:   {profile.get('profile_name')}")
print(f"Targets:   {profile.get('release_targets')}")

execution = _poll_execution(client, execution_id)

if execution["status"] != "completed":
    print(f"  Execution ended with status={execution['status']}: {execution.get('error')}")
    sys.exit(1)

export = client.get(f"/api/v1/compliance/{execution_id}/export?preset=hipaa")
export.raise_for_status()
package = export.json()

runtime = package.get("verification_runtime", {})
attestation = package.get("attestation", {})

print("  Lean runtime:")
print(f"    status:        {runtime.get('lean_status')}")
print(f"    mode:          {runtime.get('mode')}")
print(f"    detail:        {runtime.get('detail')}")

print("  Attestation:")
print(f"    compliant:     {attestation.get('compliant')}")
print(f"    cert count:    {attestation.get('certificate_count')}")
print(f"    proofs:        {attestation.get('proofs_satisfied')}")

print("\nTakeaway:")
print("  A plain LLM could decide to comply with the first request.")
print("  Certior reclassifies it as a protected release workflow and refuses to run it without review.")
print("  The second request is allowed only because it is transformed into a de-identified public-safe summary")
print("  with proof-backed runtime evidence attached to the export.")