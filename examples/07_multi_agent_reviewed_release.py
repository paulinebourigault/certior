#!/usr/bin/env python3
"""
Example 7: Multi-Agent Reviewed Release
=======================================

Shows the workflow Certior can enforce that a plain LLM agent cannot:

  - Stage 1 reviewer execution produces a compliant internal review artifact.
  - Stage 2 release execution is rejected without that upstream reviewer ID.
  - Stage 2 succeeds only when the upstream reviewer execution ID is supplied.

This is a real API example using Certior's adaptive verification profiles,
temporal validation, and proof-backed compliance exports.

Run:
    CERTIOR_ENV=production ./run.sh   # separate terminal
    python examples/07_multi_agent_reviewed_release.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from _helpers import make_client, check_server, heading  # noqa: E402


PUBLIC_ARTIFACT = (
    "A patient received hospital care, improved, and was discharged with routine follow-up instructions."
)

REVIEW_TEXT = (
    "Approved public artifact candidate:\n"
    f"{PUBLIC_ARTIFACT}"
)


def poll_execution(client, execution_id: str, timeout: float = 180.0) -> dict:
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
        if status in {"completed", "failed", "blocked", "cancelled"}:
            return execution
        time.sleep(1.0)
    raise TimeoutError(f"Execution {execution_id} did not finish in time")


def export_package(client, execution_id: str, preset: str = "hipaa") -> dict:
    resp = client.get(f"/api/v1/compliance/{execution_id}/export?preset={preset}")
    resp.raise_for_status()
    return resp.json()


def prover_counts(package: dict) -> dict[str, int]:
    counts = Counter()
    for cert in package.get("certificates", []):
        if isinstance(cert, dict):
            counts[str(cert.get("prover", "unknown"))] += 1
        else:
            counts["unknown"] += 1
    return dict(sorted(counts.items()))


heading("Example 7: Multi-Agent Reviewed Release")
client, _ = make_client(timeout=180.0)
health = check_server(client)

print(f"Server mode: {health['mode']}")

heading("1. Reviewer stage: internal-only approval artifact")

review_task = (
    "Review the following de-identified public artifact candidate for residual PHI, "
    "minimum-necessary compliance, and public-release readiness. "
    "The candidate is intended to omit diagnosis details, procedures, medication names, dates, ages, "
    "locations, provider names, record numbers, and other direct or indirect identifiers. "
    "If it is safe, return exactly the approved public artifact text and nothing else. "
    "If unsafe, return NO-GO with the blocking reason.\n\n"
    f"{REVIEW_TEXT}"
)

review_resp = client.post(
    "/api/v1/tasks",
    json={
        "task": review_task,
        "compliance_policy": "hipaa",
        "budget_cents": 2500,
        "verification_profile": {
            "task_class": "privacy_review",
            "stage_role": "reviewer",
            "stage_id": "privacy-review",
        },
    },
)
review_resp.raise_for_status()
review_created = review_resp.json()
review_execution_id = review_created["execution_id"]

print(f"Reviewer execution: {review_execution_id}")
print(f"Reviewer profile:   {review_created['verification_profile']['profile_name']}")

review_execution = poll_execution(client, review_execution_id)
review_package = export_package(client, review_execution_id)

print("Reviewer export:")
print(f"  status:           {review_execution['status']}")
print(f"  compliant:        {review_package['attestation']['compliant']}")
print(f"  proofs:           {review_package['attestation']['proofs_satisfied']}")
print(f"  cert provers:     {prover_counts(review_package)}")
print(f"  lean runtime:     {review_package['verification_runtime']['lean_status']} / {review_package['verification_runtime']['mode']}")
approved_artifact = review_package['execution_summary'].get('approved_artifact', {})
print(f"  approved hash:    {approved_artifact.get('sha256')}")
print(f"  approved:         {approved_artifact.get('approved_for_release')}")
print(f"  approved text:    {approved_artifact.get('text', '')[:120]}")
print(f"  public preview:   {review_package['execution_summary'].get('output_preview', '')[:120]}")

heading("2. Release stage without reviewer dependency: hard reject")

release_task = (
    "Publish the reviewed public artifact to the public website. "
    "Only the approved de-identified content may be released, and the release output must match the reviewed artifact exactly.\n\n"
    f"Approved public artifact candidate:\n{PUBLIC_ARTIFACT}"
)

bad_release = client.post(
    "/api/v1/tasks",
    json={
        "task": release_task,
        "compliance_policy": "hipaa",
        "budget_cents": 2500,
        "verification_profile": {
            "task_class": "protected_release",
            "stage_role": "release",
            "stage_id": "public-release",
        },
    },
)

print(f"Release without upstream status: {bad_release.status_code}")
print(f"  detail: {bad_release.json().get('detail')}")

heading("3. Release stage with reviewer dependency: allowed")

good_release = client.post(
    "/api/v1/tasks",
    json={
        "task": release_task,
        "compliance_policy": "hipaa",
        "budget_cents": 2500,
        "verification_profile": {
            "task_class": "protected_release",
            "stage_role": "release",
            "stage_id": "public-release",
            "upstream_execution_ids": [review_execution_id],
        },
    },
)
good_release.raise_for_status()
release_created = good_release.json()
release_execution_id = release_created["execution_id"]

print(f"Release execution:  {release_execution_id}")
print(f"Release profile:    {release_created['verification_profile']['profile_name']}")

release_execution = poll_execution(client, release_execution_id)
release_package = export_package(client, release_execution_id)

print("Release export:")
print(f"  status:           {release_execution['status']}")
print(f"  compliant:        {release_package['attestation']['compliant']}")
print(f"  proofs:           {release_package['attestation']['proofs_satisfied']}")
print(f"  cert provers:     {prover_counts(release_package)}")
print(f"  lean runtime:     {release_package['verification_runtime']['lean_status']} / {release_package['verification_runtime']['mode']}")
binding = release_package['execution_summary'].get('release_binding_summary', {})
print(f"  bound hash:       {binding.get('artifact_hash')}")
print(f"  rebound:          {binding.get('rebound')}")
print(f"  bound upstream:   {binding.get('upstream_execution_id')}")
print(f"  output preview:   {release_package['execution_summary'].get('output_preview', '')[:120]}")

heading("Why this is different from LLM-only safety")
print("Single-agent example:")
print("  Example 06 shows a lone agent being blocked from protected public disclosure and allowed only on a de-identified summary path.")
print("Multi-agent example:")
print("  This example shows temporal enforcement across stages. The release agent is not trusted just because it says 'I reviewed it'.")
print("  Certior requires a real upstream reviewer execution ID, checks that the reviewer stage completed compliantly,")
print("  and binds the release-stage output to the upstream reviewed artifact hash before allowing disclosure.")