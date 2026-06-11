#!/usr/bin/env python3
"""Production-style Certior API use case: single-agent + multi-agent flow."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


def _req(method: str, url: str, body: dict[str, Any] | None = None, api_key: str | None = None) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return resp.status, payload
    except urllib.error.HTTPError as e:
        payload = json.loads(e.read().decode("utf-8"))
        return e.code, payload


def _poll_execution(base_url: str, api_key: str, execution_id: str, timeout_s: int = 90) -> dict[str, Any]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status, payload = _req("GET", f"{base_url}/api/v1/executions/{execution_id}", api_key=api_key)
        if status != 200:
            raise RuntimeError(f"execution fetch failed ({status}): {payload}")
        state = payload.get("status", "unknown")
        print(f"  execution {execution_id[:8]} status={state}")
        if state in {"completed", "failed", "blocked", "cancelled"}:
            return payload
        time.sleep(2)
    raise TimeoutError(f"execution {execution_id} did not finish within timeout")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--api-key", default="")
    p.add_argument("--model", default="gpt-4o")
    args = p.parse_args()

    base = args.base_url.rstrip("/")
    api_key = args.api_key.strip()

    if not api_key:
        email = f"prod-demo-{uuid.uuid4().hex[:8]}@local"
        status, reg = _req("POST", f"{base}/api/v1/auth/register", {
            "email": email,
            "name": "Production Demo",
            "role": "admin",
        })
        if status != 201:
            raise RuntimeError(f"register failed ({status}): {reg}")
        api_key = reg["api_key"]
        print(f"[auth] registered demo user: {email}")

    status, switched = _req("POST", f"{base}/api/v1/settings/provider", {
        "provider": "openai",
        "model": args.model,
    }, api_key=api_key)
    if status != 200:
        raise RuntimeError(f"provider switch failed ({status}): {switched}")
    print(f"[provider] {switched.get('message', 'switched')}")

    print("\n[1/3] Single-agent HIPAA task")
    status, created = _req("POST", f"{base}/api/v1/tasks", {
        "task": (
            "As a healthcare intake agent, produce a PHI-safe summary template in 5 bullets. "
            "Do not include patient identifiers."
        ),
        "compliance_policy": "hipaa",
        "budget_cents": 1500,
        "provider": "openai",
        "model": args.model,
    }, api_key=api_key)
    if status != 201:
        raise RuntimeError(f"task create failed ({status}): {created}")
    ex1 = created["execution_id"]
    _poll_execution(base, api_key, ex1)

    print("\n[2/3] Policy-ceiling enforcement check (expected 403)")
    status, denied = _req("POST", f"{base}/api/v1/tasks", {
        "task": "Attempt external unrestricted data fetch.",
        "compliance_policy": "hipaa",
        "budget_cents": 500,
        "permissions": ["network:http:read", "secrets:read"],
        "provider": "openai",
        "model": args.model,
    }, api_key=api_key)
    if status == 403:
        print(f"  denied as expected: {denied.get('detail', {}).get('message', 'permission denied')}")
    else:
        print(f"  unexpected status={status}: {denied}")

    print("\n[3/3] Multi-agent style split: intake + compliance reviewer")
    tasks = [
        ("hipaa", "Agent A (intake): classify output labels and draft a minimum-necessary note."),
        ("legal_privilege", "Agent B (reviewer): verify no privileged leakage and return go/no-go."),
    ]
    execution_ids: list[str] = []
    for policy, prompt in tasks:
        status, created = _req("POST", f"{base}/api/v1/tasks", {
            "task": prompt,
            "compliance_policy": policy,
            "budget_cents": 1200,
            "provider": "openai",
            "model": args.model,
        }, api_key=api_key)
        if status != 201:
            raise RuntimeError(f"multi-agent task failed ({status}): {created}")
        execution_ids.append(created["execution_id"])
        print(f"  queued {policy}: {created['execution_id']}")

    for ex in execution_ids:
        final = _poll_execution(base, api_key, ex)
        print(f"  final {ex[:8]}: status={final.get('status')} provider={final.get('llm_provider')} model={final.get('llm_model')}")

    print("\nDone. Inspect results:")
    print(f"  Studio: {base}/api/v1/use-cases/production/studio")
    for ex in [ex1] + execution_ids:
        print(f"  {base}/api/v1/executions/{ex}")
        print(f"  {base}/api/v1/compliance/{ex}/export")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
