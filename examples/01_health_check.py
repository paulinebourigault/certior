#!/usr/bin/env python3
"""
Example 1: Health Check & API Discovery
========================================

The simplest Certior interaction.  Verifies the server is running,
shows the operating mode (agent vs legacy), and lists available
endpoints.

Run:
    python examples/01_health_check.py

Prerequisites:
    ./run.sh   (in another terminal)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from _helpers import make_client, heading

heading("Example 1: Health Check & API Discovery")

client, base = make_client()

# ── Health check ──────────────────────────────────────────────────────
print("Checking server health...")
resp = client.get("/health")
resp.raise_for_status()
health = resp.json()

print(f"  Status:          {health['status']}")
print(f"  Version:         {health['version']}")
print(f"  Mode:            {health['mode']}")
print(f"  LLM configured:  {health['llm_configured']}")
print(f"  Available tools:  {health['tools']}")

# ── Authenticated user ────────────────────────────────────────────────
print("\nChecking authentication...")
resp = client.get("/api/v1/auth/me")
resp.raise_for_status()
user = resp.json()
print(f"  User:  {user['name']} ({user['email']})")
print(f"  Role:  {user['role']}")

# ── Compliance presets ────────────────────────────────────────────────
print("\nAvailable compliance presets:")
resp = client.get("/api/v1/compliance/presets")
resp.raise_for_status()
for preset in resp.json():
    proofs = ", ".join(preset["required_proofs"][:3])
    if len(preset["required_proofs"]) > 3:
        proofs += f" (+{len(preset['required_proofs']) - 3} more)"
    print(f"  {preset['key']:10s}  {preset['name']:20s}  retention={preset['retention_days']}d  proofs=[{proofs}]")

# ── OpenAPI docs ──────────────────────────────────────────────────────
print(f"\nInteractive API docs:  {base}/docs")
print(f"OpenAPI JSON:          {base}/openapi.json")

heading("Done - server is healthy and authenticated!")
