"""
Shared helpers for Certior examples.

Handles API key discovery and provides a configured httpx client.
"""
from __future__ import annotations

import os
import sys
import httpx

DEFAULT_BASE = "http://127.0.0.1:8000"


def get_base_url() -> str:
    host = os.getenv("CERTIOR_HOST", "127.0.0.1")
    port = os.getenv("CERTIOR_PORT", "8000")
    return os.getenv("CERTIOR_BASE_URL", f"http://{host}:{port}")


def get_api_key(base_url: str | None = None) -> str:
    """
    Get a working API key.

    Priority:
      1. CERTIOR_API_KEY env var
      2. CERTIOR_DEV_API_KEY env var (set by run.sh)
      3. Auto-register a new user via the API
    """
    key = os.getenv("CERTIOR_API_KEY") or os.getenv("CERTIOR_DEV_API_KEY")
    if key:
        return key

    # Auto-register
    base = base_url or get_base_url()
    try:
        resp = httpx.post(
            f"{base}/api/v1/auth/register",
            json={"email": "example-runner@certior.local", "name": "Example Runner"},
            timeout=5.0,
        )
        if resp.status_code == 201:
            return resp.json()["api_key"]
        elif resp.status_code == 409:
            # Already registered - need to use the dev key
            pass
    except httpx.ConnectError:
        pass

    print("ERROR: Cannot obtain API key.")
    print("  1. Start the server:  ./run.sh")
    print("  2. Set CERTIOR_API_KEY or CERTIOR_DEV_API_KEY")
    sys.exit(1)


def make_client(timeout: float = 30.0) -> tuple[httpx.Client, str]:
    """Return (httpx_client, base_url) configured with auth."""
    base = get_base_url()
    key = get_api_key(base)
    client = httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {key}"},
        timeout=timeout,
    )
    return client, base


def check_server(client: httpx.Client) -> dict:
    """Check server health. Exits if unreachable."""
    try:
        resp = client.get("/health")
        resp.raise_for_status()
        return resp.json()
    except (httpx.ConnectError, httpx.HTTPError):
        print("ERROR: Certior server not reachable.")
        print("  Start it with:  ./run.sh")
        sys.exit(1)


def heading(title: str) -> None:
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")
