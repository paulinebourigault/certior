#!/usr/bin/env python3
"""Headless DAP smoke test for certior-dap."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _readline(stream) -> bytes:
    line = stream.readline()
    if not line:
        raise RuntimeError("DAP stream closed unexpectedly")
    return line


def read_message(stream) -> dict[str, Any]:
    content_length: int | None = None
    while True:
        line = _readline(stream)
        if line in (b"\r\n", b"\n"):
            break
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
    if content_length is None:
        raise RuntimeError("missing Content-Length header")
    payload = b""
    while len(payload) < content_length:
        chunk = stream.read(content_length - len(payload))
        if not chunk:
            raise RuntimeError("DAP payload stream ended early")
        payload += chunk
    return json.loads(payload.decode("utf-8"))


def send_message(stream, msg: dict[str, Any]) -> None:
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    stream.write(header + payload)
    stream.flush()


def wait_response(proc: subprocess.Popen[bytes], request_seq: int) -> dict[str, Any]:
    while True:
        msg = read_message(proc.stdout)
        if msg.get("type") == "response" and msg.get("request_seq") == request_seq:
            return msg


def wait_event(proc: subprocess.Popen[bytes], event_name: str) -> dict[str, Any]:
    while True:
        msg = read_message(proc.stdout)
        if msg.get("type") == "event" and msg.get("event") == event_name:
            return msg


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dap", required=True, help="Path to certior-dap binary")
    parser.add_argument("--planinfo", required=True, help="Path to PlanInfo JSON")
    args = parser.parse_args()

    dap_path = Path(args.dap)
    plan_path = Path(args.planinfo)
    if not dap_path.is_file():
        raise FileNotFoundError(f"DAP binary missing: {dap_path}")
    if not plan_path.is_file():
        raise FileNotFoundError(f"PlanInfo missing: {plan_path}")

    plan_info = json.loads(plan_path.read_text(encoding="utf-8"))
    proc = subprocess.Popen(
        [str(dap_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    try:
        send_message(
            proc.stdin,
            {
                "seq": 1,
                "type": "request",
                "command": "initialize",
                "arguments": {},
            },
        )
        init_resp = wait_response(proc, 1)
        if not init_resp.get("success"):
            raise RuntimeError(f"initialize failed: {init_resp}")
        wait_event(proc, "initialized")

        send_message(
            proc.stdin,
            {
                "seq": 2,
                "type": "request",
                "command": "launch",
                "arguments": {
                    "planInfo": plan_info,
                    "source": str(plan_path),
                    "stopOnEntry": True,
                },
            },
        )
        launch_resp = wait_response(proc, 2)
        if not launch_resp.get("success"):
            raise RuntimeError(f"launch failed: {launch_resp}")

        # Launch should stop or terminate immediately depending on plan.
        try:
            wait_event(proc, "stopped")
        except Exception:
            wait_event(proc, "terminated")

        send_message(
            proc.stdin,
            {
                "seq": 3,
                "type": "request",
                "command": "disconnect",
                "arguments": {},
            },
        )
        disc_resp = wait_response(proc, 3)
        if not disc_resp.get("success"):
            raise RuntimeError(f"disconnect failed: {disc_resp}")

        return 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
            proc.wait(timeout=2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"DAP smoke test failed: {exc}", file=sys.stderr)
        raise
