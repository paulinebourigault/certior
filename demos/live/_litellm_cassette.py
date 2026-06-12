"""
litellm-level cassette for recording/replaying CrewAI (or any litellm) runs.

CrewAI calls the model through ``litellm.completion`` internally, so the
single-agent OpenAI-client cassette does not apply. This patches
``litellm.completion`` instead:

    record   call the model, store (request-key -> response) to JSON.
    replay   return the recorded response for the matching request; no API key.

Requests are keyed by a hash of (model, messages, tools) rather than call order,
so replay stays correct even when delegation makes the call graph branch.
Identical repeated requests are replayed FIFO from a per-key queue.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List


def _mode() -> str:
    return os.environ.get("CERTIOR_CASSETTE", "replay").strip().lower()


def _key(model: str, messages: Any, tools: Any) -> str:
    blob = json.dumps({"model": model, "messages": messages, "tools": tools},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class LiteLLMCassette:
    """Context manager that patches litellm.completion for record/replay."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.mode = _mode()
        self._records: List[Dict[str, Any]] = []
        self._replay: Dict[str, List[dict]] = {}
        self._seq: List[dict] = []
        self._seq_i = 0
        self._orig = None

        if self.mode == "replay":
            if not self.path.exists():
                raise FileNotFoundError(
                    f"Cassette {self.path} not found - record it first with "
                    f"CERTIOR_CASSETTE=record."
                )
            data = json.loads(self.path.read_text())
            for rec in data:
                self._replay.setdefault(rec["key"], []).append(rec["response"])
                self._seq.append(rec["response"])
        elif self.mode == "record":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        import litellm

        self._orig = litellm.completion

        def patched(*args, **kwargs):
            model = kwargs.get("model") or (args[0] if args else "")
            messages = kwargs.get("messages")
            tools = kwargs.get("tools")
            k = _key(model, messages, tools)

            if self.mode == "record":
                resp = self._orig(*args, **kwargs)
                self._records.append({"key": k, "response": _dump(resp)})
                return resp

            # replay
            from litellm import ModelResponse

            q = self._replay.get(k)
            if q:
                data = q.pop(0)
            elif self._seq_i < len(self._seq):
                data = self._seq[self._seq_i]
                self._seq_i += 1
            else:
                raise RuntimeError(f"litellm cassette {self.path} miss + exhausted for key {k[:8]}")
            return ModelResponse(**data)

        litellm.completion = patched
        # CrewAI may hold a bound reference; patch the common entry points.
        try:
            import litellm.main  # noqa
            litellm.main.completion = patched
        except Exception:
            pass
        return self

    def __exit__(self, *exc):
        import litellm
        if self._orig is not None:
            litellm.completion = patched_restore = self._orig
        if self.mode == "record":
            self.path.write_text(json.dumps(self._records, indent=2, default=str))
        return False

    @property
    def recording(self) -> bool:
        return self.mode == "record"


def _dump(resp: Any) -> dict:
    for attr in ("model_dump", "dict"):
        fn = getattr(resp, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                pass
    return json.loads(resp.json())
