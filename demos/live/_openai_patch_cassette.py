"""
OpenAI-SDK-level cassette for recording/replaying LangChain (or any code that
calls the OpenAI Python SDK) runs.

LangChain's ChatOpenAI calls the model through the OpenAI SDK's
``Completions.create`` method, so this patches that method on the class — which
intercepts every LangChain LLM call without LangChain needing to know.

    record   call the model, store (request-key -> response) to JSON.
    replay   return the recorded response for the matching request; no API key.

Keyed by a hash of (model, messages, tools); identical repeated requests replay
FIFO from a per-key queue, with a sequential fallback so it stays correct even
when a multi-agent run branches.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List


def _mode() -> str:
    return os.environ.get("CERTIOR_CASSETTE", "replay").strip().lower()


def _key(model: Any, messages: Any, tools: Any) -> str:
    blob = json.dumps({"model": model, "messages": messages, "tools": tools},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class OpenAICassette:
    """Context manager that patches openai Completions.create for record/replay."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.mode = _mode()
        self._records: List[Dict[str, Any]] = []
        self._replay: Dict[str, List[dict]] = {}
        self._seq: List[dict] = []
        self._seq_i = 0
        self._orig = None
        self._cc = None

        if self.mode == "replay":
            if not self.path.exists():
                raise FileNotFoundError(
                    f"Cassette {self.path} not found - record it first with "
                    f"CERTIOR_CASSETTE=record."
                )
            for rec in json.loads(self.path.read_text()):
                self._replay.setdefault(rec["key"], []).append(rec["response"])
                self._seq.append(rec["response"])
        elif self.mode == "record":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        import openai.resources.chat.completions as cc

        self._cc = cc
        self._orig = cc.Completions.create
        cas = self

        def patched(client_self, *args, **kwargs):
            k = _key(kwargs.get("model"), kwargs.get("messages"), kwargs.get("tools"))
            if cas.mode == "record":
                resp = cas._orig(client_self, *args, **kwargs)
                cas._records.append({"key": k, "response": resp.model_dump()})
                return resp

            from openai.types.chat import ChatCompletion

            q = cas._replay.get(k)
            if q:
                data = q.pop(0)
            elif cas._seq_i < len(cas._seq):
                data = cas._seq[cas._seq_i]
                cas._seq_i += 1
            else:
                raise RuntimeError(f"openai cassette {cas.path} miss + exhausted for key {k[:8]}")
            return ChatCompletion.model_validate(data)

        cc.Completions.create = patched
        return self

    def __exit__(self, *exc):
        if self._orig is not None and self._cc is not None:
            self._cc.Completions.create = self._orig
        if self.mode == "record":
            self.path.write_text(json.dumps(self._records, indent=2, default=str))
        return False

    @property
    def recording(self) -> bool:
        return self.mode == "record"
