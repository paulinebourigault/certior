"""
Cassette recorder/replay for LLM agent demos.

Records a model call once and replays it deterministically, so a demo can run
without network access or an API key after recording.

Modes (env CERTIOR_CASSETTE=record|replay, default replay):

    record   call the OpenAI API and append each (request, response) pair to
             the cassette JSON.
    replay   return recorded responses in order; no network, no API key.

Usage in a scenario::

    from _recorder import Cassette
    cas = Cassette("cassettes/exfiltration.json")
    resp = cas.chat_create(messages=[...], tools=[...], model="gpt-4o")

The recorded response is reconstructed into a ``ChatCompletion`` object, so
downstream code (``resp.choices[0].message.tool_calls`` etc.) is identical on
the record and replay paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List


def _mode() -> str:
    return os.environ.get("CERTIOR_CASSETTE", "replay").strip().lower()


class Cassette:
    """Records/replays OpenAI chat-completion calls to a JSON file."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.mode = _mode()
        self._entries: List[Dict[str, Any]] = []
        self._cursor = 0
        self._client = None

        if self.mode == "replay":
            if not self.path.exists():
                raise FileNotFoundError(
                    f"Cassette {self.path} not found. Record it first with "
                    f"CERTIOR_CASSETTE=record (needs OPENAI_API_KEY)."
                )
            self._entries = json.loads(self.path.read_text())
        elif self.mode == "record":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            from openai import OpenAI  # lazy: only needed when recording

            self._client = OpenAI()  # reads OPENAI_API_KEY from env
        else:
            raise ValueError(f"CERTIOR_CASSETTE must be record|replay, got {self.mode!r}")

    # ── the one call the scenarios use ───────────────────────────────
    def chat_create(self, **kwargs: Any):
        """Drop-in for ``client.chat.completions.create(**kwargs)``."""
        if self.mode == "record":
            assert self._client is not None  # set in __init__ for record mode
            resp = self._client.chat.completions.create(**kwargs)
            self._entries.append({
                "request": _sanitize_request(kwargs),
                "response": resp.model_dump(),
            })
            return resp

        # replay - reconstruct a real ChatCompletion from the recorded dict
        from openai.types.chat import ChatCompletion

        if self._cursor >= len(self._entries):
            raise RuntimeError(
                f"Cassette {self.path} exhausted at call {self._cursor}; "
                f"re-record - the agent made more calls than were captured."
            )
        entry = self._entries[self._cursor]
        self._cursor += 1
        return ChatCompletion.model_validate(entry["response"])

    def save(self) -> None:
        """Persist recorded entries (no-op on replay)."""
        if self.mode == "record":
            self.path.write_text(json.dumps(self._entries, indent=2))

    @property
    def recording(self) -> bool:
        return self.mode == "record"


def _sanitize_request(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the request human-readable in the cassette; drop nothing sensitive
    (the API key lives on the client, never in kwargs)."""
    out = dict(kwargs)
    return out
