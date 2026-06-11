"""
Web fetch tool - retrieves web content with safety guarantees.

Enforces:
  - URL allowlist/blocklist patterns
  - Response size limits
  - Timeouts
  - Read-only (GET only)

Constraints are loaded from VERIFICATION.json at startup (A9 FIX).
If no spec constraints are provided, hardcoded defaults are used.

Requires capability: ``network:http:read``
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, List, Optional, TYPE_CHECKING

import httpx

from .base import BaseTool, ToolParameter, ToolResult

if TYPE_CHECKING:
    from .constraint_loader import WebFetchConstraints

# ── Hardcoded fallback defaults ──────────────────────────────────────
# These are used ONLY when no VERIFICATION.json constraints are loaded.
# When constraints are loaded (A9), they take priority.
_FALLBACK_TIMEOUT = 20
_FALLBACK_MAX_BODY_BYTES = 512_000  # ~500 KB text
_FALLBACK_BLOCKLIST = [
    re.compile(r".*\.onion$", re.IGNORECASE),
    re.compile(r".*\.mil$", re.IGNORECASE),
]
_FALLBACK_ALLOWLIST = [
    re.compile(r"^https://.*"),
    re.compile(r"^http://localhost.*"),
]


class WebFetchTool(BaseTool):
    """
    Fetch the text content of a web page.

    Returns the first ~500 KB of the response body as plain text
    (HTML tags are **not** stripped - the LLM handles that).

    A9 FIX: Accepts optional ``WebFetchConstraints`` loaded from
    ``skills/web_browsing/VERIFICATION.json``.  When provided, the
    spec-derived URL patterns, timeout, and size limits are used
    instead of the hardcoded fallbacks - ensuring Z3 proofs and
    runtime enforcement are about the **same constraints**.
    """

    def __init__(
        self,
        constraints: Optional[WebFetchConstraints] = None,
        network_policy: Any = None,
    ) -> None:
        self._constraints = constraints
        self._network_policy = network_policy
        self._fetcher = None
        # Pre-resolve effective values so execute() is fast
        if constraints is not None:
            self._allowlist = list(constraints.allowlist_patterns)
            self._blocklist = list(constraints.blocklist_patterns)
            self._timeout = constraints.timeout_seconds
            self._max_body = constraints.max_body_size_bytes
            self._constraints_source = "VERIFICATION.json"
        else:
            self._allowlist = _FALLBACK_ALLOWLIST
            self._blocklist = _FALLBACK_BLOCKLIST
            self._timeout = _FALLBACK_TIMEOUT
            self._max_body = _FALLBACK_MAX_BODY_BYTES
            self._constraints_source = "hardcoded_fallback"

        if network_policy is not None:
            from agentsafe.sandbox.net_fetch import SafeFetcher
            self._fetcher = SafeFetcher(network_policy)

    @property
    def constraints_source(self) -> str:
        """Where the active constraints came from (for audit trail)."""
        return self._constraints_source

    @property
    def name(self) -> str:
        return "web_fetch"

    @property
    def description(self) -> str:
        return (
            "Fetch the text content of a public web page given its URL. "
            "Returns the raw page content (HTML/text). Only HTTPS URLs are "
            "allowed. Use this to retrieve information from the web."
        )

    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="url",
                type="string",
                description="The full URL to fetch (must start with https://).",
            ),
        ]

    @property
    def required_capabilities(self) -> List[str]:
        return ["network:http:read"]

    @property
    def estimated_cost_cents(self) -> int:
        return 2

    @property
    def output_labels(self) -> List[str]:
        return ["internal", "cached"]

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        url: str = kwargs.get("url", "")
        if not url:
            return ToolResult(
                tool_use_id=tool_use_id,
                output="Error: 'url' parameter is required.",
                is_error=True,
            )

        # Validate URL against spec (or fallback) patterns
        violation = self._check_url(url)
        if violation:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: URL blocked - {violation}",
                is_error=True,
                metadata={"constraints_source": self._constraints_source},
            )

        try:
            if self._fetcher is not None:
                fetch_result = await asyncio.to_thread(self._fetcher.fetch, url)
                if not fetch_result.success:
                    return ToolResult(
                        tool_use_id=tool_use_id,
                        output=f"Error: {fetch_result.error}",
                        is_error=True,
                        metadata={
                            "constraints_source": self._constraints_source,
                            "network_policy": self._fetcher.policy.mode.value,
                            "network_connection": (
                                fetch_result.connection_record.to_dict()
                                if fetch_result.connection_record is not None else None
                            ),
                            "network_audit": self._fetcher.export_audit(),
                            "error_type": fetch_result.error_type,
                        },
                    )

                content_type = fetch_result.content_type or ""
                if "text" not in content_type and "json" not in content_type and "xml" not in content_type:
                    return ToolResult(
                        tool_use_id=tool_use_id,
                        output=f"Error: Non-text content type ({content_type}). Only text content is supported.",
                        is_error=True,
                        metadata={
                            "constraints_source": self._constraints_source,
                            "network_policy": self._fetcher.policy.mode.value,
                            "network_connection": (
                                fetch_result.connection_record.to_dict()
                                if fetch_result.connection_record is not None else None
                            ),
                            "network_audit": self._fetcher.export_audit(),
                        },
                    )

                body_text = fetch_result.body_text[:self._max_body]
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=body_text,
                    metadata={
                        "status_code": fetch_result.status_code,
                        "content_type": content_type,
                        "content_length": fetch_result.content_length,
                        "truncated": fetch_result.truncated or len(fetch_result.body_text) > self._max_body,
                        "constraints_source": self._constraints_source,
                        "network_policy": self._fetcher.policy.mode.value,
                        "network_connection": (
                            fetch_result.connection_record.to_dict()
                            if fetch_result.connection_record is not None else None
                        ),
                        "network_audit": self._fetcher.export_audit(),
                    },
                )

            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                headers={"User-Agent": "Certior/1.0 (VerifiedAgent)"},
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()

                content_type = resp.headers.get("content-type", "")
                if "text" not in content_type and "json" not in content_type and "xml" not in content_type:
                    return ToolResult(
                        tool_use_id=tool_use_id,
                        output=f"Error: Non-text content type ({content_type}). Only text content is supported.",
                        is_error=True,
                    )

                body = resp.text[:self._max_body]
                meta = {
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "content_length": len(resp.text),
                    "truncated": len(resp.text) > self._max_body,
                    "constraints_source": self._constraints_source,
                }
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=body,
                    metadata=meta,
                )

        except httpx.TimeoutException:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: Request timed out after {self._timeout}s.",
                is_error=True,
            )
        except httpx.HTTPStatusError as exc:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: HTTP {exc.response.status_code} - {exc.response.reason_phrase}",
                is_error=True,
            )
        except Exception as exc:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: {type(exc).__name__}: {exc}",
                is_error=True,
            )

    def _check_url(self, url: str) -> str:
        """Return an error message if the URL is disallowed, else empty string."""
        if not any(p.match(url) for p in self._allowlist):
            return "URL does not match allowlist (HTTPS required)."
        if any(p.match(url) for p in self._blocklist):
            return "URL matches blocklist."
        return ""
