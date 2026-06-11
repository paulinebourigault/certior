"""
certior.adapters.langchain - LangChain integration.
====================================================

Provides a callback handler that verifies every tool call before execution.

Usage::

    from certior import Guard
    from certior.adapters.langchain import CertiorCallbackHandler

    guard = Guard(policy="hipaa")
    handler = CertiorCallbackHandler(guard)

    # Works with any chain, agent, or tool
    agent.invoke(
        {"input": "Look up patient records"},
        config={"callbacks": [handler]},
    )

    # Or globally
    from langchain.globals import set_llm_cache
    import langchain
    langchain.callbacks.append(handler)

Requires: ``pip install langchain-core``
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence
from certior.guard import Guard, CertiorBlocked


def _check_langchain():
    try:
        from langchain_core.callbacks import BaseCallbackHandler  # noqa: F401
        return True
    except ImportError:
        return False


if _check_langchain():
    from langchain_core.callbacks import BaseCallbackHandler

    class CertiorCallbackHandler(BaseCallbackHandler):
        """
        LangChain callback that verifies tool calls via Certior.

        Hooks into ``on_tool_start`` to verify before execution.
        If blocked, raises ``CertiorBlocked`` which LangChain will
        surface as a tool error to the LLM.
        """

        def __init__(
            self,
            guard: Optional[Guard] = None,
            policy: str = "default",
            block_on_violation: bool = True,
        ):
            super().__init__()
            self.guard = guard or Guard(policy=policy)
            self.block_on_violation = block_on_violation

        def on_tool_start(
            self,
            serialized: Dict[str, Any],
            input_str: str,
            **kwargs: Any,
        ) -> None:
            """Verify tool call before LangChain executes it."""
            tool_name = serialized.get("name", "unknown")

            result = self.guard.verify(
                tool=tool_name,
                content=input_str,
                params=kwargs.get("inputs", {}),
            )

            if result.blocked and self.block_on_violation:
                raise CertiorBlocked(result)

        def on_tool_end(self, output: str, **kwargs: Any) -> None:
            """Scan tool output for PII leakage."""
            result = self.guard.verify(content=output)
            if result.blocked and self.block_on_violation:
                raise CertiorBlocked(result)

else:
    # Stub when langchain not installed
    class CertiorCallbackHandler:  # type: ignore[no-redef]
        """Install langchain-core to use this adapter."""
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "langchain-core is required: pip install langchain-core"
            )
