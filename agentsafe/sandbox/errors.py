"""
Sandbox-specific exceptions.

All exceptions are subclasses of ``SandboxError`` so callers can catch
the entire family with a single handler.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class SandboxError(Exception):
    """Base class for all sandbox errors."""


class SandboxSetupError(SandboxError):
    """Raised when sandbox containment layers fail to initialise.

    This is a *configuration* error - the user code has not run yet.
    If any mandatory containment layer cannot be established, execution
    must not proceed.
    """

    def __init__(
        self,
        message: str,
        *,
        layer: str = "unknown",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.layer = layer
        self.details = details or {}
        super().__init__(f"[{layer}] {message}")


class SandboxViolationError(SandboxError):
    """Raised when the sandboxed process attempted a forbidden operation.

    The violation was *blocked* - the system is safe - but the caller
    should be informed that the user code tried something suspicious.
    """

    def __init__(
        self,
        message: str,
        *,
        syscall: Optional[str] = None,
        signal: Optional[int] = None,
    ) -> None:
        self.syscall = syscall
        self.signal = signal
        super().__init__(message)


class SandboxTimeoutError(SandboxError):
    """Raised when the sandboxed process exceeded its CPU/wall-clock budget."""

    def __init__(
        self,
        timeout_seconds: float,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Sandbox execution timed out after {timeout_seconds:.1f}s"
        )


class SandboxResourceError(SandboxError):
    """Raised when the sandboxed process exceeded a resource limit (OOM, etc.)."""

    def __init__(
        self,
        resource: str,
        limit: Any,
    ) -> None:
        self.resource = resource
        self.limit = limit
        super().__init__(
            f"Sandbox resource limit exceeded: {resource} (limit={limit})"
        )


class FilesystemIsolationError(SandboxSetupError):
    """Raised when filesystem isolation cannot be established.

    This is a setup error - the user code has not run yet.  The caller
    can decide to retry without filesystem isolation (graceful degradation)
    or abort.
    """

    def __init__(
        self,
        message: str,
        *,
        operation: str = "unknown",
        errno: Optional[int] = None,
    ) -> None:
        self.operation = operation
        self.errno = errno
        super().__init__(
            f"{message} (op={operation}, errno={errno})",
            layer="filesystem",
        )


class NetworkIsolationError(SandboxSetupError):
    """Raised when network isolation cannot be established.

    This is a setup error - the user code has not run yet.  The caller
    can decide to retry with HOST_NETWORK mode (graceful degradation)
    or abort.
    """

    def __init__(
        self,
        message: str,
        *,
        operation: str = "unknown",
    ) -> None:
        self.operation = operation
        super().__init__(
            f"{message} (op={operation})",
            layer="network",
        )


class NsjailNotFoundError(SandboxSetupError):
    """Raised when nsjail is required but not installed."""

    def __init__(self) -> None:
        super().__init__(
            "nsjail binary not found on PATH. "
            "Install it or use policy.require_nsjail=False to fall back "
            "to seccomp/namespace isolation.",
            layer="nsjail",
        )
