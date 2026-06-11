"""
Phase B5: Dafny-Verified Workspace Confinement - Python Runtime Bridge.

Mirrors ``dafny/tools/path_safety.dfy`` which formally proves 14 safety
properties (P34-P47) about file-tool path safety.

**Why this matters:** workspace confinement is the #1 security property for
file tools.  An agent that escapes the workspace sandbox can read secrets
(``/etc/shadow``, ``~/.ssh/id_rsa``), overwrite configs, or exfiltrate data.
The Dafny proof guarantees that the filtering logic is correct; this Python
bridge enforces the *same* predicates at runtime with full audit logging.

Properties proven in Dafny and enforced here:

  P34  WORKSPACE CONFINEMENT
       A file operation is allowed ONLY IF the resolved path stays under
       the workspace root.  Established via P35-P37 + P41.

  P35  TRAVERSAL REJECTION
       Any path containing ".." is rejected unconditionally.

  P36  ABSOLUTE PATH REJECTION
       Any path starting with "/" is rejected.

  P37  HOME ESCAPE REJECTION
       Any path starting with "~" is rejected.

  P38  EXTENSION ALLOWLIST ENFORCEMENT
       If allowlist is non-empty, only extensions in the set are accepted.

  P39  EXTENSION BLOCKLIST ENFORCEMENT
       Extensions in the blocklist are always rejected.
       Blocklist takes precedence over allowlist.

  P40  SIZE LIMIT ENFORCEMENT
       file_size > max_size  ⟹  rejected.

  P41  PATH RESOLUTION SOUNDNESS
       If a path passes all syntactic checks (P35-P37), it cannot
       escape the workspace.  Conversely, any escaping path must
       fail at least one syntactic check.

  P42  CONFINEMENT MONOTONICITY
       Adding blocked extensions can only reduce accepted paths.

  P43  AUDIT COMPLETENESS
       Every check_path call appends exactly one PathAuditEntry.

  P44  INVARIANT PRESERVATION
       Valid() holds at every method boundary.

  P45  CONFIG IMMUTABILITY
       PathSafetyConfig is a frozen dataclass - workspace root,
       extension lists, and size limits never change.

  P46  DECISION DETERMINISM
       Pure function - same (path, ext, size, config) → same decision.

  P47  COMPONENT SAFETY COMPOSABILITY
       Allow requires ALL individual checks to pass.
       Failure of any single check produces Deny.

Usage::

    from agentsafe.tools.path_safety_verified import (
        PathSafetyChecker,
        PathSafetyConfig,
        create_path_checker_from_spec,
        create_file_operations_checker,
    )

    # From VERIFICATION.json
    checker = create_file_operations_checker(skills_dir="skills")

    # Manual config
    cfg = PathSafetyConfig(
        workspace_root="/tmp/ws",
        allowed_extensions=frozenset({".txt", ".csv", ".json"}),
        blocked_extensions=frozenset({".env", ".key", ".pem"}),
        max_file_size=10_000_000,
    )
    checker = PathSafetyChecker(cfg)

    d = checker.check_path("report.txt", 500, "write")
    assert d.is_allow

    d = checker.check_path("../../etc/passwd", 100, "read")
    assert d.is_deny
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
    check_invariant,
)

__all__ = [
    "PathDecision",
    "PathSafetyConfig",
    "PathAuditEntry",
    "PathSafetyChecker",
    "check_path_safety",
    "has_traversal",
    "is_absolute",
    "is_home_escape",
    "is_syntactically_clean",
    "extension_allowed",
    "extension_blocked",
    "extension_safe",
    "size_within_limit",
    "get_extension",
    "create_path_checker_from_spec",
    "create_file_operations_checker",
]


# =============================================================================
# PathDecision - verdict for path safety checks (mirrors Dafny datatype)
# =============================================================================

@dataclass(frozen=True)
class PathDecision:
    """
    Verdict from a path safety check.

    Mirrors ``datatype PathDecision = Allow | Deny(reason)`` in Dafny.

    Frozen: immutable once created.
    """

    allowed: bool
    reason: str = ""

    @classmethod
    def allow(cls) -> PathDecision:
        """Factory for Allow verdict."""
        return cls(allowed=True, reason="")

    @classmethod
    def deny(cls, reason: str) -> PathDecision:
        """Factory for Deny verdict."""
        return cls(allowed=False, reason=reason)

    @property
    def is_allow(self) -> bool:
        return self.allowed

    @property
    def is_deny(self) -> bool:
        return not self.allowed

    def __str__(self) -> str:
        if self.allowed:
            return "Allow"
        return f"Deny({self.reason})"


# =============================================================================
# PathAuditEntry - immutable record of a path safety check (P43)
# =============================================================================

@dataclass(frozen=True)
class PathAuditEntry:
    """
    Single audit record for a path safety check.

    Mirrors ``datatype PathAuditEntry`` in Dafny.
    Every ``check_path`` appends exactly one of these (P43).
    """

    path: str
    decision: PathDecision
    operation: str       # "read" or "write"
    file_size: int
    extension: str
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# PathSafetyConfig - immutable configuration (P45)
# =============================================================================

@dataclass(frozen=True)
class PathSafetyConfig:
    """
    Workspace confinement configuration.

    Mirrors ``datatype PathSafetyConfig`` in Dafny.

    Frozen: all fields immutable after construction (P45).

    Args:
        workspace_root: Absolute path to workspace directory.
        allowed_extensions: If non-empty, only these extensions are accepted (P38).
                            Empty frozenset means "allow all extensions".
        blocked_extensions: Always rejected, even if in allowlist (P39).
        max_file_size: Maximum file size in bytes (P40). Must be > 0.
    """

    workspace_root: str
    allowed_extensions: FrozenSet[str] = frozenset()
    blocked_extensions: FrozenSet[str] = frozenset()
    max_file_size: int = 10_000_000  # 10 MB default

    def __post_init__(self) -> None:
        if self.max_file_size <= 0:
            raise ValueError(
                f"max_file_size must be > 0, got {self.max_file_size}"
            )
        # Normalise extensions to lowercase with leading dot
        object.__setattr__(
            self,
            "allowed_extensions",
            frozenset(_normalise_ext(e) for e in self.allowed_extensions),
        )
        object.__setattr__(
            self,
            "blocked_extensions",
            frozenset(_normalise_ext(e) for e in self.blocked_extensions),
        )

    @classmethod
    def from_verification_json(cls, spec: Dict[str, Any]) -> PathSafetyConfig:
        """
        Build config from a parsed VERIFICATION.json specification.

        Expected structure (file_operations/VERIFICATION.json)::

            {
              "verification_requirements": {
                "resource_constraints": {
                  "max_file_size_bytes": 10000000
                },
                "safety_constraints": {
                  "allowed_extensions": [".txt", ".csv", ...],
                  "path_blocklist_patterns": [".*\\\\.env$", ...]
                }
              }
            }
        """
        vr = spec.get("verification_requirements", {})
        sc = vr.get("safety_constraints", {})
        rc = vr.get("resource_constraints", {})

        allowed = frozenset(sc.get("allowed_extensions", []))

        # Derive blocked extensions from path_blocklist_patterns
        # e.g. ".*\\.env$" → ".env"
        blocked: List[str] = []
        for pattern_str in sc.get("path_blocklist_patterns", []):
            ext = _extension_from_blocklist_pattern(pattern_str)
            if ext:
                blocked.append(ext)

        max_size = rc.get("max_file_size_bytes", 10_000_000)

        return cls(
            workspace_root="",  # Set at runtime by the checker
            allowed_extensions=frozenset(allowed),
            blocked_extensions=frozenset(blocked),
            max_file_size=max(1, max_size),
        )


def _normalise_ext(ext: str) -> str:
    """Normalise an extension to lowercase with leading dot."""
    ext = ext.strip().lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    return ext


def _extension_from_blocklist_pattern(pattern: str) -> Optional[str]:
    """
    Extract extension from a blocklist regex pattern.

    Handles common forms:
      ``.*\\.env$``  → ``.env``
      ``.*\\.key$``  → ``.key``
    """
    import re
    # Match patterns like .*\.ext$ or .*\.ext
    m = re.match(r"^\.\*\\?\\.(\w+)\$?$", pattern)
    if m:
        return "." + m.group(1).lower()
    return None


# =============================================================================
# Syntactic safety predicates - mirrors Dafny specification
# =============================================================================

def has_traversal(path: str) -> bool:
    """
    P35: Does the path contain a traversal component (``..``)?

    Mirrors ``predicate HasTraversal(path)`` in Dafny.
    """
    return ".." in path


def is_absolute(path: str) -> bool:
    """
    P36: Is the path an absolute path?

    Mirrors ``predicate IsAbsolute(path)`` in Dafny.
    """
    return len(path) > 0 and path[0] == "/"


def is_home_escape(path: str) -> bool:
    """
    P37: Does the path start with home-dir expansion (``~``)?

    Mirrors ``predicate IsHomeEscape(path)`` in Dafny.
    """
    return len(path) > 0 and path[0] == "~"


def is_syntactically_clean(path: str) -> bool:
    """
    Composite: all syntactic checks pass.

    Mirrors ``predicate SyntacticallyClean(path)`` in Dafny.
    """
    return (
        not has_traversal(path)
        and not is_absolute(path)
        and not is_home_escape(path)
    )


# =============================================================================
# Extension and size predicates
# =============================================================================

def get_extension(filename: str) -> str:
    """
    Get the file extension (lowercase, with leading dot).

    Mirrors ``function GetExtension(filename)`` in Dafny.

    Returns ``""`` if no extension found.

    Special case: files like ``.env`` where the stem is empty and the
    entire filename is dot-prefixed are treated as having that extension.
    """
    p = PurePosixPath(filename)
    ext = p.suffix.lower()
    if ext:
        return ext
    # Handle hidden files: ".env" → stem is ".env", suffix is ""
    # But the basename itself starts with "." and has no other dot
    name = p.name
    if name.startswith(".") and "." not in name[1:]:
        return name.lower()  # ".env", ".key", ".pem"
    return ""


def extension_allowed(ext: str, config: PathSafetyConfig) -> bool:
    """
    P38: Is the extension allowed by the allowlist?

    If allowlist is empty, ALL extensions are allowed.
    If non-empty, extension must be in the set.

    Mirrors ``predicate ExtensionAllowed`` in Dafny.
    """
    if not config.allowed_extensions:
        return True
    return ext in config.allowed_extensions


def extension_blocked(ext: str, config: PathSafetyConfig) -> bool:
    """
    P39: Is the extension in the blocklist?

    Mirrors ``predicate ExtensionBlocked`` in Dafny.
    """
    return ext in config.blocked_extensions


def extension_safe(ext: str, config: PathSafetyConfig) -> bool:
    """
    Combined: extension is allowed AND not blocked.

    Mirrors ``predicate ExtensionSafe`` in Dafny.
    """
    return extension_allowed(ext, config) and not extension_blocked(ext, config)


def size_within_limit(file_size: int, config: PathSafetyConfig) -> bool:
    """
    P40: Is the file size within the configured limit?

    Mirrors ``predicate SizeWithinLimit`` in Dafny.
    """
    return file_size <= config.max_file_size


# =============================================================================
# Pure safety function - THE SPECIFICATION (P46 determinism)
# =============================================================================

def check_path_safety(
    path: str,
    ext: str,
    file_size: int,
    config: PathSafetyConfig,
) -> PathDecision:
    """
    Pure path safety function - the specification.

    Mirrors ``function CheckPathSafety(path, ext, file_size, config)`` in Dafny.

    Being a pure function, it is inherently deterministic (P46).

    Checks are ordered by priority:
      1. Traversal rejection (P35) - most critical
      2. Absolute path rejection (P36)
      3. Home escape rejection (P37)
      4. Extension blocklist (P39) - before allowlist
      5. Extension allowlist (P38)
      6. Size limit (P40)

    Returns Allow IFF all checks pass (P47 composability).
    """
    if has_traversal(path):
        return PathDecision.deny("Path contains traversal component '..'")
    if is_absolute(path):
        return PathDecision.deny("Absolute paths not allowed")
    if is_home_escape(path):
        return PathDecision.deny("Home directory escape not allowed")
    if extension_blocked(ext, config):
        return PathDecision.deny("Extension is in blocklist")
    if not extension_allowed(ext, config):
        return PathDecision.deny("Extension not in allowlist")
    if not size_within_limit(file_size, config):
        return PathDecision.deny("File exceeds size limit")
    return PathDecision.allow()


# =============================================================================
# PathSafetyChecker - stateful checker with audit trail (P43, P44)
# =============================================================================

_CLASS_NAME = "PathSafetyChecker"


class PathSafetyChecker:
    """
    Dafny-verified workspace confinement checker with audit trail.

    Mirrors ``class PathSafetyChecker`` in ``dafny/tools/path_safety.dfy``.

    Every method boundary enforces the class invariant ``Valid()`` via
    ``check_invariant()``, recording results to ``InvariantAuditLog``.

    Thread-safe: all mutable state protected by a lock.

    Properties proven in Dafny and enforced at runtime:
      P34-P37: Workspace confinement (traversal, absolute, home)
      P38-P39: Extension enforcement (allowlist, blocklist)
      P40:     Size limit
      P41:     Resolution soundness
      P42:     Confinement monotonicity
      P43:     Audit completeness
      P44:     Invariant preservation
      P45:     Config immutability (frozen dataclass)
      P46:     Decision determinism (pure function)
      P47:     Component composability
    """

    def __init__(self, config: PathSafetyConfig) -> None:
        """
        Construct a PathSafetyChecker.

        Dafny precondition: ``config.max_file_size > 0``.
        Dafny postconditions: ``Valid()``, ``audit_log == []``, ``total_checks == 0``.

        Raises:
            PreconditionViolation: If config.max_file_size <= 0.
        """
        if config.max_file_size <= 0:
            raise PreconditionViolation(
                property_id="requires cfg.max_file_size > 0",
                class_name=_CLASS_NAME,
                method="__init__",
                phase="pre",
                details=f"max_file_size={config.max_file_size}",
            )

        self._config: PathSafetyConfig = config
        self._audit_log: List[PathAuditEntry] = []
        self._total_checks: int = 0
        self._lock = threading.Lock()

        # P44: verify invariant established
        check_invariant(
            self._valid, _CLASS_NAME, "__init__", "post", "Valid()",
        )

    # ── Class invariant (P44) ────────────────────────────────────

    def _valid(self) -> bool:
        """
        Class invariant - mirrors ``ghost predicate Valid()`` in Dafny.

        C1: max_file_size > 0
        C2: total_checks >= len(audit_log)
        """
        return (
            self._config.max_file_size > 0
            and self._total_checks >= len(self._audit_log)
        )

    # ── Main entry point ─────────────────────────────────────────

    def check_path(
        self,
        path: str,
        file_size: int,
        operation: str = "read",
    ) -> PathDecision:
        """
        Check whether a file path is safe for the given operation.

        This is the main entry point.  It:
          1. Extracts the extension from the path
          2. Delegates to the pure ``check_path_safety()`` function (P46)
          3. Records the result in the audit log (P43)
          4. Enforces the class invariant at pre/post boundaries (P44)

        The decision matches the pure specification exactly.

        Args:
            path: Relative file path to check (e.g. "report.txt",
                  "data/results.csv", "../../etc/passwd").
            file_size: Size of the file in bytes (for write) or size on
                       disk (for read). Use 0 if size is not yet known.
            operation: "read" or "write".

        Returns:
            PathDecision - Allow or Deny(reason).
        """
        ext = get_extension(path)

        with self._lock:
            # P44 pre-check
            check_invariant(
                self._valid, _CLASS_NAME, "check_path", "pre", "Valid()",
            )

            old_log_len = len(self._audit_log)
            old_config = self._config  # for P45 assertion

            # P46: pure function - the specification
            decision = check_path_safety(path, ext, file_size, self._config)

            # P43: append exactly one audit entry
            entry = PathAuditEntry(
                path=path,
                decision=decision,
                operation=operation,
                file_size=file_size,
                extension=ext,
            )
            self._audit_log.append(entry)
            self._total_checks += 1

            # P43: verify exactly one entry added
            assert len(self._audit_log) == old_log_len + 1, \
                "P43: audit log must grow by exactly 1"
            assert self._audit_log[-1] is entry, \
                "P43: last entry must be the one we appended"

            # P45: config unchanged
            assert self._config is old_config, "P45: config immutability"

            # P44 post-check
            check_invariant(
                self._valid, _CLASS_NAME, "check_path", "post", "Valid()",
            )

        return decision

    # ── Convenience: check without audit ─────────────────────────

    def is_path_safe(self, path: str, file_size: int = 0) -> bool:
        """
        Quick safety check without audit (pure filter only).

        Uses the pure ``check_path_safety()`` function directly.
        Does NOT record to audit log.
        """
        ext = get_extension(path)
        return check_path_safety(path, ext, file_size, self._config).is_allow

    # ── Path resolution with confinement check (P34) ─────────────

    def resolve_and_check(
        self,
        path: str,
        file_size: int,
        operation: str = "read",
    ) -> Tuple[PathDecision, Optional[str]]:
        """
        Check path safety AND resolve to absolute path under workspace.

        This combines the Dafny-verified pure checks (P35-P40) with
        OS-level path resolution for the full P34 guarantee.

        Returns:
            (decision, resolved_path): where resolved_path is the
            absolute path under workspace_root, or None if denied.
        """
        # First: Dafny-verified checks (records to audit)
        decision = self.check_path(path, file_size, operation)
        if decision.is_deny:
            return decision, None

        # Second: OS-level resolution for defence-in-depth
        if not self._config.workspace_root:
            # No workspace root configured - allow but can't resolve
            return decision, None

        try:
            workspace = os.path.realpath(self._config.workspace_root)
            resolved = os.path.realpath(
                os.path.join(workspace, path)
            )

            # Defence-in-depth: verify resolved path is under workspace
            # This should be guaranteed by P35-P37+P41, but we double-check
            if not resolved.startswith(workspace + os.sep) and resolved != workspace:
                # This should be unreachable if Dafny proofs are correct,
                # but we reject just in case of OS-level symlink tricks
                return PathDecision.deny(
                    "Resolved path escapes workspace (defence-in-depth)"
                ), None

            return decision, resolved

        except (OSError, ValueError) as exc:
            return PathDecision.deny(f"Path resolution error: {exc}"), None

    # ── Audit log access ─────────────────────────────────────────

    @property
    def audit_log(self) -> List[PathAuditEntry]:
        """Return a copy of the audit log."""
        with self._lock:
            return list(self._audit_log)

    @property
    def total_checks(self) -> int:
        """Total number of checks performed."""
        with self._lock:
            return self._total_checks

    @property
    def config(self) -> PathSafetyConfig:
        """Access the immutable config (P45)."""
        return self._config

    def get_stats(self) -> Dict[str, Any]:
        """Return checker statistics."""
        with self._lock:
            allows = sum(1 for e in self._audit_log if e.decision.is_allow)
            denies = sum(1 for e in self._audit_log if e.decision.is_deny)
            return {
                "total_checks": self._total_checks,
                "audit_entries": len(self._audit_log),
                "total_allows": allows,
                "total_denies": denies,
                "workspace_root": self._config.workspace_root,
                "allowed_extensions": sorted(self._config.allowed_extensions),
                "blocked_extensions": sorted(self._config.blocked_extensions),
                "max_file_size": self._config.max_file_size,
            }

    def __repr__(self) -> str:
        return (
            f"PathSafetyChecker("
            f"workspace={self._config.workspace_root!r}, "
            f"allowed_ext={len(self._config.allowed_extensions)}, "
            f"blocked_ext={len(self._config.blocked_extensions)}, "
            f"max_size={self._config.max_file_size}, "
            f"checks={self._total_checks})"
        )


# =============================================================================
# Factory: build PathSafetyChecker from VERIFICATION.json
# =============================================================================

def create_path_checker_from_spec(
    spec: Dict[str, Any],
    workspace_root: str = "",
) -> PathSafetyChecker:
    """
    Build a Dafny-verified PathSafetyChecker from a VERIFICATION.json spec.

    This is the standard production entry point, ensuring the runtime
    checker is configured from the same spec that Dafny proofs verify.

    Args:
        spec: Parsed VERIFICATION.json dict.
        workspace_root: Absolute path to workspace directory.

    Returns:
        PathSafetyChecker with invariant enforcement enabled.
    """
    config = PathSafetyConfig.from_verification_json(spec)
    # Override workspace_root (it's not in the spec)
    config = PathSafetyConfig(
        workspace_root=workspace_root,
        allowed_extensions=config.allowed_extensions,
        blocked_extensions=config.blocked_extensions,
        max_file_size=config.max_file_size,
    )
    return PathSafetyChecker(config)


def create_file_operations_checker(
    skills_dir: str = "skills",
    workspace_root: str = "",
) -> PathSafetyChecker:
    """
    Build a PathSafetyChecker from the file_operations skill spec.

    Convenience function for the common case.

    Args:
        skills_dir: Path to skills directory.
        workspace_root: Absolute path to workspace directory.
    """
    import json
    from pathlib import Path

    spec_path = Path(skills_dir) / "file_operations" / "VERIFICATION.json"
    if not spec_path.exists():
        # Fallback: hardcoded defaults matching the spec
        config = PathSafetyConfig(
            workspace_root=workspace_root,
            allowed_extensions=frozenset({
                ".txt", ".csv", ".json", ".md", ".pdf",
            }),
            blocked_extensions=frozenset({
                ".env", ".key", ".pem",
            }),
            max_file_size=10_000_000,
        )
        return PathSafetyChecker(config)

    with open(spec_path) as f:
        spec = json.load(f)
    return create_path_checker_from_spec(spec, workspace_root)
