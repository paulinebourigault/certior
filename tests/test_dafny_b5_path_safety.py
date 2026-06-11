"""
Dafny-Verified Workspace Confinement - Comprehensive Tests.

Tests every property proven in ``dafny/tools/path_safety.dfy``:

  P34  Workspace confinement - Allow only if path stays under workspace
  P35  Traversal rejection - ".." always rejected
  P36  Absolute path rejection - "/" prefix always rejected
  P37  Home escape rejection - "~" prefix always rejected
  P38  Extension allowlist enforcement - non-allowlisted rejected
  P39  Extension blocklist enforcement - blocklisted always rejected
  P40  Size limit enforcement - over-limit rejected
  P41  Path resolution soundness - clean path ⟹ confined
  P42  Confinement monotonicity - adding restrictions reduces accepts
  P43  Audit completeness - every check_path appends exactly one entry
  P44  Invariant preservation - Valid() at every method boundary
  P45  Config immutability - config frozen after construction
  P46  Decision determinism - same inputs → same output
  P47  Component composability - Allow requires ALL checks pass

Also tests:
  - Pure predicate functions (has_traversal, is_absolute, etc.)
  - Extension normalisation and extraction
  - Thread safety under concurrent operations
  - Audit trail completeness via InvariantAuditLog
  - Factory functions (from_verification_json, file_operations_checker)
  - Edge cases (empty path, deeply nested, unicode, no extension, etc.)
  - Integration with existing FileReadTool / FileWriteTool constraints
  - resolve_and_check with real filesystem
  - VERIFICATION.json round-trip
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

import pytest

from agentsafe.tools.path_safety_verified import (
    PathAuditEntry,
    PathDecision,
    PathSafetyChecker,
    PathSafetyConfig,
    check_path_safety,
    create_file_operations_checker,
    create_path_checker_from_spec,
    extension_allowed,
    extension_blocked,
    extension_safe,
    get_extension,
    has_traversal,
    is_absolute,
    is_home_escape,
    is_syntactically_clean,
    size_within_limit,
)
from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def _reset_audit_log():
    """Reset the global InvariantAuditLog before every test."""
    InvariantAuditLog.reset()
    yield
    InvariantAuditLog.reset()


@pytest.fixture
def _file_ops_config() -> PathSafetyConfig:
    """Config matching file_operations/VERIFICATION.json."""
    return PathSafetyConfig(
        workspace_root="/tmp/certior_ws",
        allowed_extensions=frozenset({".txt", ".csv", ".json", ".md", ".pdf"}),
        blocked_extensions=frozenset({".env", ".key", ".pem"}),
        max_file_size=10_000_000,
    )


@pytest.fixture
def _fresh_checker(_file_ops_config) -> PathSafetyChecker:
    """Fresh PathSafetyChecker with file_operations config."""
    return PathSafetyChecker(_file_ops_config)


@pytest.fixture
def _minimal_config() -> PathSafetyConfig:
    """Minimal config: allow all extensions, no blocklist."""
    return PathSafetyConfig(
        workspace_root="/tmp/ws",
        allowed_extensions=frozenset(),  # allow all
        blocked_extensions=frozenset(),
        max_file_size=1_000_000,
    )


@pytest.fixture
def _minimal_checker(_minimal_config) -> PathSafetyChecker:
    """Checker with minimal config."""
    return PathSafetyChecker(_minimal_config)


# =============================================================================
# PathDecision tests
# =============================================================================

class TestPathDecision:
    def test_allow(self):
        d = PathDecision.allow()
        assert d.is_allow
        assert not d.is_deny
        assert d.reason == ""
        assert "Allow" in str(d)

    def test_deny(self):
        d = PathDecision.deny("traversal")
        assert d.is_deny
        assert not d.is_allow
        assert d.reason == "traversal"
        assert "Deny" in str(d)
        assert "traversal" in str(d)

    def test_immutability(self):
        d = PathDecision.allow()
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]

    def test_equality(self):
        a1 = PathDecision.allow()
        a2 = PathDecision.allow()
        assert a1 == a2
        d1 = PathDecision.deny("x")
        d2 = PathDecision.deny("x")
        assert d1 == d2
        assert a1 != d1


# =============================================================================
# PathSafetyConfig tests
# =============================================================================

class TestPathSafetyConfig:
    def test_immutability(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=100)
        with pytest.raises(AttributeError):
            cfg.workspace_root = "/evil"  # type: ignore[misc]
        with pytest.raises(AttributeError):
            cfg.max_file_size = 999  # type: ignore[misc]

    def test_extension_normalisation(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({"TXT", ".CSV", "json"}),
            max_file_size=100,
        )
        assert ".txt" in cfg.allowed_extensions
        assert ".csv" in cfg.allowed_extensions
        assert ".json" in cfg.allowed_extensions

    def test_invalid_max_file_size(self):
        with pytest.raises(ValueError, match="max_file_size must be > 0"):
            PathSafetyConfig(workspace_root="/tmp", max_file_size=0)
        with pytest.raises(ValueError, match="max_file_size must be > 0"):
            PathSafetyConfig(workspace_root="/tmp", max_file_size=-1)

    def test_from_verification_json(self):
        spec = {
            "verification_requirements": {
                "resource_constraints": {"max_file_size_bytes": 5_000_000},
                "safety_constraints": {
                    "allowed_extensions": [".txt", ".csv"],
                    "path_blocklist_patterns": [".*\\.env$", ".*\\.key$"],
                },
            }
        }
        cfg = PathSafetyConfig.from_verification_json(spec)
        assert ".txt" in cfg.allowed_extensions
        assert ".csv" in cfg.allowed_extensions
        assert ".env" in cfg.blocked_extensions
        assert ".key" in cfg.blocked_extensions
        assert cfg.max_file_size == 5_000_000

    def test_from_verification_json_empty(self):
        cfg = PathSafetyConfig.from_verification_json({})
        assert cfg.allowed_extensions == frozenset()
        assert cfg.blocked_extensions == frozenset()
        assert cfg.max_file_size == 10_000_000

    def test_default_values(self):
        cfg = PathSafetyConfig(workspace_root="/tmp")
        assert cfg.allowed_extensions == frozenset()
        assert cfg.blocked_extensions == frozenset()
        assert cfg.max_file_size == 10_000_000


# =============================================================================
# Pure predicate tests
# =============================================================================

class TestHasTraversal:
    def test_dotdot_start(self):
        assert has_traversal("../secret.txt")

    def test_dotdot_middle(self):
        assert has_traversal("data/../../../etc/passwd")

    def test_dotdot_end(self):
        assert has_traversal("data/..")

    def test_bare_dotdot(self):
        assert has_traversal("..")

    def test_no_traversal(self):
        assert not has_traversal("data/report.txt")

    def test_single_dot(self):
        assert not has_traversal("./data/report.txt")

    def test_dotdot_in_filename(self):
        # "..." contains ".." as substring - this is conservative but safe
        assert has_traversal("...")

    def test_empty(self):
        assert not has_traversal("")


class TestIsAbsolute:
    def test_slash(self):
        assert is_absolute("/etc/passwd")

    def test_relative(self):
        assert not is_absolute("data/report.txt")

    def test_dot_relative(self):
        assert not is_absolute("./data/report.txt")

    def test_empty(self):
        assert not is_absolute("")

    def test_tilde(self):
        assert not is_absolute("~/.ssh/id_rsa")


class TestIsHomeEscape:
    def test_tilde(self):
        assert is_home_escape("~/.ssh/id_rsa")

    def test_tilde_alone(self):
        assert is_home_escape("~")

    def test_tilde_user(self):
        assert is_home_escape("~user/secret")

    def test_relative(self):
        assert not is_home_escape("data/report.txt")

    def test_empty(self):
        assert not is_home_escape("")


class TestIsSyntacticallyClean:
    def test_clean_simple(self):
        assert is_syntactically_clean("report.txt")

    def test_clean_nested(self):
        assert is_syntactically_clean("data/results/q1.csv")

    def test_traversal_dirty(self):
        assert not is_syntactically_clean("../secret.txt")

    def test_absolute_dirty(self):
        assert not is_syntactically_clean("/etc/passwd")

    def test_home_dirty(self):
        assert not is_syntactically_clean("~/.ssh/id_rsa")

    def test_empty_is_clean(self):
        assert is_syntactically_clean("")


class TestGetExtension:
    def test_txt(self):
        assert get_extension("report.txt") == ".txt"

    def test_csv(self):
        assert get_extension("data/results.csv") == ".csv"

    def test_no_extension(self):
        assert get_extension("Makefile") == ""

    def test_hidden_file(self):
        assert get_extension(".env") == ".env"

    def test_double_extension(self):
        assert get_extension("archive.tar.gz") == ".gz"

    def test_uppercase(self):
        assert get_extension("IMAGE.PNG") == ".png"

    def test_empty(self):
        assert get_extension("") == ""


class TestExtensionAllowed:
    def test_empty_allowlist_allows_all(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", allowed_extensions=frozenset())
        assert extension_allowed(".exe", cfg)
        assert extension_allowed(".txt", cfg)
        assert extension_allowed("", cfg)

    def test_non_empty_allowlist_allows_listed(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt", ".csv"}),
        )
        assert extension_allowed(".txt", cfg)
        assert extension_allowed(".csv", cfg)
        assert not extension_allowed(".exe", cfg)
        assert not extension_allowed(".sh", cfg)

    def test_no_extension_not_allowed_if_allowlist(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
        )
        assert not extension_allowed("", cfg)


class TestExtensionBlocked:
    def test_empty_blocklist_blocks_none(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", blocked_extensions=frozenset())
        assert not extension_blocked(".exe", cfg)
        assert not extension_blocked(".env", cfg)

    def test_non_empty_blocklist(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset({".env", ".key"}),
        )
        assert extension_blocked(".env", cfg)
        assert extension_blocked(".key", cfg)
        assert not extension_blocked(".txt", cfg)


class TestExtensionSafe:
    def test_allowed_not_blocked(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            blocked_extensions=frozenset({".env"}),
        )
        assert extension_safe(".txt", cfg)
        assert not extension_safe(".env", cfg)
        assert not extension_safe(".sh", cfg)  # not in allowlist

    def test_in_both_lists_blocked_wins(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".sh", ".txt"}),
            blocked_extensions=frozenset({".sh"}),
        )
        assert not extension_safe(".sh", cfg)  # P39: blocklist precedence
        assert extension_safe(".txt", cfg)


class TestSizeWithinLimit:
    def test_under_limit(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        assert size_within_limit(500, cfg)

    def test_at_limit(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        assert size_within_limit(1000, cfg)

    def test_over_limit(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        assert not size_within_limit(1001, cfg)

    def test_zero_size(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        assert size_within_limit(0, cfg)


# =============================================================================
# Pure function check_path_safety tests (P46 determinism)
# =============================================================================

class TestCheckPathSafety:
    def test_clean_path_allowed(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("report.txt", ".txt", 100, cfg)
        assert d.is_allow

    def test_traversal_denied(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("../secret.txt", ".txt", 100, cfg)
        assert d.is_deny
        assert ".." in d.reason

    def test_absolute_denied(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("/etc/passwd", "", 100, cfg)
        assert d.is_deny
        assert "Absolute" in d.reason

    def test_home_denied(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("~/.ssh/id_rsa", "", 100, cfg)
        assert d.is_deny
        assert "Home" in d.reason

    def test_blocked_extension_denied(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset({".env"}),
            max_file_size=1000,
        )
        d = check_path_safety(".env", ".env", 100, cfg)
        assert d.is_deny
        assert "blocklist" in d.reason

    def test_non_allowed_extension_denied(self):
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            max_file_size=1000,
        )
        d = check_path_safety("script.sh", ".sh", 100, cfg)
        assert d.is_deny
        assert "allowlist" in d.reason

    def test_oversize_denied(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("big.txt", ".txt", 2000, cfg)
        assert d.is_deny
        assert "size" in d.reason.lower()

    def test_priority_traversal_first(self):
        """Traversal check fires before all others."""
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            blocked_extensions=frozenset({".env"}),
            max_file_size=100,
        )
        # Path has traversal AND oversize AND wrong extension
        d = check_path_safety("../big.env", ".env", 999, cfg)
        assert d.is_deny
        assert ".." in d.reason  # traversal fires first

    def test_priority_absolute_second(self):
        """Absolute fires after traversal."""
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("/etc/passwd", "", 100, cfg)
        assert "Absolute" in d.reason

    def test_priority_home_third(self):
        """Home fires after absolute."""
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("~/.ssh/id_rsa", "", 100, cfg)
        assert "Home" in d.reason

    def test_determinism_repeated(self):
        """P46: same inputs always produce same output."""
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        results = [
            check_path_safety("report.txt", ".txt", 100, cfg)
            for _ in range(100)
        ]
        assert all(r == results[0] for r in results)

    def test_determinism_across_configs(self):
        """P46: identical configs produce same result."""
        cfg1 = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        cfg2 = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d1 = check_path_safety("report.txt", ".txt", 100, cfg1)
        d2 = check_path_safety("report.txt", ".txt", 100, cfg2)
        assert d1 == d2


# =============================================================================
# P34+P41: Workspace confinement (resolution soundness)
# =============================================================================

class TestP34WorkspaceConfinement:
    """P34: resolved path must stay under workspace."""

    def test_clean_path_is_confined(self):
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        d = check_path_safety("report.txt", ".txt", 100, cfg)
        assert d.is_allow

    def test_traversal_breaks_confinement(self):
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        d = check_path_safety("../../etc/passwd", "", 100, cfg)
        assert d.is_deny

    def test_absolute_breaks_confinement(self):
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        d = check_path_safety("/etc/shadow", "", 100, cfg)
        assert d.is_deny

    def test_home_breaks_confinement(self):
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        d = check_path_safety("~/.bashrc", "", 100, cfg)
        assert d.is_deny

    def test_nested_path_confined(self):
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        d = check_path_safety("a/b/c/d/e.txt", ".txt", 100, cfg)
        assert d.is_allow


class TestP41ResolutionSoundness:
    """P41: syntactically clean path cannot escape workspace."""

    def test_clean_implies_allow(self):
        """If all checks pass, the path is allowed."""
        cfg = PathSafetyConfig(workspace_root="/tmp/ws", max_file_size=1000)
        path = "data/report.txt"
        assert is_syntactically_clean(path)
        assert extension_safe(".txt", cfg)
        assert size_within_limit(100, cfg)
        d = check_path_safety(path, ".txt", 100, cfg)
        assert d.is_allow

    def test_deny_implies_failed_check(self):
        """If denied, at least one check must have failed."""
        cfg = PathSafetyConfig(
            workspace_root="/tmp/ws",
            allowed_extensions=frozenset({".txt"}),
            max_file_size=1000,
        )
        path = "script.sh"
        d = check_path_safety(path, ".sh", 100, cfg)
        assert d.is_deny
        # At least one check failed
        assert (
            has_traversal(path)
            or is_absolute(path)
            or is_home_escape(path)
            or extension_blocked(".sh", cfg)
            or not extension_allowed(".sh", cfg)
            or not size_within_limit(100, cfg)
        )


# =============================================================================
# P35: Traversal rejection
# =============================================================================

class TestP35TraversalRejection:
    def test_single_dotdot(self, _fresh_checker):
        d = _fresh_checker.check_path("../secret.txt", 100, "read")
        assert d.is_deny

    def test_double_dotdot(self, _fresh_checker):
        d = _fresh_checker.check_path("../../etc/passwd", 100, "read")
        assert d.is_deny

    def test_deep_traversal(self, _fresh_checker):
        d = _fresh_checker.check_path("a/b/../../../../../../etc/shadow", 100, "read")
        assert d.is_deny

    def test_middle_traversal(self, _fresh_checker):
        d = _fresh_checker.check_path("data/../../../secret", 100, "read")
        assert d.is_deny

    def test_traversal_with_allowed_extension(self, _fresh_checker):
        """P35 fires even if extension is allowed."""
        d = _fresh_checker.check_path("../report.txt", 100, "read")
        assert d.is_deny


# =============================================================================
# P36: Absolute path rejection
# =============================================================================

class TestP36AbsolutePathRejection:
    def test_etc_passwd(self, _fresh_checker):
        d = _fresh_checker.check_path("/etc/passwd", 100, "read")
        assert d.is_deny

    def test_etc_shadow(self, _fresh_checker):
        d = _fresh_checker.check_path("/etc/shadow", 100, "read")
        assert d.is_deny

    def test_root(self, _fresh_checker):
        d = _fresh_checker.check_path("/", 100, "read")
        assert d.is_deny

    def test_absolute_with_allowed_extension(self, _fresh_checker):
        d = _fresh_checker.check_path("/data/report.txt", 100, "read")
        assert d.is_deny


# =============================================================================
# P37: Home escape rejection
# =============================================================================

class TestP37HomeEscapeRejection:
    def test_ssh_key(self, _fresh_checker):
        d = _fresh_checker.check_path("~/.ssh/id_rsa", 100, "read")
        assert d.is_deny

    def test_bashrc(self, _fresh_checker):
        d = _fresh_checker.check_path("~/.bashrc", 100, "read")
        assert d.is_deny

    def test_tilde_alone(self, _fresh_checker):
        d = _fresh_checker.check_path("~", 100, "read")
        assert d.is_deny

    def test_tilde_user(self, _fresh_checker):
        d = _fresh_checker.check_path("~user/secret.txt", 100, "read")
        assert d.is_deny


# =============================================================================
# P38: Extension allowlist enforcement
# =============================================================================

class TestP38ExtensionAllowlist:
    def test_allowed_extension_accepted(self, _fresh_checker):
        d = _fresh_checker.check_path("report.txt", 100, "write")
        assert d.is_allow

    def test_allowed_csv(self, _fresh_checker):
        d = _fresh_checker.check_path("data.csv", 100, "write")
        assert d.is_allow

    def test_allowed_json(self, _fresh_checker):
        d = _fresh_checker.check_path("config.json", 100, "read")
        assert d.is_allow

    def test_not_allowed_rejected(self, _fresh_checker):
        d = _fresh_checker.check_path("script.sh", 100, "write")
        assert d.is_deny

    def test_not_allowed_exe(self, _fresh_checker):
        d = _fresh_checker.check_path("malware.exe", 100, "write")
        assert d.is_deny

    def test_empty_allowlist_accepts_all(self, _minimal_checker):
        d = _minimal_checker.check_path("script.sh", 100, "write")
        assert d.is_allow
        d = _minimal_checker.check_path("anything.xyz", 100, "write")
        assert d.is_allow


# =============================================================================
# P39: Extension blocklist enforcement
# =============================================================================

class TestP39ExtensionBlocklist:
    def test_env_blocked(self, _fresh_checker):
        d = _fresh_checker.check_path("secrets.env", 100, "read")
        assert d.is_deny

    def test_key_blocked(self, _fresh_checker):
        d = _fresh_checker.check_path("server.key", 100, "read")
        assert d.is_deny

    def test_pem_blocked(self, _fresh_checker):
        d = _fresh_checker.check_path("cert.pem", 100, "read")
        assert d.is_deny

    def test_hidden_env_blocked(self, _fresh_checker):
        d = _fresh_checker.check_path(".env", 100, "read")
        assert d.is_deny

    def test_blocklist_precedence_over_allowlist(self):
        """P39 corollary: if ext is in BOTH lists, blocklist wins."""
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".key", ".txt"}),
            blocked_extensions=frozenset({".key"}),
            max_file_size=1000,
        )
        checker = PathSafetyChecker(cfg)
        d = checker.check_path("server.key", 100, "read")
        assert d.is_deny


# =============================================================================
# P40: Size limit enforcement
# =============================================================================

class TestP40SizeLimit:
    def test_under_limit(self, _fresh_checker):
        d = _fresh_checker.check_path("small.txt", 100, "write")
        assert d.is_allow

    def test_at_limit(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        checker = PathSafetyChecker(cfg)
        d = checker.check_path("exact.txt", 1000, "write")
        assert d.is_allow

    def test_over_limit(self):
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        checker = PathSafetyChecker(cfg)
        d = checker.check_path("big.txt", 1001, "write")
        assert d.is_deny

    def test_zero_size_allowed(self, _fresh_checker):
        d = _fresh_checker.check_path("empty.txt", 0, "write")
        assert d.is_allow

    def test_very_large_file(self, _fresh_checker):
        d = _fresh_checker.check_path("huge.txt", 999_999_999, "write")
        assert d.is_deny


# =============================================================================
# P42: Confinement monotonicity
# =============================================================================

class TestP42ConfinementMonotonicity:
    def test_adding_blocklist_reduces_accepts(self):
        """Path accepted under no blocklist → denied after adding matching entry."""
        cfg1 = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset(),
            max_file_size=1000,
        )
        cfg2 = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset({".sh"}),
            max_file_size=1000,
        )
        d1 = check_path_safety("script.sh", ".sh", 100, cfg1)
        d2 = check_path_safety("script.sh", ".sh", 100, cfg2)
        assert d1.is_allow
        assert d2.is_deny

    def test_adding_non_matching_blocklist_preserves(self):
        """Adding unrelated blocklist entry doesn't affect other paths."""
        cfg1 = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset(),
            max_file_size=1000,
        )
        cfg2 = PathSafetyConfig(
            workspace_root="/tmp",
            blocked_extensions=frozenset({".env"}),
            max_file_size=1000,
        )
        d1 = check_path_safety("report.txt", ".txt", 100, cfg1)
        d2 = check_path_safety("report.txt", ".txt", 100, cfg2)
        assert d1.is_allow
        assert d2.is_allow  # .env blocklist doesn't affect .txt

    def test_reducing_size_limit_reduces_accepts(self):
        """Smaller size limit → previously-accepted file now denied."""
        cfg1 = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        cfg2 = PathSafetyConfig(workspace_root="/tmp", max_file_size=50)
        d1 = check_path_safety("report.txt", ".txt", 100, cfg1)
        d2 = check_path_safety("report.txt", ".txt", 100, cfg2)
        assert d1.is_allow
        assert d2.is_deny

    def test_adding_allowlist_reduces_accepts(self):
        """Going from empty allowlist (all) to restricted allowlist reduces accepts."""
        cfg1 = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset(),  # all
            max_file_size=1000,
        )
        cfg2 = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            max_file_size=1000,
        )
        d1 = check_path_safety("script.sh", ".sh", 100, cfg1)
        d2 = check_path_safety("script.sh", ".sh", 100, cfg2)
        assert d1.is_allow
        assert d2.is_deny


# =============================================================================
# P43: Audit completeness
# =============================================================================

class TestP43AuditCompleteness:
    def test_single_check_one_entry(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        assert len(_fresh_checker.audit_log) == 1

    def test_multiple_checks_multiple_entries(self, _fresh_checker):
        _fresh_checker.check_path("a.txt", 10, "write")
        _fresh_checker.check_path("b.csv", 20, "write")
        _fresh_checker.check_path("../evil", 30, "read")
        assert len(_fresh_checker.audit_log) == 3

    def test_entry_records_path(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        entry = _fresh_checker.audit_log[0]
        assert entry.path == "report.txt"

    def test_entry_records_decision(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        entry = _fresh_checker.audit_log[0]
        assert entry.decision.is_allow

    def test_entry_records_deny_decision(self, _fresh_checker):
        _fresh_checker.check_path("../evil", 100, "read")
        entry = _fresh_checker.audit_log[0]
        assert entry.decision.is_deny

    def test_entry_records_operation(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        entry = _fresh_checker.audit_log[0]
        assert entry.operation == "write"

    def test_entry_records_size(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 42, "write")
        entry = _fresh_checker.audit_log[0]
        assert entry.file_size == 42

    def test_entry_records_extension(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        entry = _fresh_checker.audit_log[0]
        assert entry.extension == ".txt"

    def test_entry_has_timestamp(self, _fresh_checker):
        before = time.time()
        _fresh_checker.check_path("report.txt", 100, "write")
        after = time.time()
        entry = _fresh_checker.audit_log[0]
        assert before <= entry.timestamp <= after

    def test_audit_append_only(self, _fresh_checker):
        _fresh_checker.check_path("a.txt", 10, "write")
        _fresh_checker.check_path("b.csv", 20, "read")
        log = _fresh_checker.audit_log
        assert log[0].path == "a.txt"
        assert log[1].path == "b.csv"
        # First entry unchanged
        _fresh_checker.check_path("c.json", 30, "write")
        log2 = _fresh_checker.audit_log
        assert log2[0].path == "a.txt"
        assert log2[1].path == "b.csv"
        assert log2[2].path == "c.json"

    def test_total_checks_matches(self, _fresh_checker):
        for i in range(5):
            _fresh_checker.check_path(f"file{i}.txt", 10, "write")
        assert _fresh_checker.total_checks == 5
        assert len(_fresh_checker.audit_log) == 5


# =============================================================================
# P44: Invariant preservation
# =============================================================================

class TestP44InvariantPreservation:
    def test_valid_after_construction(self, _fresh_checker):
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for(_CLASS_NAME := "PathSafetyChecker", "__init__")
        assert len(entries) == 1
        assert entries[0].passed
        assert entries[0].phase == "post"

    def test_valid_after_allow(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("PathSafetyChecker", "check_path")
        pre_entries = [e for e in entries if e.phase == "pre"]
        post_entries = [e for e in entries if e.phase == "post"]
        assert len(pre_entries) >= 1
        assert len(post_entries) >= 1
        assert all(e.passed for e in pre_entries)
        assert all(e.passed for e in post_entries)

    def test_valid_after_deny(self, _fresh_checker):
        _fresh_checker.check_path("../evil", 100, "read")
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("PathSafetyChecker", "check_path")
        assert all(e.passed for e in entries)

    def test_valid_after_many_operations(self, _fresh_checker):
        for i in range(20):
            _fresh_checker.check_path(f"file{i}.txt", 10, "write")
        for i in range(5):
            _fresh_checker.check_path(f"../evil{i}", 10, "read")
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("PathSafetyChecker")
        assert all(e.passed for e in entries)

    def test_precondition_violation(self):
        """Config with max_file_size <= 0 raises PreconditionViolation."""
        # Create a valid config then mutate it to be invalid (bypass frozen)
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1)
        # Use object.__setattr__ to bypass frozen and create invalid state
        object.__setattr__(cfg, "max_file_size", 0)
        with pytest.raises(PreconditionViolation):
            PathSafetyChecker(cfg)

    def test_invariant_audit_log_phases(self, _fresh_checker):
        _fresh_checker.check_path("report.txt", 100, "write")
        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("PathSafetyChecker")
        phases = [e.phase for e in entries]
        # Constructor: post. check_path: pre, post.
        assert "post" in phases
        assert "pre" in phases


# =============================================================================
# P45: Config immutability
# =============================================================================

class TestP45ConfigImmutability:
    def test_config_unchanged_after_allow(self, _fresh_checker):
        cfg_before = _fresh_checker.config
        _fresh_checker.check_path("report.txt", 100, "write")
        assert _fresh_checker.config is cfg_before

    def test_config_unchanged_after_deny(self, _fresh_checker):
        cfg_before = _fresh_checker.config
        _fresh_checker.check_path("../evil", 100, "read")
        assert _fresh_checker.config is cfg_before

    def test_config_unchanged_after_many_operations(self, _fresh_checker):
        cfg_before = _fresh_checker.config
        for i in range(50):
            _fresh_checker.check_path(f"file{i}.txt", 10, "write")
        assert _fresh_checker.config is cfg_before
        assert _fresh_checker.config == cfg_before

    def test_config_frozen(self, _fresh_checker):
        with pytest.raises(AttributeError):
            _fresh_checker.config.max_file_size = 999  # type: ignore


# =============================================================================
# P46: Decision determinism
# =============================================================================

class TestP46Determinism:
    def test_repeated_allow(self, _minimal_checker):
        results = [
            _minimal_checker.check_path("report.txt", 100, "write")
            for _ in range(50)
        ]
        assert all(r.is_allow for r in results)

    def test_repeated_deny(self, _minimal_checker):
        results = [
            _minimal_checker.check_path("../evil", 100, "read")
            for _ in range(50)
        ]
        assert all(r.is_deny for r in results)

    def test_across_instances(self, _file_ops_config):
        checker1 = PathSafetyChecker(_file_ops_config)
        checker2 = PathSafetyChecker(_file_ops_config)
        d1 = checker1.check_path("report.txt", 100, "write")
        d2 = checker2.check_path("report.txt", 100, "write")
        assert d1 == d2


# =============================================================================
# P47: Component composability
# =============================================================================

class TestP47Composability:
    def test_allow_requires_all_pass(self):
        """If any check fails, the result is Deny."""
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            blocked_extensions=frozenset({".env"}),
            max_file_size=1000,
        )
        # All pass
        d = check_path_safety("report.txt", ".txt", 100, cfg)
        assert d.is_allow

        # Fail: traversal
        d = check_path_safety("../report.txt", ".txt", 100, cfg)
        assert d.is_deny

        # Fail: extension
        d = check_path_safety("report.sh", ".sh", 100, cfg)
        assert d.is_deny

        # Fail: size
        d = check_path_safety("report.txt", ".txt", 2000, cfg)
        assert d.is_deny

    def test_every_check_independently_necessary(self):
        """Each individual check can cause denial."""
        cfg = PathSafetyConfig(
            workspace_root="/tmp",
            allowed_extensions=frozenset({".txt"}),
            blocked_extensions=frozenset({".env"}),
            max_file_size=1000,
        )
        # Each failing alone
        failures = [
            ("../x.txt", ".txt", 100),     # traversal
            ("/x.txt", ".txt", 100),        # absolute
            ("~/x.txt", ".txt", 100),       # home
            ("x.env", ".env", 100),         # blocked ext
            ("x.sh", ".sh", 100),           # non-allowed ext
            ("x.txt", ".txt", 9999),        # oversize
        ]
        for path, ext, size in failures:
            d = check_path_safety(path, ext, size, cfg)
            assert d.is_deny, f"Expected deny for ({path}, {ext}, {size})"


# =============================================================================
# resolve_and_check (P34 with real filesystem)
# =============================================================================

class TestResolveAndCheck:
    def test_resolve_clean_path(self):
        with tempfile.TemporaryDirectory() as ws:
            cfg = PathSafetyConfig(workspace_root=ws, max_file_size=1000)
            checker = PathSafetyChecker(cfg)
            d, resolved = checker.resolve_and_check("report.txt", 100, "write")
            assert d.is_allow
            assert resolved is not None
            assert resolved.startswith(ws)

    def test_resolve_nested_path(self):
        with tempfile.TemporaryDirectory() as ws:
            cfg = PathSafetyConfig(workspace_root=ws, max_file_size=1000)
            checker = PathSafetyChecker(cfg)
            d, resolved = checker.resolve_and_check("a/b/c.txt", 100, "write")
            assert d.is_allow
            assert resolved is not None
            assert resolved.startswith(ws)

    def test_resolve_traversal_denied(self):
        with tempfile.TemporaryDirectory() as ws:
            cfg = PathSafetyConfig(workspace_root=ws, max_file_size=1000)
            checker = PathSafetyChecker(cfg)
            d, resolved = checker.resolve_and_check("../../etc/passwd", 100, "read")
            assert d.is_deny
            assert resolved is None

    def test_resolve_no_workspace(self):
        cfg = PathSafetyConfig(workspace_root="", max_file_size=1000)
        checker = PathSafetyChecker(cfg)
        d, resolved = checker.resolve_and_check("report.txt", 100, "write")
        assert d.is_allow
        assert resolved is None  # no workspace to resolve against


# =============================================================================
# Thread safety
# =============================================================================

class TestThreadSafety:
    def test_concurrent_check_path(self, _minimal_config):
        checker = PathSafetyChecker(_minimal_config)
        errors: List[Exception] = []

        def worker(thread_id: int):
            try:
                for i in range(50):
                    path = f"thread{thread_id}/file{i}.txt"
                    d = checker.check_path(path, 10, "write")
                    assert d.is_allow
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker, t) for t in range(8)]
            for f in as_completed(futures):
                f.result()

        assert not errors
        assert checker.total_checks == 8 * 50
        assert len(checker.audit_log) == 8 * 50

    def test_concurrent_mixed_allow_deny(self, _file_ops_config):
        checker = PathSafetyChecker(_file_ops_config)
        errors: List[Exception] = []

        def worker(thread_id: int):
            try:
                for i in range(25):
                    # Alternate allow/deny
                    if i % 2 == 0:
                        d = checker.check_path(f"t{thread_id}_{i}.txt", 10, "write")
                        assert d.is_allow
                    else:
                        d = checker.check_path(f"../evil{thread_id}_{i}", 10, "read")
                        assert d.is_deny
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker, t) for t in range(8)]
            for f in as_completed(futures):
                f.result()

        assert not errors
        assert checker.total_checks == 8 * 25

    def test_concurrent_audit_integrity(self, _minimal_config):
        """All audit entries present and no corruption."""
        checker = PathSafetyChecker(_minimal_config)

        def worker(tid: int):
            for i in range(30):
                checker.check_path(f"t{tid}_f{i}.txt", 10, "write")

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(worker, t) for t in range(16)]
            for f in as_completed(futures):
                f.result()

        log = checker.audit_log
        assert len(log) == 16 * 30
        # Every entry has a valid path
        for entry in log:
            assert entry.path.endswith(".txt")
            assert entry.decision.is_allow


# =============================================================================
# Factory functions
# =============================================================================

class TestFactoryFunctions:
    def test_create_path_checker_from_spec(self):
        spec = {
            "verification_requirements": {
                "resource_constraints": {"max_file_size_bytes": 5_000_000},
                "safety_constraints": {
                    "allowed_extensions": [".txt", ".csv"],
                    "path_blocklist_patterns": [".*\\.env$"],
                },
            }
        }
        checker = create_path_checker_from_spec(spec, workspace_root="/tmp/ws")
        assert checker.config.workspace_root == "/tmp/ws"
        assert ".txt" in checker.config.allowed_extensions
        assert ".env" in checker.config.blocked_extensions
        assert checker.config.max_file_size == 5_000_000

    def test_create_file_operations_checker_with_spec(self):
        skills = Path(__file__).resolve().parent.parent / "skills"
        if not (skills / "file_operations" / "VERIFICATION.json").exists():
            pytest.skip("skills dir not found")
        checker = create_file_operations_checker(
            skills_dir=str(skills),
            workspace_root="/tmp/ws",
        )
        assert ".txt" in checker.config.allowed_extensions
        assert ".env" in checker.config.blocked_extensions

    def test_create_file_operations_checker_fallback(self, tmp_path):
        """Falls back to hardcoded defaults if spec not found."""
        checker = create_file_operations_checker(
            skills_dir=str(tmp_path / "nonexistent"),
            workspace_root="/tmp/ws",
        )
        assert ".txt" in checker.config.allowed_extensions
        assert ".csv" in checker.config.allowed_extensions
        assert ".env" in checker.config.blocked_extensions
        assert checker.config.max_file_size == 10_000_000


# =============================================================================
# VERIFICATION.json round-trip
# =============================================================================

class TestVerificationJsonRoundTrip:
    def test_full_spec_round_trip(self):
        """Load spec → create checker → decisions match expectations."""
        spec = {
            "skill_id": "file_operations",
            "verification_requirements": {
                "resource_constraints": {"max_file_size_bytes": 10_000_000},
                "safety_constraints": {
                    "allowed_extensions": [".txt", ".csv", ".json", ".md", ".pdf"],
                    "path_blocklist_patterns": [
                        ".*\\.env$", ".*\\.key$", ".*\\.pem$",
                    ],
                },
            },
        }
        checker = create_path_checker_from_spec(spec, "/tmp/ws")

        # Allowed
        assert checker.check_path("report.txt", 100, "write").is_allow
        assert checker.check_path("data.csv", 100, "write").is_allow
        assert checker.check_path("config.json", 100, "read").is_allow
        assert checker.check_path("readme.md", 100, "write").is_allow
        assert checker.check_path("doc.pdf", 100, "write").is_allow

        # Denied: blocked extensions
        assert checker.check_path("secrets.env", 100, "read").is_deny
        assert checker.check_path("server.key", 100, "read").is_deny
        assert checker.check_path("cert.pem", 100, "read").is_deny

        # Denied: not in allowlist
        assert checker.check_path("script.sh", 100, "write").is_deny
        assert checker.check_path("binary.exe", 100, "write").is_deny

        # Denied: traversal
        assert checker.check_path("../secret.txt", 100, "read").is_deny

        # Denied: oversize
        assert checker.check_path("huge.txt", 20_000_000, "write").is_deny


# =============================================================================
# Integration with FileReadTool / FileWriteTool
# =============================================================================

class TestFileToolIntegration:
    def test_decisions_align_with_file_write_tool(self):
        """
        Verify that PathSafetyChecker decisions agree with FileWriteTool's
        hardcoded checks for the same paths.
        """
        cfg = PathSafetyConfig(
            workspace_root="/tmp/ws",
            allowed_extensions=frozenset({".txt", ".csv", ".json", ".md", ".pdf"}),
            blocked_extensions=frozenset({".env", ".key", ".pem"}),
            max_file_size=10_000_000,
        )
        checker = PathSafetyChecker(cfg)

        # Paths that FileWriteTool would reject
        traversal_paths = ["../secret", "../../etc/passwd", "a/../../../b"]
        for p in traversal_paths:
            d = checker.check_path(p, 100, "write")
            assert d.is_deny, f"Expected deny for traversal: {p}"

        absolute_paths = ["/etc/passwd", "/tmp/outside"]
        for p in absolute_paths:
            d = checker.check_path(p, 100, "write")
            assert d.is_deny, f"Expected deny for absolute: {p}"

        home_paths = ["~/.ssh/id_rsa", "~/.bashrc"]
        for p in home_paths:
            d = checker.check_path(p, 100, "write")
            assert d.is_deny, f"Expected deny for home: {p}"

        # Paths that FileWriteTool would accept
        safe_paths = ["report.txt", "data/results.csv", "nested/deep/config.json"]
        for p in safe_paths:
            d = checker.check_path(p, 100, "write")
            assert d.is_allow, f"Expected allow for safe: {p}"


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases:
    def test_empty_path(self, _minimal_checker):
        d = _minimal_checker.check_path("", 100, "read")
        # Empty path has no traversal/absolute/home issues, empty extension
        assert d.is_allow

    def test_very_long_path(self, _minimal_checker):
        path = "a/" * 100 + "file.txt"
        d = _minimal_checker.check_path(path, 100, "write")
        assert d.is_allow

    def test_unicode_path(self, _minimal_checker):
        d = _minimal_checker.check_path("données/rapport.txt", 100, "write")
        assert d.is_allow

    def test_spaces_in_path(self, _minimal_checker):
        d = _minimal_checker.check_path("my documents/report.txt", 100, "write")
        assert d.is_allow

    def test_dotdot_in_directory_name(self):
        """A directory literally named '..foo' is not traversal,
        but our conservative check catches it. This is safe: false positives
        are acceptable for security."""
        cfg = PathSafetyConfig(workspace_root="/tmp", max_file_size=1000)
        d = check_path_safety("..foo/bar.txt", ".txt", 100, cfg)
        assert d.is_deny  # conservative - ".." substring detected

    def test_no_extension_with_empty_allowlist(self, _minimal_checker):
        d = _minimal_checker.check_path("Makefile", 100, "read")
        assert d.is_allow

    def test_no_extension_with_non_empty_allowlist(self, _fresh_checker):
        d = _fresh_checker.check_path("Makefile", 100, "read")
        assert d.is_deny  # "" not in allowlist

    def test_hidden_file_not_in_blocklist(self, _minimal_checker):
        d = _minimal_checker.check_path(".gitignore", 100, "read")
        assert d.is_allow

    def test_double_extension(self, _fresh_checker):
        # ".tar.gz" → extension is ".gz", not in allowlist
        d = _fresh_checker.check_path("archive.tar.gz", 100, "write")
        assert d.is_deny

    def test_path_with_query_like_chars(self, _minimal_checker):
        d = _minimal_checker.check_path("file?name=value.txt", 100, "write")
        assert d.is_allow

    def test_repr(self, _fresh_checker):
        r = repr(_fresh_checker)
        assert "PathSafetyChecker" in r
        assert "workspace=" in r

    def test_stats(self, _fresh_checker):
        _fresh_checker.check_path("a.txt", 10, "write")
        _fresh_checker.check_path("../evil", 10, "read")
        stats = _fresh_checker.get_stats()
        assert stats["total_checks"] == 2
        assert stats["total_allows"] == 1
        assert stats["total_denies"] == 1
        assert ".txt" in stats["allowed_extensions"]
        assert ".env" in stats["blocked_extensions"]

    def test_is_path_safe_convenience(self, _fresh_checker):
        assert _fresh_checker.is_path_safe("report.txt")
        assert not _fresh_checker.is_path_safe("../evil")
        # Convenience method does NOT add to audit
        assert _fresh_checker.total_checks == 0


# =============================================================================
# Full lifecycle (mirrors Dafny TestFullLifecycle)
# =============================================================================

class TestFullLifecycle:
    def test_lifecycle(self):
        """
        Comprehensive lifecycle test mirroring Dafny TestFullLifecycle.
        Uses config matching file_operations/VERIFICATION.json.
        """
        cfg = PathSafetyConfig(
            workspace_root="/tmp/certior_ws",
            allowed_extensions=frozenset({".txt", ".csv", ".json", ".md", ".pdf"}),
            blocked_extensions=frozenset({".env", ".key", ".pem"}),
            max_file_size=10_000_000,
        )
        checker = PathSafetyChecker(cfg)

        # ── Allowed paths ─────────────────────────────────────────
        a1 = checker.check_path("report.md", 500, "write")
        assert a1.is_allow

        a2 = checker.check_path("data/results.csv", 1000, "write")
        assert a2.is_allow

        a3 = checker.check_path("config.json", 200, "read")
        assert a3.is_allow

        assert checker.total_checks == 3

        # ── Denied: traversal (P35) ───────────────────────────────
        d1 = checker.check_path("../secret.txt", 100, "read")
        assert d1.is_deny

        # ── Denied: absolute (P36) ────────────────────────────────
        d2 = checker.check_path("/etc/shadow", 100, "read")
        assert d2.is_deny

        # ── Denied: home (P37) ────────────────────────────────────
        d3 = checker.check_path("~/.ssh/id_rsa", 100, "read")
        assert d3.is_deny

        # ── Denied: blocked extension (P39) ───────────────────────
        d4 = checker.check_path("secrets.env", 100, "read")
        assert d4.is_deny

        d5 = checker.check_path("server.key", 100, "read")
        assert d5.is_deny

        # ── Denied: not in allowlist (P38) ────────────────────────
        d6 = checker.check_path("script.sh", 100, "write")
        assert d6.is_deny

        # ── Denied: over size (P40) ───────────────────────────────
        d7 = checker.check_path("huge.txt", 20_000_000, "write")
        assert d7.is_deny

        # ── Audit complete (P43) ──────────────────────────────────
        assert checker.total_checks == 10
        assert len(checker.audit_log) == 10

        log = checker.audit_log
        # First three: Allow
        assert all(e.decision.is_allow for e in log[:3])
        # Next seven: Deny
        assert all(e.decision.is_deny for e in log[3:])

        # Paths recorded correctly
        assert log[0].path == "report.md"
        assert log[3].path == "../secret.txt"
        assert log[7].path == "server.key"
        assert log[9].path == "huge.txt"

        # Operations recorded
        assert log[0].operation == "write"
        assert log[3].operation == "read"

        # ── Config unchanged (P45) ────────────────────────────────
        assert checker.config is cfg

        # ── Invariant holds (P44) ─────────────────────────────────
        inv_log = InvariantAuditLog.get_instance()
        entries = inv_log.entries_for("PathSafetyChecker")
        assert all(e.passed for e in entries)

        # Stats
        stats = checker.get_stats()
        assert stats["total_allows"] == 3
        assert stats["total_denies"] == 7
