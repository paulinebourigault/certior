"""
Dafny-Verified URL Filter & Tool Enforcement - Comprehensive Tests.

Tests every property proven in ``dafny/tools/url_filter.dfy``:

  P22  Allowlist completeness - Accept only if allowlist match exists
  P23  Blocklist correctness - Blocklist match always produces Reject
  P24  Blocklist precedence - Blocklist wins over allowlist
  P25  Filter determinism - Same (url, config) → same decision
  P26  Empty allowlist rejects all
  P27  Empty blocklist defers to allowlist
  P28  Blocklist monotonicity - Adding blocklist entries reduces accepts
  P29  Rate limit enforcement - request_count bounded by max_rpm
  P30  Audit completeness - Every check_url appends exactly one entry
  P31  Invariant preservation - Valid() holds at every method boundary
  P32  Rate limit reset correctness
  P33  Config immutability - config frozen after construction

Also tests:
  - Pattern matching (prefix, suffix, contains, exact, any)
  - Thread safety under concurrent operations
  - Audit trail completeness via InvariantAuditLog
  - Factory functions (from_verification_json, create_web_browsing_filter)
  - Edge cases (empty config, single pattern, unicode URLs, etc.)
  - Integration with existing WebFetchTool constraints
  - from_regex pattern classification
"""
from __future__ import annotations

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from agentsafe.tools.url_filter_verified import (
    AuditEntry,
    FilterDecision,
    PatternKind,
    UrlFilter,
    UrlFilterConfig,
    UrlPattern,
    create_url_filter_from_spec,
    create_web_browsing_filter,
    filter_url,
    matches_any,
    matches_none,
)
from agentsafe.verification.dafny_runtime import (
    InvariantAuditLog,
    InvariantViolation,
    PreconditionViolation,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_audit_log():
    """Reset the global audit log between tests."""
    InvariantAuditLog.reset()
    yield
    InvariantAuditLog.reset()


def _web_browsing_config() -> UrlFilterConfig:
    """Config matching skills/web_browsing/VERIFICATION.json."""
    return UrlFilterConfig(
        allowlist=(
            UrlPattern.prefix("https://"),
            UrlPattern.prefix("http://localhost"),
        ),
        blocklist=(
            UrlPattern.suffix(".onion"),
            UrlPattern.suffix(".gov"),
            UrlPattern.suffix(".mil"),
        ),
        max_requests_per_minute=60,
    )


def _fresh_filter(max_rpm: int = 60) -> UrlFilter:
    """Standard web_browsing filter for testing."""
    return UrlFilter(_web_browsing_config())


def _minimal_filter(
    allowlist: List[UrlPattern] | None = None,
    blocklist: List[UrlPattern] | None = None,
    max_rpm: int = 100,
) -> UrlFilter:
    """Custom filter for targeted tests."""
    cfg = UrlFilterConfig(
        allowlist=tuple(allowlist or []),
        blocklist=tuple(blocklist or []),
        max_requests_per_minute=max_rpm,
    )
    return UrlFilter(cfg)


# =============================================================================
# UrlPattern - matching correctness
# =============================================================================

class TestUrlPattern:
    """Test pattern matching mirrors Dafny predicates."""

    def test_prefix_match(self):
        p = UrlPattern.prefix("https://")
        assert p.matches("https://example.com")
        assert p.matches("https://")
        assert not p.matches("http://example.com")
        assert not p.matches("ftp://example.com")

    def test_suffix_match(self):
        p = UrlPattern.suffix(".onion")
        assert p.matches("https://hidden.onion")
        assert p.matches(".onion")
        assert not p.matches("https://onion.com")
        assert not p.matches("https://hidden.onions")

    def test_contains_match(self):
        p = UrlPattern.contains("localhost")
        assert p.matches("http://localhost:3000")
        assert p.matches("https://localhost/api")
        assert p.matches("localhost")
        assert not p.matches("https://example.com")

    def test_exact_match(self):
        p = UrlPattern.exact("https://api.example.com/v1")
        assert p.matches("https://api.example.com/v1")
        assert not p.matches("https://api.example.com/v2")
        assert not p.matches("https://api.example.com/v1/extra")
        assert not p.matches("https://api.example.com")

    def test_any_match(self):
        p = UrlPattern.any_pattern()
        assert p.matches("")
        assert p.matches("anything")
        assert p.matches("https://example.com")
        assert p.matches("ftp://files.net/path?q=1")

    def test_prefix_empty_matches_all(self):
        p = UrlPattern.prefix("")
        assert p.matches("")
        assert p.matches("anything")

    def test_suffix_empty_matches_all(self):
        p = UrlPattern.suffix("")
        assert p.matches("")
        assert p.matches("anything")

    def test_from_regex_prefix(self):
        p = UrlPattern.from_regex("^https://.*")
        assert p.kind == PatternKind.PREFIX
        assert p.matches("https://example.com")
        assert not p.matches("http://example.com")

    def test_from_regex_suffix_onion(self):
        p = UrlPattern.from_regex(r".*\.onion(/.*)?$")
        assert p.matches("https://hidden.onion")
        assert p.matches("https://hidden.onion/path")

    def test_from_regex_suffix_gov(self):
        p = UrlPattern.from_regex(r".*\.gov(/.*)?$")
        assert p.matches("https://example.gov")
        assert p.matches("https://example.gov/page")

    def test_from_regex_suffix_mil(self):
        p = UrlPattern.from_regex(r".*\.mil(/.*)?$")
        assert p.matches("https://secret.mil")

    def test_from_regex_wildcard(self):
        p = UrlPattern.from_regex(".*")
        assert p.kind == PatternKind.ANY
        assert p.matches("anything")

    def test_pattern_str(self):
        assert "prefix" in str(UrlPattern.prefix("https://")).lower()
        assert "suffix" in str(UrlPattern.suffix(".onion")).lower()
        assert str(UrlPattern.any_pattern()) == "Any"

    def test_pattern_immutability(self):
        p = UrlPattern.prefix("https://")
        with pytest.raises(AttributeError):
            p.kind = PatternKind.SUFFIX  # type: ignore[misc]
        with pytest.raises(AttributeError):
            p.value = "changed"  # type: ignore[misc]


# =============================================================================
# FilterDecision
# =============================================================================

class TestFilterDecision:
    def test_accept(self):
        d = FilterDecision.accept()
        assert d.is_accept
        assert not d.is_reject
        assert d.reason == ""

    def test_reject(self):
        d = FilterDecision.reject("blocked")
        assert d.is_reject
        assert not d.is_accept
        assert d.reason == "blocked"

    def test_immutability(self):
        d = FilterDecision.accept()
        with pytest.raises(AttributeError):
            d.accepted = False  # type: ignore[misc]

    def test_str(self):
        assert "Accept" in str(FilterDecision.accept())
        assert "Reject" in str(FilterDecision.reject("reason"))
        assert "reason" in str(FilterDecision.reject("reason"))


# =============================================================================
# UrlFilterConfig (P33)
# =============================================================================

class TestUrlFilterConfig:
    def test_immutability(self):
        cfg = _web_browsing_config()
        with pytest.raises(AttributeError):
            cfg.max_requests_per_minute = 999  # type: ignore[misc]
        with pytest.raises(AttributeError):
            cfg.allowlist = ()  # type: ignore[misc]

    def test_coerce_list_to_tuple(self):
        cfg = UrlFilterConfig(
            allowlist=[UrlPattern.prefix("https://")],  # type: ignore[arg-type]
            blocklist=[UrlPattern.suffix(".onion")],  # type: ignore[arg-type]
        )
        assert isinstance(cfg.allowlist, tuple)
        assert isinstance(cfg.blocklist, tuple)

    def test_negative_rpm_raises(self):
        with pytest.raises(ValueError, match="max_requests_per_minute"):
            UrlFilterConfig(max_requests_per_minute=-1)

    def test_from_verification_json(self):
        spec = {
            "verification_requirements": {
                "safety_constraints": {
                    "url_allowlist_patterns": ["^https://.*", "^http://localhost.*"],
                    "url_blocklist_patterns": [r".*\.onion(/.*)?$", r".*\.gov(/.*)?$"],
                },
                "resource_constraints": {
                    "max_requests_per_minute": 30,
                },
            },
        }
        cfg = UrlFilterConfig.from_verification_json(spec)
        assert len(cfg.allowlist) == 2
        assert len(cfg.blocklist) == 2
        assert cfg.max_requests_per_minute == 30

    def test_from_verification_json_defaults(self):
        cfg = UrlFilterConfig.from_verification_json({})
        assert len(cfg.allowlist) == 0
        assert len(cfg.blocklist) == 0
        assert cfg.max_requests_per_minute == 60


# =============================================================================
# Pure filter function (P25 determinism)
# =============================================================================

class TestFilterUrlPure:
    """Tests for the pure filter_url function (specification)."""

    def test_accept_https(self):
        cfg = _web_browsing_config()
        d = filter_url("https://example.com", cfg)
        assert d.is_accept

    def test_reject_not_allowlisted(self):
        cfg = _web_browsing_config()
        d = filter_url("ftp://files.com", cfg)
        assert d.is_reject
        assert "allowlist" in d.reason.lower()

    def test_reject_blocklisted(self):
        cfg = _web_browsing_config()
        d = filter_url("https://evil.onion", cfg)
        assert d.is_reject
        assert "blocklist" in d.reason.lower()

    def test_determinism(self):
        """P25: Same input always produces same output."""
        cfg = _web_browsing_config()
        urls = [
            "https://example.com",
            "https://evil.onion",
            "http://insecure.com",
            "http://localhost:8080",
            "ftp://files.net",
        ]
        for url in urls:
            d1 = filter_url(url, cfg)
            d2 = filter_url(url, cfg)
            assert d1 == d2, f"Non-deterministic for {url}"

    def test_matches_any_helper(self):
        patterns = [UrlPattern.prefix("https://"), UrlPattern.prefix("http://localhost")]
        assert matches_any("https://example.com", patterns)
        assert matches_any("http://localhost:3000", patterns)
        assert not matches_any("ftp://files.com", patterns)

    def test_matches_none_helper(self):
        patterns = [UrlPattern.suffix(".onion"), UrlPattern.suffix(".gov")]
        assert matches_none("https://example.com", patterns)
        assert not matches_none("https://evil.onion", patterns)


# =============================================================================
# P22: ALLOWLIST COMPLETENESS
# =============================================================================

class TestP22AllowlistCompleteness:
    """Accept ONLY IF url matches at least one allowlist pattern."""

    def test_accept_requires_allowlist_match(self):
        f = _fresh_filter()
        d = f.check_url("https://example.com")
        assert d.is_accept
        assert matches_any("https://example.com", f.config.allowlist)

    def test_no_allowlist_match_rejects(self):
        f = _fresh_filter()
        d = f.check_url("ftp://files.com")
        assert d.is_reject
        assert not matches_any("ftp://files.com", f.config.allowlist)

    def test_http_not_in_allowlist(self):
        f = _fresh_filter()
        d = f.check_url("http://insecure.com")
        assert d.is_reject

    def test_localhost_in_allowlist(self):
        f = _fresh_filter()
        d = f.check_url("http://localhost:3000")
        assert d.is_accept

    def test_exhaustive_allowlist_matching(self):
        """Every Accept URL must match at least one allowlist pattern."""
        f = _fresh_filter()
        test_urls = [
            ("https://a.com", True),
            ("https://b.io/path", True),
            ("http://localhost:8080", True),
            ("http://localhost", True),
            ("http://example.com", False),
            ("ftp://files.net", False),
            ("ws://socket.io", False),
            ("", False),
        ]
        for url, should_accept in test_urls:
            d = f.check_url(url)
            if d.is_accept:
                assert matches_any(url, f.config.allowlist), \
                    f"P22 violated: {url} accepted without allowlist match"
            if should_accept:
                assert d.is_accept, f"Expected accept for {url}"
            else:
                assert d.is_reject, f"Expected reject for {url}"


# =============================================================================
# P23: BLOCKLIST CORRECTNESS
# =============================================================================

class TestP23BlocklistCorrectness:
    """Blocklist match always produces Reject."""

    def test_onion_blocked(self):
        f = _fresh_filter()
        d = f.check_url("https://hidden.onion")
        assert d.is_reject

    def test_gov_blocked(self):
        f = _fresh_filter()
        d = f.check_url("https://example.gov")
        assert d.is_reject

    def test_mil_blocked(self):
        f = _fresh_filter()
        d = f.check_url("https://classified.mil")
        assert d.is_reject

    def test_blocklist_match_always_rejects(self):
        """Exhaustive: every blocklisted URL is rejected."""
        f = _fresh_filter()
        blocked_urls = [
            "https://dark.onion",
            "https://some.gov",
            "https://any.mil",
        ]
        for url in blocked_urls:
            d = f.check_url(url)
            assert d.is_reject, f"P23 violated: {url} not rejected"
            assert matches_any(url, f.config.blocklist)


# =============================================================================
# P24: BLOCKLIST PRECEDENCE
# =============================================================================

class TestP24BlocklistPrecedence:
    """If URL matches BOTH allowlist and blocklist, Reject wins."""

    def test_https_gov_rejected(self):
        """https:// matches allowlist, .gov matches blocklist → Reject."""
        f = _fresh_filter()
        url = "https://example.gov"
        assert matches_any(url, f.config.allowlist), "Should match allowlist"
        assert matches_any(url, f.config.blocklist), "Should match blocklist"
        d = f.check_url(url)
        assert d.is_reject, "P24: blocklist must take precedence"

    def test_https_mil_rejected(self):
        f = _fresh_filter()
        url = "https://classified.mil"
        assert matches_any(url, f.config.allowlist)
        assert matches_any(url, f.config.blocklist)
        d = f.check_url(url)
        assert d.is_reject

    def test_https_onion_rejected(self):
        f = _fresh_filter()
        url = "https://hidden.onion"
        assert matches_any(url, f.config.allowlist)
        assert matches_any(url, f.config.blocklist)
        d = f.check_url(url)
        assert d.is_reject

    def test_blocklist_precedence_custom_patterns(self):
        """Custom config where same URL matches both lists."""
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            blocklist=[UrlPattern.contains("secret")],
        )
        d = f.check_url("https://secret.example.com")
        assert d.is_reject


# =============================================================================
# P25: FILTER DETERMINISM
# =============================================================================

class TestP25FilterDeterminism:
    """Same (url, config) always produces the same FilterDecision."""

    def test_repeated_calls_identical(self):
        f = _fresh_filter()
        url = "https://example.com"
        results = [f.check_url(url) for _ in range(10)]
        assert all(r.is_accept for r in results)

    def test_determinism_across_instances(self):
        url = "https://example.com"
        d1 = UrlFilter(_web_browsing_config()).check_url(url)
        d2 = UrlFilter(_web_browsing_config()).check_url(url)
        assert d1.accepted == d2.accepted
        assert d1.reason == d2.reason

    def test_determinism_reject(self):
        f = _fresh_filter()
        url = "https://evil.onion"
        results = [f.check_url(url) for _ in range(5)]
        assert all(r.is_reject for r in results)
        reasons = {r.reason for r in results}
        assert len(reasons) == 1


# =============================================================================
# P26: EMPTY ALLOWLIST REJECTS ALL
# =============================================================================

class TestP26EmptyAllowlistRejectsAll:
    """If allowlist is empty, no URL is accepted."""

    def test_empty_allowlist_rejects_everything(self):
        f = _minimal_filter(allowlist=[], blocklist=[])
        urls = [
            "https://example.com",
            "http://localhost",
            "ftp://files.net",
            "",
            "anything",
        ]
        for url in urls:
            d = f.check_url(url)
            assert d.is_reject, f"P26 violated: {url} accepted with empty allowlist"

    def test_empty_allowlist_with_blocklist(self):
        f = _minimal_filter(
            allowlist=[],
            blocklist=[UrlPattern.suffix(".onion")],
        )
        d = f.check_url("https://example.com")
        assert d.is_reject


# =============================================================================
# P27: EMPTY BLOCKLIST DEFERS TO ALLOWLIST
# =============================================================================

class TestP27EmptyBlocklistDefersToAllowlist:
    """If blocklist is empty, acceptance depends only on allowlist."""

    def test_empty_blocklist_accepts_allowlisted(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.prefix("https://")],
            blocklist=[],
        )
        d = f.check_url("https://example.com")
        assert d.is_accept

    def test_empty_blocklist_rejects_non_allowlisted(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.prefix("https://")],
            blocklist=[],
        )
        d = f.check_url("http://example.com")
        assert d.is_reject

    def test_empty_blocklist_gov_accepted(self):
        """With no blocklist, .gov URLs matching allowlist pass."""
        f = _minimal_filter(
            allowlist=[UrlPattern.prefix("https://")],
            blocklist=[],
        )
        d = f.check_url("https://example.gov")
        assert d.is_accept  # no blocklist → allowlist decides


# =============================================================================
# P28: BLOCKLIST MONOTONICITY
# =============================================================================

class TestP28BlocklistMonotonicity:
    """Adding blocklist entries can only reduce accepted URLs."""

    def test_adding_non_matching_blocklist_preserves_accept(self):
        cfg1 = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(UrlPattern.suffix(".onion"),),
        )
        cfg2 = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(UrlPattern.suffix(".onion"), UrlPattern.suffix(".mil")),
        )
        url = "https://example.com"
        d1 = filter_url(url, cfg1)
        d2 = filter_url(url, cfg2)
        assert d1.is_accept
        assert d2.is_accept  # new pattern doesn't match → still accepted

    def test_adding_matching_blocklist_causes_reject(self):
        cfg1 = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(),
        )
        cfg2 = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(UrlPattern.suffix(".com"),),
        )
        url = "https://example.com"
        d1 = filter_url(url, cfg1)
        d2 = filter_url(url, cfg2)
        assert d1.is_accept
        assert d2.is_reject  # new pattern matches → now rejected

    def test_monotonicity_systematic(self):
        """Adding blocklist entries never turns Reject→Accept."""
        base_cfg = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(UrlPattern.suffix(".onion"),),
        )
        extended_cfg = UrlFilterConfig(
            allowlist=(UrlPattern.prefix("https://"),),
            blocklist=(
                UrlPattern.suffix(".onion"),
                UrlPattern.suffix(".gov"),
                UrlPattern.suffix(".mil"),
            ),
        )
        test_urls = [
            "https://example.com",
            "https://evil.onion",
            "https://example.gov",
            "http://insecure.com",
        ]
        for url in test_urls:
            d_base = filter_url(url, base_cfg)
            d_extended = filter_url(url, extended_cfg)
            if d_base.is_reject:
                assert d_extended.is_reject, \
                    f"P28 violated: {url} was Reject, became Accept after adding blocklist"


# =============================================================================
# P29: RATE LIMIT ENFORCEMENT
# =============================================================================

class TestP29RateLimitEnforcement:
    """request_count bounded by max_rpm; excess requests rejected."""

    def test_under_limit_accepted(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=5,
        )
        for i in range(5):
            d = f.check_url(f"https://site{i}.com")
            assert d.is_accept
            assert f.request_count == i + 1

    def test_at_limit_rejected(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=3,
        )
        f.check_url("https://a.com")
        f.check_url("https://b.com")
        f.check_url("https://c.com")
        assert f.request_count == 3

        d = f.check_url("https://d.com")
        assert d.is_reject
        assert "rate limit" in d.reason.lower()
        assert f.request_count == 3  # unchanged on reject

    def test_reject_doesnt_increment_count(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.prefix("https://")],
            blocklist=[UrlPattern.suffix(".onion")],
            max_rpm=100,
        )
        f.check_url("https://evil.onion")  # rejected by blocklist
        assert f.request_count == 0

        f.check_url("ftp://files.com")  # rejected by allowlist
        assert f.request_count == 0

    def test_rate_limit_zero(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=0,
        )
        d = f.check_url("https://example.com")
        assert d.is_reject
        assert f.request_count == 0

    def test_request_count_bounded(self):
        """request_count never exceeds max_rpm."""
        max_rpm = 5
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=max_rpm,
        )
        for i in range(max_rpm * 3):
            f.check_url(f"https://site{i}.com")
            assert f.request_count <= max_rpm


# =============================================================================
# P30: AUDIT COMPLETENESS
# =============================================================================

class TestP30AuditCompleteness:
    """Every check_url appends exactly one AuditEntry."""

    def test_single_check_one_entry(self):
        f = _fresh_filter()
        assert len(f.audit_log) == 0
        f.check_url("https://example.com")
        assert len(f.audit_log) == 1

    def test_multiple_checks_sequential_entries(self):
        f = _fresh_filter()
        urls = [
            "https://a.com",
            "https://evil.onion",
            "ftp://bad.com",
            "http://localhost:3000",
        ]
        for i, url in enumerate(urls):
            f.check_url(url)
            assert len(f.audit_log) == i + 1

    def test_entry_records_url(self):
        f = _fresh_filter()
        f.check_url("https://target.com")
        assert f.audit_log[0].url == "https://target.com"

    def test_entry_records_decision(self):
        f = _fresh_filter()
        d = f.check_url("https://example.com")
        assert f.audit_log[0].decision == d

    def test_append_only(self):
        """Previous entries are never modified."""
        f = _fresh_filter()
        f.check_url("https://first.com")
        first_entry = f.audit_log[0]

        f.check_url("https://second.com")
        assert f.audit_log[0].url == first_entry.url
        assert f.audit_log[0].decision == first_entry.decision

    def test_rate_limited_request_also_audited(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=1,
        )
        f.check_url("https://first.com")
        f.check_url("https://rate-limited.com")
        assert len(f.audit_log) == 2
        assert f.audit_log[1].url == "https://rate-limited.com"
        assert f.audit_log[1].decision.is_reject

    def test_entry_has_timestamp(self):
        before = time.time()
        f = _fresh_filter()
        f.check_url("https://example.com")
        after = time.time()
        assert before <= f.audit_log[0].timestamp <= after


# =============================================================================
# P31: INVARIANT PRESERVATION
# =============================================================================

class TestP31InvariantPreservation:
    """Valid() holds at every method boundary."""

    def test_valid_after_construction(self):
        f = _fresh_filter()
        assert f._valid()

    def test_valid_after_accept(self):
        f = _fresh_filter()
        f.check_url("https://example.com")
        assert f._valid()

    def test_valid_after_reject(self):
        f = _fresh_filter()
        f.check_url("https://evil.onion")
        assert f._valid()

    def test_valid_after_rate_limit(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=1,
        )
        f.check_url("https://a.com")
        f.check_url("https://b.com")  # rate limited
        assert f._valid()

    def test_valid_after_reset(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=2,
        )
        f.check_url("https://a.com")
        f.check_url("https://b.com")
        f.reset_rate_limit()
        assert f._valid()

    def test_audit_log_records_all_invariant_checks(self):
        """InvariantAuditLog captures pre/post checks for every method."""
        f = _fresh_filter()
        f.check_url("https://example.com")

        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("UrlFilter")
        # Constructor post + check_url pre + check_url post = 3
        assert len(entries) >= 3
        assert all(e.passed for e in entries), "All invariant checks should pass"

    def test_invariant_check_phases(self):
        f = _fresh_filter()
        f.check_url("https://example.com")

        log = InvariantAuditLog.get_instance()
        entries = log.entries_for("UrlFilter", "check_url")
        phases = {e.phase for e in entries}
        assert "pre" in phases
        assert "post" in phases


# =============================================================================
# P32: RATE LIMIT RESET CORRECTNESS
# =============================================================================

class TestP32RateLimitReset:
    """After reset_rate_limit(): request_count == 0, audit preserved."""

    def test_reset_zeroes_count(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=5,
        )
        f.check_url("https://a.com")
        f.check_url("https://b.com")
        assert f.request_count == 2

        f.reset_rate_limit()
        assert f.request_count == 0

    def test_reset_preserves_audit(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=5,
        )
        f.check_url("https://a.com")
        f.check_url("https://b.com")
        log_before = f.audit_log

        f.reset_rate_limit()
        log_after = f.audit_log
        assert log_after == log_before

    def test_reset_preserves_config(self):
        cfg = _web_browsing_config()
        f = UrlFilter(cfg)
        f.check_url("https://example.com")
        f.reset_rate_limit()
        assert f.config is cfg

    def test_reset_then_accept(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=1,
        )
        f.check_url("https://a.com")  # count=1
        d = f.check_url("https://b.com")  # rate limited
        assert d.is_reject

        f.reset_rate_limit()
        d = f.check_url("https://c.com")
        assert d.is_accept
        assert f.request_count == 1


# =============================================================================
# P33: CONFIG IMMUTABILITY
# =============================================================================

class TestP33ConfigImmutability:
    """Config never changes after construction."""

    def test_config_unchanged_after_accept(self):
        cfg = _web_browsing_config()
        f = UrlFilter(cfg)
        f.check_url("https://example.com")
        assert f.config is cfg

    def test_config_unchanged_after_reject(self):
        cfg = _web_browsing_config()
        f = UrlFilter(cfg)
        f.check_url("https://evil.onion")
        assert f.config is cfg

    def test_config_unchanged_after_reset(self):
        cfg = _web_browsing_config()
        f = UrlFilter(cfg)
        f.reset_rate_limit()
        assert f.config is cfg

    def test_config_frozen(self):
        cfg = _web_browsing_config()
        with pytest.raises(AttributeError):
            cfg.max_requests_per_minute = 999  # type: ignore[misc]


# =============================================================================
# Thread safety
# =============================================================================

class TestThreadSafety:
    """Concurrent operations maintain all invariants."""

    def test_concurrent_check_url(self):
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=1000,
        )
        n_threads = 8
        n_per_thread = 50
        results: List[FilterDecision] = []
        lock = threading.Lock()

        def worker(thread_id: int) -> None:
            for i in range(n_per_thread):
                d = f.check_url(f"https://t{thread_id}-{i}.com")
                with lock:
                    results.append(d)

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futures = [pool.submit(worker, t) for t in range(n_threads)]
            for fut in as_completed(futures):
                fut.result()  # raises if thread failed

        total = n_threads * n_per_thread
        assert len(results) == total
        assert f._valid()
        assert f.request_count <= f.config.max_requests_per_minute
        assert len(f.audit_log) == total

    def test_concurrent_rate_limit(self):
        """Under high concurrency, rate limit is never exceeded."""
        max_rpm = 20
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=max_rpm,
        )

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [
                pool.submit(f.check_url, f"https://site{i}.com")
                for i in range(100)
            ]
            for fut in as_completed(futures):
                fut.result()

        assert f.request_count <= max_rpm
        assert f._valid()

    def test_concurrent_reset_and_check(self):
        """Interleaved reset and check operations maintain invariant."""
        f = _minimal_filter(
            allowlist=[UrlPattern.any_pattern()],
            max_rpm=10,
        )
        errors: List[Exception] = []

        def checker() -> None:
            try:
                for i in range(20):
                    f.check_url(f"https://site{i}.com")
            except Exception as e:
                errors.append(e)

        def resetter() -> None:
            try:
                for _ in range(5):
                    time.sleep(0.001)
                    f.reset_rate_limit()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=checker),
            threading.Thread(target=resetter),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors in concurrent test: {errors}"
        assert f._valid()


# =============================================================================
# Factory functions
# =============================================================================

class TestFactoryFunctions:
    def test_create_url_filter_from_spec(self):
        spec = {
            "verification_requirements": {
                "safety_constraints": {
                    "url_allowlist_patterns": ["^https://.*"],
                    "url_blocklist_patterns": [r".*\.onion(/.*)?$"],
                },
                "resource_constraints": {
                    "max_requests_per_minute": 30,
                },
            },
        }
        f = create_url_filter_from_spec(spec)
        assert f._valid()
        assert f.config.max_requests_per_minute == 30

        d = f.check_url("https://example.com")
        assert d.is_accept

        d = f.check_url("https://evil.onion")
        assert d.is_reject

    def test_create_web_browsing_filter_with_spec(self):
        f = create_web_browsing_filter(
            skills_dir=str(Path(__file__).parent.parent / "skills")
        )
        assert f._valid()
        d = f.check_url("https://example.com")
        assert d.is_accept

    def test_create_web_browsing_filter_fallback(self):
        f = create_web_browsing_filter(skills_dir="/nonexistent")
        assert f._valid()
        d = f.check_url("https://example.com")
        assert d.is_accept
        d = f.check_url("https://evil.onion")
        assert d.is_reject


# =============================================================================
# Integration: VERIFICATION.json round-trip
# =============================================================================

class TestVerificationJsonRoundTrip:
    """Filter built from VERIFICATION.json produces correct decisions."""

    def test_web_browsing_spec_round_trip(self):
        spec_path = Path(__file__).parent.parent / "skills" / "web_browsing" / "VERIFICATION.json"
        if not spec_path.exists():
            pytest.skip("VERIFICATION.json not found")

        with open(spec_path) as fh:
            spec = json.load(fh)

        f = create_url_filter_from_spec(spec)

        # Allowed
        assert f.check_url("https://example.com").is_accept
        assert f.check_url("https://api.service.io").is_accept
        assert f.check_url("http://localhost:8080/api").is_accept

        # Blocked by blocklist
        assert f.check_url("https://evil.onion").is_reject
        assert f.check_url("https://secret.gov").is_reject
        assert f.check_url("https://classified.mil").is_reject

        # Blocked by missing allowlist
        assert f.check_url("ftp://files.com").is_reject
        assert f.check_url("http://insecure.com").is_reject


# =============================================================================
# Integration: WebFetchTool compatibility
# =============================================================================

class TestWebFetchToolCompatibility:
    """UrlFilter decisions match WebFetchTool._check_url behavior."""

    def test_decisions_align_with_web_fetch(self):
        """Verified filter should accept/reject same URLs as WebFetchTool."""
        f = create_web_browsing_filter(
            skills_dir=str(Path(__file__).parent.parent / "skills")
        )

        # These should match WebFetchTool behavior
        assert f.check_url("https://example.com").is_accept
        assert f.check_url("http://localhost:3000").is_accept
        assert f.check_url("ftp://files.com").is_reject
        assert f.check_url("http://insecure.com").is_reject


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases:
    def test_empty_url(self):
        f = _fresh_filter()
        d = f.check_url("")
        assert d.is_reject

    def test_very_long_url(self):
        f = _fresh_filter()
        url = "https://" + "a" * 10000 + ".com"
        d = f.check_url(url)
        assert d.is_accept

    def test_url_with_query_params(self):
        f = _fresh_filter()
        d = f.check_url("https://api.example.com/search?q=test&page=1")
        assert d.is_accept

    def test_url_with_fragment(self):
        f = _fresh_filter()
        d = f.check_url("https://example.com/page#section")
        assert d.is_accept

    def test_url_with_auth(self):
        f = _fresh_filter()
        d = f.check_url("https://user:pass@example.com/api")
        assert d.is_accept

    def test_single_allowlist_pattern(self):
        f = _minimal_filter(allowlist=[UrlPattern.exact("https://only.this.url")])
        assert f.check_url("https://only.this.url").is_accept
        assert f.check_url("https://anything.else").is_reject

    def test_wildcard_allowlist(self):
        f = _minimal_filter(allowlist=[UrlPattern.any_pattern()])
        assert f.check_url("literally-anything").is_accept

    def test_repr(self):
        f = _fresh_filter()
        r = repr(f)
        assert "UrlFilter" in r
        assert "allowlist" in r

    def test_is_url_allowed_convenience(self):
        f = _fresh_filter()
        assert f.is_url_allowed("https://example.com")
        assert not f.is_url_allowed("https://evil.onion")

    def test_get_stats(self):
        f = _fresh_filter()
        f.check_url("https://good.com")
        f.check_url("https://evil.onion")
        stats = f.get_stats()
        assert stats["request_count"] == 1
        assert stats["audit_entries"] == 2
        assert stats["total_accepts"] == 1
        assert stats["total_rejects"] == 1
        assert stats["allowlist_patterns"] == 2
        assert stats["blocklist_patterns"] == 3


# =============================================================================
# Full lifecycle (mirrors Dafny TestFullLifecycle)
# =============================================================================

class TestFullLifecycle:
    """End-to-end lifecycle matching Dafny integration test."""

    def test_full_lifecycle(self):
        cfg = UrlFilterConfig(
            allowlist=(
                UrlPattern.prefix("https://"),
                UrlPattern.prefix("http://localhost"),
            ),
            blocklist=(
                UrlPattern.suffix(".onion"),
                UrlPattern.suffix(".gov"),
                UrlPattern.suffix(".mil"),
            ),
            max_requests_per_minute=60,
        )
        f = UrlFilter(cfg)
        assert f._valid()
        assert f.request_count == 0
        assert len(f.audit_log) == 0

        # ── Allowed URLs ──────────────────────────────────────
        a1 = f.check_url("https://example.com")
        assert a1.is_accept

        a2 = f.check_url("https://api.service.io/data")
        assert a2.is_accept

        a3 = f.check_url("http://localhost:3000/api")
        assert a3.is_accept

        assert f.request_count == 3

        # ── Blocked by blocklist (P23, P24) ───────────────────
        b1 = f.check_url("https://hidden.onion")
        assert b1.is_reject

        b2 = f.check_url("https://secret.gov")
        assert b2.is_reject

        b3 = f.check_url("https://classified.mil")
        assert b3.is_reject

        assert f.request_count == 3  # rejects don't increment

        # ── Blocked by missing allowlist (P22) ────────────────
        c1 = f.check_url("ftp://files.com")
        assert c1.is_reject

        c2 = f.check_url("http://insecure.com")
        assert c2.is_reject

        assert f.request_count == 3

        # ── Audit trail complete (P30) ────────────────────────
        assert len(f.audit_log) == 8

        # ── Invariant holds throughout (P31) ──────────────────
        assert f._valid()

        # ── All audit entries recorded correctly ──────────────
        log = InvariantAuditLog.get_instance()
        all_entries = log.entries_for("UrlFilter")
        assert all(e.passed for e in all_entries)
