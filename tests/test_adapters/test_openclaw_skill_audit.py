"""Tests for ``certior.adapters.openclaw_skill_audit``.

These tests use the same SKILL.md fixtures the loader tests use
(``tests/fixtures/openclaw_skills/{research,writer,legacy}/SKILL.md``)
so the audit behaviour is grounded in real frontmatter shapes, not
synthetic strings.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from certior import Guard
from certior.adapters.openclaw_skill_audit import (
    SkillAuditResult,
    audit_skill,
    audit_skills_dir,
    skill_fingerprint,
)
from certior.adapters.openclaw_skill_audit_cli import main as cli_main


FIXTURE_ROOT = Path(__file__).parent.parent / "fixtures" / "openclaw_skills"
RESEARCH = FIXTURE_ROOT / "research" / "SKILL.md"
WRITER = FIXTURE_ROOT / "writer" / "SKILL.md"
LEGACY = FIXTURE_ROOT / "legacy" / "SKILL.md"


# ── Fingerprint ───────────────────────────────────────────────────────


def test_fingerprint_is_sha256_of_bytes() -> None:
    expected = hashlib.sha256(RESEARCH.read_bytes()).hexdigest()
    assert skill_fingerprint(RESEARCH) == expected


def test_fingerprint_changes_when_file_changes(tmp_path: Path) -> None:
    a = tmp_path / "SKILL.md"
    a.write_text(
        "---\nname: x\nmetadata:\n  certior:\n    capabilities: [a]\n---\nbody\n"
    )
    fp1 = skill_fingerprint(a)
    a.write_text(
        "---\nname: x\nmetadata:\n  certior:\n    capabilities: [a]\n---\nbody!\n"
    )
    fp2 = skill_fingerprint(a)
    assert fp1 != fp2


# ── audit_skill ───────────────────────────────────────────────────────


def test_audit_passes_when_declared_subset_of_parent() -> None:
    guard = Guard(
        permissions=["network:http:read", "filesystem:read"],
        budget_cents=0,
    )
    result = audit_skill(RESEARCH, guard)
    assert result.passed is True
    assert result.declared_capabilities == ["network:http:read"]
    assert result.missing_capabilities == []
    assert result.declared_no_capabilities is False
    assert result.reasons == []


def test_audit_fails_when_capability_outside_parent() -> None:
    guard = Guard(permissions=["filesystem:read"], budget_cents=0)
    result = audit_skill(RESEARCH, guard)
    assert result.passed is False
    assert "network:http:read" in result.missing_capabilities
    assert any("capability_not_in_parent" in r for r in result.reasons)


def test_audit_passes_with_wildcard_parent() -> None:
    guard = Guard(permissions=["*"], budget_cents=0)
    result = audit_skill(WRITER, guard)
    assert result.passed is True
    assert result.missing_capabilities == []


def test_audit_undeclared_fails_closed_by_default() -> None:
    guard = Guard(permissions=["*"], budget_cents=0)
    result = audit_skill(LEGACY, guard)
    assert result.passed is False
    assert result.declared_no_capabilities is True
    assert any("no metadata.certior.capabilities" in r for r in result.reasons)


def test_audit_undeclared_passes_with_allow_undeclared() -> None:
    guard = Guard(permissions=["filesystem:read"], budget_cents=0)
    result = audit_skill(LEGACY, guard, allow_undeclared=True)
    assert result.passed is True
    assert result.declared_capabilities == []
    assert result.declared_no_capabilities is True


def test_audit_fingerprint_match_passes() -> None:
    guard = Guard(permissions=["network:http:read"], budget_cents=0)
    fp = skill_fingerprint(RESEARCH)
    result = audit_skill(RESEARCH, guard, expected_fingerprint=fp)
    assert result.passed is True
    assert result.fingerprint_matches is True
    assert result.expected_fingerprint == fp


def test_audit_fingerprint_mismatch_fails() -> None:
    guard = Guard(permissions=["network:http:read"], budget_cents=0)
    wrong = "0" * 64
    result = audit_skill(RESEARCH, guard, expected_fingerprint=wrong)
    assert result.passed is False
    assert result.fingerprint_matches is False
    assert any("fingerprint_mismatch" in r for r in result.reasons)


def test_audit_skill_name_falls_back_to_dirname(tmp_path: Path) -> None:
    skill_dir = tmp_path / "unnamed"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nmetadata:\n  certior:\n    capabilities: [a]\n---\nbody\n"
    )
    guard = Guard(permissions=["a"], budget_cents=0)
    result = audit_skill(skill_dir / "SKILL.md", guard)
    assert result.skill_name == "unnamed"


def test_audit_raises_on_missing_frontmatter(tmp_path: Path) -> None:
    bad = tmp_path / "SKILL.md"
    bad.write_text("just a body, no frontmatter\n")
    guard = Guard(permissions=["*"], budget_cents=0)
    with pytest.raises(ValueError):
        audit_skill(bad, guard)


def test_audit_result_as_dict_round_trips_through_json() -> None:
    guard = Guard(permissions=["network:http:read"], budget_cents=0)
    result = audit_skill(RESEARCH, guard)
    encoded = json.dumps(result.as_dict())
    decoded = json.loads(encoded)
    assert decoded["skill_name"] == "research"
    assert decoded["passed"] is True


# ── audit_skills_dir ──────────────────────────────────────────────────


def test_audit_skills_dir_returns_one_result_per_skill() -> None:
    guard = Guard(
        permissions=["network:http:read", "filesystem:read", "filesystem:write"],
        budget_cents=0,
    )
    results = audit_skills_dir(FIXTURE_ROOT, guard)
    names = {r.skill_name for r in results}
    assert names == {"research", "writer", "legacy"}


def test_audit_skills_dir_fingerprint_pin_by_skill_name() -> None:
    guard = Guard(
        permissions=["network:http:read", "filesystem:read", "filesystem:write"],
        budget_cents=0,
    )
    pins = {"research": skill_fingerprint(RESEARCH)}
    results = audit_skills_dir(FIXTURE_ROOT, guard, expected_fingerprints=pins)
    research = next(r for r in results if r.skill_name == "research")
    writer = next(r for r in results if r.skill_name == "writer")
    assert research.expected_fingerprint == pins["research"]
    assert research.fingerprint_matches is True
    assert writer.expected_fingerprint is None  # no pin for writer


def test_audit_skills_dir_raises_when_not_a_directory(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "missing"
    guard = Guard(permissions=["*"], budget_cents=0)
    with pytest.raises(NotADirectoryError):
        audit_skills_dir(not_a_dir, guard)


# ── CLI ───────────────────────────────────────────────────────────────


def test_cli_passes_on_valid_skill(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_main(
        [
            str(RESEARCH),
            "--permission",
            "network:http:read",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "[PASS] research" in out


def test_cli_fails_on_capability_outside_parent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(RESEARCH),
            "--permission",
            "filesystem:read",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "[FAIL] research" in out
    assert "capability_not_in_parent" in out


def test_cli_fails_without_permission_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main([str(RESEARCH)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "--permission" in err


def test_cli_directory_mode_audits_every_skill(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(FIXTURE_ROOT),
            "--permission",
            "*",
            "--allow-undeclared",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "research" in out
    assert "writer" in out
    assert "legacy" in out
    assert "3 pass" in out


def test_cli_directory_mode_legacy_fails_without_allow_undeclared(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(FIXTURE_ROOT),
            "--permission",
            "*",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "[FAIL] legacy" in out


def test_cli_json_output_is_parseable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(RESEARCH),
            "--permission",
            "network:http:read",
            "--json",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    decoded = json.loads(out)
    assert isinstance(decoded, list)
    assert decoded[0]["passed"] is True
    assert decoded[0]["skill_name"] == "research"


def test_cli_fingerprint_pin_match_passes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fp = skill_fingerprint(RESEARCH)
    rc = cli_main(
        [
            str(RESEARCH),
            "--permission",
            "network:http:read",
            "--expected-fingerprint",
            f"research={fp}",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "pin:      ok" in out


def test_cli_fingerprint_pin_mismatch_fails(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(RESEARCH),
            "--permission",
            "network:http:read",
            "--expected-fingerprint",
            "research=" + ("0" * 64),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "fingerprint_mismatch" in out


def test_cli_rejects_malformed_fingerprint_pair(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        cli_main(
            [
                str(RESEARCH),
                "--permission",
                "network:http:read",
                "--expected-fingerprint",
                "research=not-a-sha",
            ]
        )


def test_cli_rejects_nonexistent_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_main(
        [
            str(tmp_path / "nope.md"),
            "--permission",
            "*",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 2
    assert "neither a file nor a directory" in err
