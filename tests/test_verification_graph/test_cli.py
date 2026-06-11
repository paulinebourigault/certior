from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agentsafe.verification_graph import cli


@pytest.mark.asyncio
async def test_run_ingest_uses_repo_root_without_repo_override(monkeypatch, capsys) -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "ingest",
        ]
    )

    ingest_mock = AsyncMock(return_value={"ok": True, "repo_root": "/tmp/certior-repo"})
    monkeypatch.setattr(cli, "ingest_repository", ingest_mock)

    exit_code = await cli._run(args)

    assert exit_code == 0
    ingest_mock.assert_awaited_once_with("postgresql://certior:certior@localhost:5432/certior", "/tmp/certior-repo")
    assert '"ok": true' in capsys.readouterr().out


def test_parser_accepts_ingest_repo_override() -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/default-repo",
            "ingest",
            "--repo",
            "/tmp/override-repo",
        ]
    )

    assert args.repo_override == "/tmp/override-repo"


def test_parser_accepts_snapshot_selectors_for_repo_context() -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "repo-context",
            "--snapshot-id",
            "snapshot-123",
            "--commit-sha",
            "abcdef1234",
        ]
    )

    assert args.snapshot_id == "snapshot-123"
    assert args.commit_sha == "abcdef1234"


def test_parser_accepts_snapshot_promotion_and_baseline_selectors() -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "promote-snapshot",
            "--snapshot-id",
            "snapshot-123",
            "--status",
            "promoted",
            "--release-label",
            "candidate-1",
            "--metadata-json",
            '{"channel": "staging"}',
        ]
    )

    assert args.command == "promote-snapshot"
    assert args.snapshot_id == "snapshot-123"
    assert args.status == "promoted"
    assert args.release_label == "candidate-1"
    assert args.metadata_json == '{"channel": "staging"}'


def test_parser_accepts_snapshot_compare_baseline_selectors() -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "snapshot-compare",
            "--snapshot-id",
            "snapshot-456",
            "--baseline-commit-sha",
            "abcdef1234",
        ]
    )

    assert args.command == "snapshot-compare"
    assert args.snapshot_id == "snapshot-456"
    assert args.baseline_commit_sha == "abcdef1234"


def test_parser_accepts_proof_impact_command() -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "proof-impact",
            "seccomp_dafny_bridge",
            "--kind",
            "bridge",
            "--commit-sha",
            "abcdef1234",
        ]
    )

    assert args.command == "proof-impact"
    assert args.subject == "seccomp_dafny_bridge"
    assert args.kind == "bridge"
    assert args.commit_sha == "abcdef1234"


def test_parser_accepts_ingest_health_and_runtime_freshness_commands() -> None:
    ingest_health_args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "ingest-health",
            "--snapshot-id",
            "snapshot-123",
        ]
    )
    freshness_args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "runtime-evidence-freshness",
            "--property",
            "P47",
            "--commit-sha",
            "abcdef1234",
        ]
    )

    assert ingest_health_args.command == "ingest-health"
    assert ingest_health_args.snapshot_id == "snapshot-123"
    assert freshness_args.command == "runtime-evidence-freshness"
    assert freshness_args.property_key == "P47"
    assert freshness_args.commit_sha == "abcdef1234"


@pytest.mark.asyncio
async def test_run_proof_impact_passes_snapshot_selection(monkeypatch, capsys) -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "proof-impact",
            "flow_safe",
            "--kind",
            "property",
            "--snapshot-id",
            "snapshot-123",
        ]
    )

    tools = SimpleNamespace(
        proof_impact=AsyncMock(return_value={"tool": "proof_impact", "risk_flags": []}),
    )
    monkeypatch.setattr(cli, "VerificationGraphTools", lambda dsn: tools)

    exit_code = await cli._run(args)

    assert exit_code == 0
    tools.proof_impact.assert_awaited_once_with(
        "/tmp/certior-repo",
        "flow_safe",
        subject_kind="property",
        snapshot_id="snapshot-123",
        commit_sha=None,
    )
    assert '"tool": "proof_impact"' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_promote_snapshot_passes_release_metadata(monkeypatch, capsys) -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "promote-snapshot",
            "--snapshot-id",
            "snapshot-123",
            "--status",
            "attested",
            "--release-label",
            "release-2025-03-10",
            "--metadata-json",
            '{"channel": "prod"}',
        ]
    )

    tools = SimpleNamespace(
        promote_snapshot=AsyncMock(return_value={"tool": "promote_snapshot", "promotion": {"status": "attested"}}),
    )
    monkeypatch.setattr(cli, "VerificationGraphTools", lambda dsn: tools)

    exit_code = await cli._run(args)

    assert exit_code == 0
    tools.promote_snapshot.assert_awaited_once_with(
        "/tmp/certior-repo",
        snapshot_id="snapshot-123",
        commit_sha=None,
        status="attested",
        release_label="release-2025-03-10",
        metadata={"channel": "prod"},
    )
    assert '"tool": "promote_snapshot"' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_snapshot_compare_passes_baseline_selection(monkeypatch, capsys) -> None:
    args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "snapshot-compare",
            "--snapshot-id",
            "snapshot-456",
            "--baseline-snapshot-id",
            "snapshot-123",
        ]
    )

    tools = SimpleNamespace(
        snapshot_compare=AsyncMock(return_value={"tool": "snapshot_compare", "baseline": {"id": "snapshot-123"}}),
    )
    monkeypatch.setattr(cli, "VerificationGraphTools", lambda dsn: tools)

    exit_code = await cli._run(args)

    assert exit_code == 0
    tools.snapshot_compare.assert_awaited_once_with(
        "/tmp/certior-repo",
        snapshot_id="snapshot-456",
        commit_sha=None,
        baseline_snapshot_id="snapshot-123",
        baseline_commit_sha=None,
    )
    assert '"tool": "snapshot_compare"' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_ingest_health_and_runtime_freshness_pass_selection(monkeypatch, capsys) -> None:
    ingest_args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "ingest-health",
            "--snapshot-id",
            "snapshot-123",
        ]
    )
    freshness_args = cli._parser().parse_args(
        [
            "--dsn",
            "postgresql://certior:certior@localhost:5432/certior",
            "--repo-root",
            "/tmp/certior-repo",
            "runtime-evidence-freshness",
            "--property",
            "P47",
            "--commit-sha",
            "abcdef1234",
        ]
    )

    tools = SimpleNamespace(
        ingest_health=AsyncMock(return_value={"tool": "ingest_health", "counts": {"blocking": 0}}),
        runtime_evidence_freshness=AsyncMock(return_value={"tool": "runtime_evidence_freshness", "counts": {"fresh": 1}}),
    )
    monkeypatch.setattr(cli, "VerificationGraphTools", lambda dsn: tools)

    ingest_exit_code = await cli._run(ingest_args)
    freshness_exit_code = await cli._run(freshness_args)

    assert ingest_exit_code == 0
    assert freshness_exit_code == 0
    tools.ingest_health.assert_awaited_once_with(
        "/tmp/certior-repo",
        snapshot_id="snapshot-123",
        commit_sha=None,
    )
    tools.runtime_evidence_freshness.assert_awaited_once_with(
        "/tmp/certior-repo",
        property_key="P47",
        snapshot_id=None,
        commit_sha="abcdef1234",
    )
    output = capsys.readouterr().out
    assert '"tool": "ingest_health"' in output
    assert '"tool": "runtime_evidence_freshness"' in output