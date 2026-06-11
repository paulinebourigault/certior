from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from .ingest import ingest_repository
from .tools import VerificationGraphTools


def _add_snapshot_selectors(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--snapshot-id", help="Select an explicit ingest snapshot id")
    parser.add_argument("--commit-sha", help="Select the latest snapshot for a specific commit sha")


def _load_json_metadata(value: str | None) -> dict | None:
    if not value:
        return None
    return json.loads(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Certior verification graph CLI")
    parser.add_argument("--dsn", default=os.getenv("DATABASE_URL"), help="PostgreSQL DSN (defaults to DATABASE_URL)")
    parser.add_argument("--repo-root", default=str(Path.cwd()), help="Repository root path")

    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="Ingest the repository into the verification graph")
    ingest.add_argument("--repo", dest="repo_override", help="Override repo root path")

    repo_context = sub.add_parser("repo-context", help="Read repo_context")
    repo_context.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(repo_context)

    promote_snapshot = sub.add_parser("promote-snapshot", help="Mark a snapshot as promoted or attested with release metadata")
    promote_snapshot.add_argument("--repo", dest="repo_override", help="Override repo root path")
    promote_snapshot.add_argument("--status", choices=["promoted", "attested"], default="attested")
    promote_snapshot.add_argument("--release-label", help="Human-readable release or attestation label")
    promote_snapshot.add_argument("--metadata-json", help="JSON metadata to persist with the promotion record")
    _add_snapshot_selectors(promote_snapshot)

    snapshot_compare = sub.add_parser("snapshot-compare", help="Compare a snapshot against an explicit or latest-attested baseline")
    snapshot_compare.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(snapshot_compare)
    snapshot_compare.add_argument("--baseline-snapshot-id", help="Explicit baseline snapshot id")
    snapshot_compare.add_argument("--baseline-commit-sha", help="Select the latest baseline snapshot for a specific commit sha")

    component_context = sub.add_parser("component-context", help="Read component_context")
    component_context.add_argument("component_name")
    component_context.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(component_context)

    bridge_alignment = sub.add_parser("bridge-alignment", help="Read bridge_alignment")
    bridge_alignment.add_argument("bridge_name")
    bridge_alignment.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(bridge_alignment)

    workflow_lineage = sub.add_parser("workflow-lineage", help="Read workflow lineage and stage/execution provenance")
    workflow_lineage.add_argument("workflow_name")
    workflow_lineage.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(workflow_lineage)

    proof_coverage = sub.add_parser("proof-coverage", help="Read proof coverage derived view")
    proof_coverage.add_argument("--component", dest="component_name", help="Filter to one component")
    proof_coverage.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(proof_coverage)

    stale_verification = sub.add_parser("stale-verification", help="Read stale verification derived view")
    stale_verification.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(stale_verification)

    ingest_health = sub.add_parser("ingest-health", help="Read operator-facing ingest health derived view")
    ingest_health.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(ingest_health)

    runtime_evidence_freshness = sub.add_parser("runtime-evidence-freshness", help="Read runtime evidence freshness derived view")
    runtime_evidence_freshness.add_argument("--property", dest="property_key", help="Filter to one verified property")
    runtime_evidence_freshness.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(runtime_evidence_freshness)

    release_readiness = sub.add_parser("release-attestation-readiness", help="Read release attestation readiness derived view")
    release_readiness.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(release_readiness)

    proof_runtime_trace = sub.add_parser("proof-runtime-trace", help="Read proof-to-runtime trace derived view")
    proof_runtime_trace.add_argument("--property", dest="property_key", help="Filter to one verified property")
    proof_runtime_trace.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(proof_runtime_trace)

    proof_impact = sub.add_parser("proof-impact", help="Explain runtime, policy, and evidence impact for a file, component, bridge, or property")
    proof_impact.add_argument("subject")
    proof_impact.add_argument("--kind", choices=["auto", "file", "component", "bridge", "property"], default="auto")
    proof_impact.add_argument("--repo", dest="repo_override", help="Override repo root path")
    _add_snapshot_selectors(proof_impact)

    return parser


async def _run(args: argparse.Namespace) -> int:
    if not args.dsn:
        raise RuntimeError("PostgreSQL DSN is required; pass --dsn or set DATABASE_URL")
    repo_root = getattr(args, "repo_override", None) or args.repo_root
    if args.command == "ingest":
        payload = await ingest_repository(args.dsn, repo_root)
    else:
        tools = VerificationGraphTools(args.dsn)
        selection = {
            "snapshot_id": getattr(args, "snapshot_id", None),
            "commit_sha": getattr(args, "commit_sha", None),
        }
        if args.command == "repo-context":
            payload = await tools.repo_context(repo_root, **selection)
        elif args.command == "promote-snapshot":
            payload = await tools.promote_snapshot(
                repo_root,
                status=args.status,
                release_label=args.release_label,
                metadata=_load_json_metadata(args.metadata_json),
                **selection,
            )
        elif args.command == "snapshot-compare":
            payload = await tools.snapshot_compare(
                repo_root,
                baseline_snapshot_id=args.baseline_snapshot_id,
                baseline_commit_sha=args.baseline_commit_sha,
                **selection,
            )
        elif args.command == "component-context":
            payload = await tools.component_context(repo_root, args.component_name, **selection)
        elif args.command == "bridge-alignment":
            payload = await tools.bridge_alignment(repo_root, args.bridge_name, **selection)
        elif args.command == "workflow-lineage":
            payload = await tools.workflow_lineage(repo_root, args.workflow_name, **selection)
        elif args.command == "proof-coverage":
            payload = await tools.proof_coverage(repo_root, component_name=args.component_name, **selection)
        elif args.command == "stale-verification":
            payload = await tools.stale_verification(repo_root, **selection)
        elif args.command == "ingest-health":
            payload = await tools.ingest_health(repo_root, **selection)
        elif args.command == "runtime-evidence-freshness":
            payload = await tools.runtime_evidence_freshness(repo_root, property_key=args.property_key, **selection)
        elif args.command == "release-attestation-readiness":
            payload = await tools.release_attestation_readiness(repo_root, **selection)
        elif args.command == "proof-runtime-trace":
            payload = await tools.proof_runtime_trace(repo_root, property_key=args.property_key, **selection)
        elif args.command == "proof-impact":
            payload = await tools.proof_impact(repo_root, args.subject, subject_kind=args.kind, **selection)
        else:
            raise RuntimeError(f"unknown command: {args.command}")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main() -> int:
    args = _parser().parse_args()
    return asyncio.run(_run(args))


def main_ingest() -> int:
    parser = _parser()
    args = parser.parse_args(["ingest", *os.sys.argv[1:]])
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())