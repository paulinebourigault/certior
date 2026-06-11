from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from agentsafe.verification_graph.ingest import ingest_repository
from agentsafe.verification_graph.tools import VerificationGraphTools


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Certior verification graph ingest and query surface")
    parser.add_argument("--dsn", default=os.getenv("DATABASE_URL"), help="PostgreSQL DSN (defaults to DATABASE_URL)")
    parser.add_argument("--repo-root", default=str(Path.cwd()), help="Repository root path")
    parser.add_argument("--bridge", default="seccomp_dafny_bridge", help="Bridge used for alignment and impact validation")
    parser.add_argument("--output", help="Optional path for the JSON validation report")
    return parser


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.dsn:
        raise RuntimeError("PostgreSQL DSN is required; pass --dsn or set DATABASE_URL")

    repo_root = str(Path(args.repo_root).resolve())
    ingest_summary = await ingest_repository(args.dsn, repo_root)
    snapshot_id = ingest_summary["snapshot"]["id"]

    tools = VerificationGraphTools(args.dsn)
    repo_context = await tools.repo_context(repo_root, snapshot_id=snapshot_id)
    bridge_alignment = await tools.bridge_alignment(repo_root, args.bridge, snapshot_id=snapshot_id)
    proof_coverage = await tools.proof_coverage(repo_root, component_name=args.bridge, snapshot_id=snapshot_id)
    stale_verification = await tools.stale_verification(repo_root, snapshot_id=snapshot_id)
    runtime_evidence_freshness = await tools.runtime_evidence_freshness(repo_root, snapshot_id=snapshot_id)
    ingest_health = await tools.ingest_health(repo_root, snapshot_id=snapshot_id)
    release_attestation_readiness = await tools.release_attestation_readiness(repo_root, snapshot_id=snapshot_id)
    proof_impact = await tools.proof_impact(repo_root, args.bridge, subject_kind="bridge", snapshot_id=snapshot_id)
    component_count = sum(int(count) for count in repo_context["counts"].get("components_by_kind", {}).values())

    _require(repo_context["snapshot"]["id"] == snapshot_id, "repo_context did not resolve the ingested snapshot")
    _require(component_count > 0, "ingest produced no components")
    _require(bool(bridge_alignment["properties"]), f"bridge_alignment returned no properties for {args.bridge}")
    _require(bool(proof_coverage["rows"]), f"proof_coverage returned no rows for {args.bridge}")
    _require("counts" in stale_verification, "stale_verification did not return counts")
    _require("counts" in runtime_evidence_freshness, "runtime_evidence_freshness did not return counts")
    _require("counts" in ingest_health, "ingest_health did not return counts")
    _require("readiness" in release_attestation_readiness, "release_attestation_readiness did not return readiness")
    _require(bool(proof_impact["subject"]["matched_components"]), f"proof_impact did not match component {args.bridge}")

    report = {
        "snapshot_id": snapshot_id,
        "repo_context": repo_context,
        "bridge_alignment": bridge_alignment,
        "proof_coverage": proof_coverage,
        "stale_verification": stale_verification,
        "runtime_evidence_freshness": runtime_evidence_freshness,
        "ingest_health": ingest_health,
        "release_attestation_readiness": release_attestation_readiness,
        "proof_impact": proof_impact,
    }
    return report


def main() -> int:
    args = _parser().parse_args()
    report = asyncio.run(_run(args))
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())