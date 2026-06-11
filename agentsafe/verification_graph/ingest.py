from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any

from .git import inspect_repo, list_tracked_files, sha256_for_file
from .lean_adapter import extract_lean_metadata
from .manifest import load_manifests
from .models import (
    ComponentRecord,
    GraphEdgeRecord,
    IngestIssueRecord,
    ProofArtifactRecord,
    SnapshotBundle,
    SourceFileRecord,
    VerifiedPropertyRecord,
    classify_language,
    stable_id,
)
from .python_adapter import extract_python_metadata
from .runtime_adapter import extract_runtime_metadata
from .store import PgVerificationGraphStore


def _unique_by_id(rows):
    ordered = OrderedDict()
    for row in rows:
        ordered[getattr(row, "id")] = row
    return list(ordered.values())


def _build_source_file_records(repo_root: Path, tracked_files: list[str]) -> list[SourceFileRecord]:
    records: list[SourceFileRecord] = []
    for rel_path in tracked_files:
        abs_path = repo_root / rel_path
        records.append(
            SourceFileRecord(
                id=stable_id("source_file", rel_path),
                path=rel_path,
                sha256=sha256_for_file(abs_path),
                language=classify_language(rel_path),
                size_bytes=abs_path.stat().st_size,
                metadata={},
            )
        )
    return records


def _components_from_manifest(manifests: dict[str, dict[str, Any]]) -> tuple[list[ComponentRecord], list[VerifiedPropertyRecord], list[ProofArtifactRecord], list[GraphEdgeRecord]]:
    components: list[ComponentRecord] = []
    properties: list[VerifiedPropertyRecord] = []
    proof_artifacts: list[ProofArtifactRecord] = []
    edges: list[GraphEdgeRecord] = []

    for component in manifests["components"].get("components", []):
        component_id = stable_id("component", component["kind"], component["id"])
        components.append(
            ComponentRecord(
                id=component_id,
                name=component["id"],
                display_name=component.get("display_name", component["id"]),
                kind=component["kind"],
                language=component["language"],
                source_path=component.get("source_path"),
                metadata={
                    "phase": component.get("phase"),
                    "proof_family": component.get("proof_family"),
                    "runtime_critical": bool(component.get("runtime_critical", False)),
                    "module": component.get("module"),
                    "bounded_calls": component.get("bounded_calls", []),
                },
            )
        )
        for test_path in component.get("tests", []):
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "TESTS", component["id"], test_path),
                    edge_type="TESTS",
                    source_ref=component["id"],
                    source_kind="component",
                    target_ref=test_path,
                    target_kind="test",
                    provenance_kind="curated_manifest",
                )
            )

    for evidence in manifests["evidence_types"].get("evidence_types", []):
        artifact_key = evidence["id"]
        proof_artifacts.append(
            ProofArtifactRecord(
                id=stable_id("proof_artifact", artifact_key),
                artifact_key=artifact_key,
                name=evidence["name"],
                proof_system=evidence["proof_system"],
                source_path=None,
                metadata={
                    "artifact_type": evidence["artifact_type"],
                    "description": evidence.get("description"),
                },
            )
        )

    for alignment in manifests["dafny_alignment"].get("alignments", []):
        model_ref = alignment["model_component"]
        bridge_ref = alignment["bridge_component"]
        for prop in alignment.get("properties", []):
            properties.append(
                VerifiedPropertyRecord(
                    id=stable_id("property", prop),
                    property_key=prop,
                    name=prop,
                    proof_system="dafny",
                    source_path=alignment["dafny_file"],
                    metadata={
                        "alignment": alignment["id"],
                        "property_family": alignment.get("property_family"),
                        "logical_module": alignment.get("logical_module"),
                        "bridge_component": bridge_ref,
                        "model_component": model_ref,
                        "evidence_types": alignment.get("evidence_types", []),
                        "release_attestation_components": alignment.get("release_attestation_components", []),
                        "release_attestation_properties": alignment.get("release_attestation_properties", []),
                        "related_tests": alignment.get("related_tests", []),
                        "runtime_entrypoints": alignment.get("runtime_entrypoints", []),
                    },
                )
            )
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "IMPLEMENTS_PROPERTY", bridge_ref, prop),
                    edge_type="IMPLEMENTS_PROPERTY",
                    source_ref=bridge_ref,
                    source_kind="component",
                    target_ref=prop,
                    target_kind="verified_property",
                    provenance_kind="curated_manifest",
                )
            )
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "PROVES", model_ref, prop),
                    edge_type="PROVES",
                    source_ref=model_ref,
                    source_kind="component",
                    target_ref=prop,
                    target_kind="verified_property",
                    provenance_kind="curated_manifest",
                )
            )
        edges.append(
            GraphEdgeRecord(
                id=stable_id("edge", "MIRRORS_MODEL", bridge_ref, model_ref),
                edge_type="MIRRORS_MODEL",
                source_ref=bridge_ref,
                source_kind="component",
                target_ref=model_ref,
                target_kind="component",
                provenance_kind="curated_manifest",
                metadata={
                    "dafny_file": alignment["dafny_file"],
                    "evidence_types": alignment.get("evidence_types", []),
                    "logical_module": alignment.get("logical_module"),
                    "property_family": alignment.get("property_family"),
                },
            )
        )
        for evidence_type in alignment.get("evidence_types", []):
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "EXPORTS_EVIDENCE", bridge_ref, evidence_type),
                    edge_type="EXPORTS_EVIDENCE",
                    source_ref=bridge_ref,
                    source_kind="component",
                    target_ref=evidence_type,
                    target_kind="proof_artifact",
                    provenance_kind="curated_manifest",
                    metadata={"alignment": alignment["id"]},
                )
            )
        for test_path in alignment.get("related_tests", []):
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "TESTS", model_ref, test_path),
                    edge_type="TESTS",
                    source_ref=model_ref,
                    source_kind="component",
                    target_ref=test_path,
                    target_kind="test",
                    provenance_kind="curated_manifest",
                    metadata={"alignment": alignment["id"]},
                )
            )
        for entrypoint in alignment.get("runtime_entrypoints", []):
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "CONFIGURES", bridge_ref, entrypoint),
                    edge_type="CONFIGURES",
                    source_ref=bridge_ref,
                    source_kind="component",
                    target_ref=entrypoint,
                    target_kind="component",
                    provenance_kind="curated_manifest",
                    metadata={"alignment": alignment["id"]},
                )
            )

    return _unique_by_id(components), _unique_by_id(properties), _unique_by_id(proof_artifacts), _unique_by_id(edges)


async def ingest_repository(dsn: str, repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    repo = inspect_repo(root)
    manifests = load_manifests(root)
    tracked_files = list_tracked_files(root)
    if not tracked_files:
        raise RuntimeError("no tracked files found; commit or stage repository content before ingest")

    source_files = _build_source_file_records(root, tracked_files)
    manifest_components, manifest_properties, proof_artifacts, manifest_edges = _components_from_manifest(manifests)
    py_components, py_declarations, py_edges, py_issues = extract_python_metadata(
        root,
        tracked_files,
        manifests["components"],
    )
    lean_components, lean_declarations, lean_edges, lean_issues = extract_lean_metadata(root, manifests["lean_exports"])
    runtime = await extract_runtime_metadata(dsn)

    issues: list[IngestIssueRecord] = []
    issues.extend(py_issues)
    issues.extend(lean_issues)
    issues.extend(runtime["issues"])

    bundle = SnapshotBundle(
        files=_unique_by_id(source_files),
        components=_unique_by_id(manifest_components + py_components + lean_components),
        declarations=_unique_by_id(py_declarations + lean_declarations),
        properties=_unique_by_id(manifest_properties + runtime["properties"]),
        proof_artifacts=_unique_by_id(proof_artifacts),
        runtime_artifacts=_unique_by_id(runtime["runtime_artifacts"]),
        execution_artifacts=_unique_by_id(runtime["execution_artifacts"]),
        policy_profiles=_unique_by_id(runtime["policy_profiles"]),
        workflow_profiles=_unique_by_id(runtime["workflow_profiles"]),
        edges=_unique_by_id(manifest_edges + py_edges + lean_edges + runtime["edges"]),
        issues=_unique_by_id(issues),
        metadata={
            "tracked_file_count": len(tracked_files),
            "manifests_loaded": sorted(manifests.keys()),
            "runtime_execution_count": len(runtime["execution_artifacts"]),
            "runtime_workflow_count": len(runtime["workflow_profiles"]),
        },
    )

    store = PgVerificationGraphStore(dsn)
    await store.initialize()
    try:
        snapshot_id = await store.store_snapshot(repo, bundle)
        summary = await store.repo_context(repo.root_path)
        summary["snapshot"]["id"] = snapshot_id
        return summary
    finally:
        await store.close()