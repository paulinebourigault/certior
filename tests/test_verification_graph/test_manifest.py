from __future__ import annotations

from pathlib import Path

from agentsafe.verification_graph.manifest import load_manifests


def test_load_manifests_reads_required_files() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    manifests = load_manifests(repo_root)

    assert sorted(manifests.keys()) == [
        "components",
        "dafny_alignment",
        "evidence_types",
        "lean_exports",
    ]
    assert manifests["components"]["version"] == 1
    assert manifests["lean_exports"]["packages"][0]["package"] == "CertiorLattice"
    assert any(component.get("bounded_calls") for component in manifests["components"]["components"])
    assert all(
        isinstance(alignment.get("property_family"), str)
        for alignment in manifests["dafny_alignment"]["alignments"]
    )
    assert all(
        isinstance(alignment.get("release_attestation_components", []), list)
        for alignment in manifests["dafny_alignment"]["alignments"]
    )
    assert all(
        isinstance(alignment.get("release_attestation_properties", []), list)
        for alignment in manifests["dafny_alignment"]["alignments"]
    )