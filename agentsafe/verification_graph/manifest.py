from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REQUIRED_MANIFESTS = {
    "components": "verification/manifest/components.yaml",
    "dafny_alignment": "verification/manifest/dafny_alignment.yaml",
    "lean_exports": "verification/manifest/lean_exports.yaml",
    "evidence_types": "verification/manifest/evidence_types.yaml",
}


class ManifestError(RuntimeError):
    pass


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ManifestError(f"missing manifest: {path}")
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ManifestError(f"manifest must decode to an object: {path}")
    return loaded


def _require_string_list(value: Any, *, manifest_name: str, field_name: str, item_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ManifestError(f"{manifest_name}: {field_name} for {item_name} must be a list of non-empty strings")
    return value


def _validate_components_manifest(manifest: dict[str, Any]) -> None:
    components = manifest.get("components")
    if not isinstance(components, list):
        raise ManifestError("components manifest must contain a 'components' list")
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("id"), str):
            raise ManifestError("components manifest entries must be objects with an 'id'")
        _require_string_list(
            component.get("tests"),
            manifest_name="components manifest",
            field_name="tests",
            item_name=component["id"],
        )
        _require_string_list(
            component.get("bounded_calls"),
            manifest_name="components manifest",
            field_name="bounded_calls",
            item_name=component["id"],
        )


def _validate_dafny_alignment_manifest(manifest: dict[str, Any]) -> None:
    alignments = manifest.get("alignments")
    if not isinstance(alignments, list):
        raise ManifestError("dafny_alignment manifest must contain an 'alignments' list")
    for alignment in alignments:
        if not isinstance(alignment, dict) or not isinstance(alignment.get("id"), str):
            raise ManifestError("dafny_alignment manifest entries must be objects with an 'id'")
        name = alignment["id"]
        _require_string_list(alignment.get("properties"), manifest_name="dafny_alignment manifest", field_name="properties", item_name=name)
        _require_string_list(alignment.get("evidence_types"), manifest_name="dafny_alignment manifest", field_name="evidence_types", item_name=name)
        _require_string_list(alignment.get("related_tests"), manifest_name="dafny_alignment manifest", field_name="related_tests", item_name=name)
        _require_string_list(
            alignment.get("release_attestation_components"),
            manifest_name="dafny_alignment manifest",
            field_name="release_attestation_components",
            item_name=name,
        )
        _require_string_list(
            alignment.get("release_attestation_properties"),
            manifest_name="dafny_alignment manifest",
            field_name="release_attestation_properties",
            item_name=name,
        )
        _require_string_list(
            alignment.get("runtime_entrypoints"),
            manifest_name="dafny_alignment manifest",
            field_name="runtime_entrypoints",
            item_name=name,
        )
        for field_name in ("logical_module", "property_family"):
            value = alignment.get(field_name)
            if value is not None and not isinstance(value, str):
                raise ManifestError(f"dafny_alignment manifest: {field_name} for {name} must be a string when present")


def _validate_manifests(manifests: dict[str, dict[str, Any]]) -> None:
    _validate_components_manifest(manifests["components"])
    _validate_dafny_alignment_manifest(manifests["dafny_alignment"])


def load_manifests(repo_root: str | Path) -> dict[str, dict[str, Any]]:
    root = Path(repo_root)
    manifests: dict[str, dict[str, Any]] = {}
    for key, rel_path in REQUIRED_MANIFESTS.items():
        manifests[key] = _load_yaml(root / rel_path)
    _validate_manifests(manifests)
    return manifests