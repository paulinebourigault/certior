from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

from .models import ComponentRecord, DeclarationRecord, GraphEdgeRecord, IngestIssueRecord, stable_id


def _component_id(kind: str, name: str) -> str:
    return stable_id("component", kind, name)


def extract_lean_metadata(
    repo_root: str | Path,
    manifest: dict[str, Any],
) -> tuple[list[ComponentRecord], list[DeclarationRecord], list[GraphEdgeRecord], list[IngestIssueRecord]]:
    root = Path(repo_root)
    packages = manifest.get("packages", [])
    components: list[ComponentRecord] = []
    declarations: list[DeclarationRecord] = []
    edges: list[GraphEdgeRecord] = []
    issues: list[IngestIssueRecord] = []

    for package in packages:
        package_name = package["package"]
        command = package["command"]
        workdir = root / package["workdir"]
        package_id = _component_id("lean_package", package_name)
        components.append(
            ComponentRecord(
                id=package_id,
                name=package_name,
                display_name=package_name,
                kind="lean_package",
                language="lean",
                source_path=package["workdir"],
                metadata={
                    "runtime_critical": bool(package.get("runtime_critical", False)),
                    "root_module": package.get("root_module"),
                },
            )
        )
        result = subprocess.run(
            command,
            cwd=workdir,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            issues.append(
                IngestIssueRecord(
                    id=stable_id("issue", package_name, "lean_export_failed"),
                    severity="warning",
                    code="lean_export_failed",
                    message=result.stderr.strip() or result.stdout.strip() or "Lean exporter failed",
                    path=package["workdir"],
                    metadata={"command": command},
                )
            )
            continue
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            issues.append(
                IngestIssueRecord(
                    id=stable_id("issue", package_name, "lean_export_invalid_json"),
                    severity="warning",
                    code="lean_export_invalid_json",
                    message=str(exc),
                    path=package["workdir"],
                    metadata={"command": command},
                )
            )
            continue
        for module in payload.get("modules", []):
            module_name = module["name"]
            module_id = _component_id("lean_module", module_name)
            components.append(
                ComponentRecord(
                    id=module_id,
                    name=module_name,
                    display_name=module_name.split(".")[-1],
                    kind="lean_module",
                    language="lean",
                    source_path=str(Path(package["workdir"]) / module["sourcePath"]),
                    metadata={
                        "sorry_count": module.get("sorryCount", 0),
                        "module_family": module.get("moduleFamily"),
                        "dependency_modules": module.get("dependencyModules", []),
                        "theorem_families": module.get("theoremFamilies", []),
                    },
                )
            )
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "DECLARES", package_name, module_name),
                    edge_type="DECLARES",
                    source_ref=package_name,
                    source_kind="component",
                    target_ref=module_name,
                    target_kind="component",
                    provenance_kind="lean_export",
                )
            )
            for imported in module.get("imports", []):
                edges.append(
                    GraphEdgeRecord(
                        id=stable_id("edge", "IMPORTS", module_name, imported),
                        edge_type="IMPORTS",
                        source_ref=module_name,
                        source_kind="component",
                        target_ref=imported,
                        target_kind="lean_module",
                        provenance_kind="lean_export",
                    )
                )
            for decl in module.get("declarations", []):
                qualified_name = f"{module_name}.{decl['name']}"
                declarations.append(
                    DeclarationRecord(
                        id=stable_id("declaration", qualified_name, module["sourcePath"]),
                        component_id=module_id,
                        qualified_name=qualified_name,
                        kind=decl["kind"],
                        language="lean",
                        source_path=str(Path(package["workdir"]) / module["sourcePath"]),
                        line_start=None,
                        line_end=None,
                        metadata={
                            "theorem_family": decl.get("theoremFamily"),
                            "dependency_modules": decl.get("dependencyModules", []),
                        },
                    )
                )
                edges.append(
                    GraphEdgeRecord(
                        id=stable_id("edge", "DECLARES", module_name, qualified_name),
                        edge_type="DECLARES",
                        source_ref=module_name,
                        source_kind="component",
                        target_ref=qualified_name,
                        target_kind="declaration",
                        provenance_kind="lean_export",
                    )
                )
        for binary in payload.get("binaries", []):
            binary_name = binary["name"]
            components.append(
                ComponentRecord(
                    id=_component_id("lean_binary", binary_name),
                    name=binary_name,
                    display_name=binary_name,
                    kind="lean_binary",
                    language="lean",
                    source_path=binary.get("rootModule"),
                    metadata={
                        "root_module": binary.get("rootModule"),
                        "runtime_critical": bool(binary.get("runtimeCritical", False)),
                        "dependency_modules": binary.get("dependencyModules", []),
                    },
                )
            )
            edges.append(
                GraphEdgeRecord(
                    id=stable_id("edge", "BUILDS_BINARY", package_name, binary_name),
                    edge_type="BUILDS_BINARY",
                    source_ref=package_name,
                    source_kind="component",
                    target_ref=binary_name,
                    target_kind="component",
                    provenance_kind="lean_export",
                    metadata={"root_module": binary.get("rootModule")},
                )
            )

    return components, declarations, edges, issues