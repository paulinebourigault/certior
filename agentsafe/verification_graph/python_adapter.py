from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .models import ComponentRecord, DeclarationRecord, GraphEdgeRecord, IngestIssueRecord, stable_id


def _module_name_for(path: str) -> str:
    without_suffix = str(Path(path).with_suffix(""))
    return without_suffix.replace("/", ".")


def _target_is_bounded(target: str, allowed_targets: set[str]) -> bool:
    return any(target == candidate or target.startswith(f"{candidate}.") for candidate in allowed_targets)


def _resolve_call_target(
    expr: ast.expr,
    *,
    import_aliases: dict[str, str],
    local_symbols: dict[str, str],
) -> str | None:
    if isinstance(expr, ast.Name):
        return local_symbols.get(expr.id) or import_aliases.get(expr.id) or expr.id
    if isinstance(expr, ast.Attribute):
        base = _resolve_call_target(expr.value, import_aliases=import_aliases, local_symbols=local_symbols)
        if base:
            return f"{base}.{expr.attr}"
        return expr.attr
    if isinstance(expr, ast.Call):
        return _resolve_call_target(expr.func, import_aliases=import_aliases, local_symbols=local_symbols)
    return None


def _bounded_call_specs(components_manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not components_manifest:
        return {}
    specs: dict[str, dict[str, Any]] = {}
    for component in components_manifest.get("components", []):
        if not isinstance(component, dict):
            continue
        source_path = component.get("source_path")
        bounded_calls = component.get("bounded_calls") or []
        if not isinstance(source_path, str) or not bounded_calls:
            continue
        if not all(isinstance(target, str) and target for target in bounded_calls):
            continue
        specs[source_path] = {
            "component_id": component.get("id"),
            "allowed_targets": set(bounded_calls),
        }
    return specs


def extract_python_metadata(
    repo_root: str | Path,
    tracked_files: list[str],
    components_manifest: dict[str, Any] | None = None,
) -> tuple[list[ComponentRecord], list[DeclarationRecord], list[GraphEdgeRecord], list[IngestIssueRecord]]:
    root = Path(repo_root)
    components: list[ComponentRecord] = []
    declarations: list[DeclarationRecord] = []
    edges: list[GraphEdgeRecord] = []
    issues: list[IngestIssueRecord] = []
    call_specs = _bounded_call_specs(components_manifest)

    for rel_path in tracked_files:
        if not rel_path.endswith(".py"):
            continue
        if not rel_path.startswith(("agentsafe/", "app/", "certior/")):
            continue
        path = root / rel_path
        module_name = _module_name_for(rel_path)
        module_component_id = stable_id("component", "python_module", rel_path)
        components.append(
            ComponentRecord(
                id=module_component_id,
                name=module_name,
                display_name=module_name.split(".")[-1],
                kind="python_module",
                language="python",
                source_path=rel_path,
                metadata={"module": module_name},
            )
        )
        edges.append(
            GraphEdgeRecord(
                id=stable_id("edge", "DECLARES", rel_path, module_name),
                edge_type="DECLARES",
                source_ref=rel_path,
                source_kind="source_file",
                target_ref=module_name,
                target_kind="component",
                provenance_kind="static_python_ast",
            )
        )
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel_path)
        except SyntaxError as exc:
            issues.append(
                IngestIssueRecord(
                    id=stable_id("issue", rel_path, str(exc.lineno or 0), exc.msg),
                    severity="error",
                    code="python_syntax_error",
                    message=exc.msg,
                    path=rel_path,
                    metadata={"line": exc.lineno, "offset": exc.offset},
                )
            )
            continue

        import_aliases: dict[str, str] = {}
        local_symbols: dict[str, str] = {}
        top_level_declarations: list[tuple[str, ast.AST]] = []

        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = alias.name
                    import_aliases[alias.asname or alias.name.split(".")[0]] = imported
                    edges.append(
                        GraphEdgeRecord(
                            id=stable_id("edge", "IMPORTS", module_name, imported),
                            edge_type="IMPORTS",
                            source_ref=module_name,
                            source_kind="component",
                            target_ref=imported,
                            target_kind="python_module",
                            provenance_kind="static_python_ast",
                            metadata={"import_kind": "import"},
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        import_aliases[local_name] = f"{node.module}.{alias.name}"
                    edges.append(
                        GraphEdgeRecord(
                            id=stable_id("edge", "IMPORTS", module_name, node.module),
                            edge_type="IMPORTS",
                            source_ref=module_name,
                            source_kind="component",
                            target_ref=node.module,
                            target_kind="python_module",
                            provenance_kind="static_python_ast",
                            metadata={"import_kind": "from"},
                        )
                    )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                decl_kind = "class" if isinstance(node, ast.ClassDef) else "function"
                qualified_name = f"{module_name}.{node.name}"
                local_symbols[node.name] = qualified_name
                top_level_declarations.append((qualified_name, node))
                declarations.append(
                    DeclarationRecord(
                        id=stable_id("declaration", qualified_name, rel_path),
                        component_id=module_component_id,
                        qualified_name=qualified_name,
                        kind=decl_kind,
                        language="python",
                        source_path=rel_path,
                        line_start=getattr(node, "lineno", None),
                        line_end=getattr(node, "end_lineno", None),
                        metadata={},
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
                        provenance_kind="static_python_ast",
                    )
                )

        spec = call_specs.get(rel_path)
        if spec:
            allowed_targets = spec["allowed_targets"]
            for source_ref, node in top_level_declarations:
                for child in ast.walk(node):
                    if not isinstance(child, ast.Call):
                        continue
                    target = _resolve_call_target(child.func, import_aliases=import_aliases, local_symbols=local_symbols)
                    if not target or not _target_is_bounded(target, allowed_targets):
                        continue
                    edges.append(
                        GraphEdgeRecord(
                            id=stable_id("edge", "CALLS", source_ref, target, str(getattr(child, "lineno", 0))),
                            edge_type="CALLS",
                            source_ref=source_ref,
                            source_kind="declaration",
                            target_ref=target,
                            target_kind="symbol",
                            provenance_kind="static_python_ast",
                            metadata={
                                "line": getattr(child, "lineno", None),
                                "source_path": rel_path,
                                "bounded_component": spec.get("component_id"),
                            },
                        )
                    )

    return components, declarations, edges, issues