from __future__ import annotations

from pathlib import Path

from agentsafe.verification_graph.python_adapter import extract_python_metadata


def test_extract_python_metadata_discovers_top_level_declarations(tmp_path: Path) -> None:
    pkg = tmp_path / "agentsafe" / "demo"
    pkg.mkdir(parents=True)
    file_path = pkg / "sample.py"
    file_path.write_text(
        "import json\n"
        "from agentsafe.kernel import certificate\n\n"
        "class Demo:\n"
        "    pass\n\n"
        "def run() -> None:\n"
        "    return None\n",
        encoding="utf-8",
    )

    components, declarations, edges, issues = extract_python_metadata(
        tmp_path,
        ["agentsafe/demo/sample.py"],
    )

    assert not issues
    assert any(component.name == "agentsafe.demo.sample" for component in components)
    assert {decl.qualified_name for decl in declarations} == {
        "agentsafe.demo.sample.Demo",
        "agentsafe.demo.sample.run",
    }
    assert any(edge.edge_type == "IMPORTS" and edge.target_ref == "json" for edge in edges)


def test_extract_python_metadata_emits_bounded_calls_for_manifest_selected_components(tmp_path: Path) -> None:
    pkg = tmp_path / "agentsafe" / "sandbox"
    pkg.mkdir(parents=True)
    file_path = pkg / "seccomp_verified.py"
    file_path.write_text(
        "from agentsafe.sandbox import seccomp_policy\n\n"
        "def enforce() -> None:\n"
        "    seccomp_policy.compile_program()\n"
        "    seccomp_policy.render_bpf()\n",
        encoding="utf-8",
    )

    components, declarations, edges, issues = extract_python_metadata(
        tmp_path,
        ["agentsafe/sandbox/seccomp_verified.py"],
        {
            "components": [
                {
                    "id": "seccomp_verified_bridge",
                    "source_path": "agentsafe/sandbox/seccomp_verified.py",
                    "bounded_calls": ["agentsafe.sandbox.seccomp_policy"],
                }
            ]
        },
    )

    assert not issues
    assert any(component.name == "agentsafe.sandbox.seccomp_verified" for component in components)
    assert any(decl.qualified_name == "agentsafe.sandbox.seccomp_verified.enforce" for decl in declarations)
    call_targets = {edge.target_ref for edge in edges if edge.edge_type == "CALLS"}
    assert call_targets == {
        "agentsafe.sandbox.seccomp_policy.compile_program",
        "agentsafe.sandbox.seccomp_policy.render_bpf",
    }