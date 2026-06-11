"""Tests for ``load_step_capabilities_from_skill`` and
``load_step_capabilities_from_skills_dir``.

These tests parse real ``SKILL.md`` fixtures committed to
``tests/fixtures/openclaw_skills/``. They run in every environment,
with or without ``openclaw-sdk`` installed, because the loader has no
SDK dependency - it parses YAML frontmatter only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from certior.adapters import openclaw as adapter


_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "openclaw_skills"


# ── load_step_capabilities_from_skill ────────────────────────────────


def test_loader_reads_explicit_certior_capabilities() -> None:
    caps = adapter.load_step_capabilities_from_skill(_FIXTURES / "research" / "SKILL.md")
    assert caps == ["network:http:read"]


def test_loader_reads_multiple_capabilities_in_order() -> None:
    caps = adapter.load_step_capabilities_from_skill(_FIXTURES / "writer" / "SKILL.md")
    assert caps == ["filesystem:read", "filesystem:write"]


def test_loader_returns_empty_set_when_extension_absent(caplog: pytest.LogCaptureFixture) -> None:
    """A SKILL.md without ``metadata.certior.capabilities`` returns the
    empty set (most restrictive) and emits a warning so the developer
    sees that they have not declared anything."""
    with caplog.at_level("WARNING", logger="certior.adapters.openclaw"):
        caps = adapter.load_step_capabilities_from_skill(_FIXTURES / "legacy" / "SKILL.md")
    assert caps == []
    assert any(
        "metadata.certior.capabilities" in r.message for r in caplog.records
    )


def test_loader_raises_on_missing_frontmatter(tmp_path: Path) -> None:
    bad = tmp_path / "SKILL.md"
    bad.write_text("Just markdown without frontmatter\n")
    with pytest.raises(ValueError, match="no YAML frontmatter"):
        adapter.load_step_capabilities_from_skill(bad)


def test_loader_raises_on_malformed_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "SKILL.md"
    bad.write_text("---\nname: x\n  bad indent: [1, 2,\n---\n")
    with pytest.raises(ValueError, match="malformed YAML"):
        adapter.load_step_capabilities_from_skill(bad)


def test_loader_raises_on_non_list_capabilities(tmp_path: Path) -> None:
    bad = tmp_path / "SKILL.md"
    bad.write_text(
        "---\nname: x\nmetadata:\n  certior:\n    capabilities: not-a-list\n---\n"
    )
    with pytest.raises(ValueError, match="must be a list of strings"):
        adapter.load_step_capabilities_from_skill(bad)


def test_loader_raises_on_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        adapter.load_step_capabilities_from_skill(_FIXTURES / "does-not-exist" / "SKILL.md")


def test_loader_accepts_metadata_as_json_string(tmp_path: Path) -> None:
    """OpenClaw's documented form sometimes serialises ``metadata`` as a
    single-line JSON object. The loader must handle both."""
    fp = tmp_path / "SKILL.md"
    fp.write_text(
        '---\n'
        'name: json-meta\n'
        'description: Has stringified metadata\n'
        'metadata: \'{"certior": {"capabilities": ["x:y"]}}\'\n'
        '---\n'
    )
    assert adapter.load_step_capabilities_from_skill(fp) == ["x:y"]


# ── load_step_capabilities_from_skills_dir ───────────────────────────


def test_dir_loader_builds_step_capabilities_keyed_by_name() -> None:
    """Default behaviour: key by the ``name`` field from each frontmatter."""
    mapping = adapter.load_step_capabilities_from_skills_dir(_FIXTURES)
    assert mapping == {
        "research": ["network:http:read"],
        "writer": ["filesystem:read", "filesystem:write"],
        "legacy": [],
    }


def test_dir_loader_can_key_by_dirname() -> None:
    """Alternate behaviour: key by the containing directory name."""
    mapping = adapter.load_step_capabilities_from_skills_dir(
        _FIXTURES, step_name_from="dirname"
    )
    assert set(mapping.keys()) == {"research", "writer", "legacy"}
    assert mapping["research"] == ["network:http:read"]


def test_dir_loader_rejects_non_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "not_a_dir.txt"
    file_path.write_text("x")
    with pytest.raises(NotADirectoryError):
        adapter.load_step_capabilities_from_skills_dir(file_path)


def test_dir_loader_returns_empty_for_dir_with_no_skills(tmp_path: Path) -> None:
    """A directory with no ``*/SKILL.md`` returns an empty mapping."""
    (tmp_path / "no-skills").mkdir()
    assert adapter.load_step_capabilities_from_skills_dir(tmp_path) == {}
