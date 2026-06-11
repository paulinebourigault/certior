"""
certior.adapters.openclaw_skill_audit - static skill audit.
===========================================================

A pre-install / pre-load audit for OpenClaw skills that proves the
skill's declared capability surface is a subset of a parent guard's
permissions **before** the skill is wired into a pipeline.

The check is intentionally narrow:

* **Relational, not heuristic.** Given a skill that declares
  ``metadata.certior.capabilities`` in its ``SKILL.md``, we check
  ``declared ⊆ parent.permissions`` using the same subset rule
  ``GuardedPipeline`` runs at ``add_step`` time. The *soundness* of
  that rule is what Lean's ``delegationSafety`` theorem establishes
  offline; the auditor runs the rule statically against a skill so
  delegation safety can be assessed before the first call.

* **No source-code SAST.** This module does not regex skill code for
  dangerous patterns (``eval``, ``curl``, reverse shells, etc.). Tools
  that do that - for example ClawGuard's auditor
  (https://github.com/NY1024/ClawGuard) - are complementary: they
  scan the implementation; this scans the *capability claim*.

* **Fingerprint pinning.** The auditor records a SHA-256 of the
  ``SKILL.md`` file at audit time so a later run can detect that the
  skill has drifted from the version that was approved.

Public surface:

* :class:`SkillAuditResult`
* :func:`audit_skill`
* :func:`audit_skills_dir`
* :func:`skill_fingerprint`
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from certior.guard import Guard

__all__ = [
    "SkillAuditResult",
    "audit_skill",
    "audit_skills_dir",
    "skill_fingerprint",
]

log = logging.getLogger("certior.adapters.openclaw_skill_audit")


# ── Result type ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class SkillAuditResult:
    """Outcome of auditing one ``SKILL.md`` against a parent guard.

    Attributes:
        skill_path: Absolute path to the audited ``SKILL.md``.
        skill_name: Value of the ``name`` field in the frontmatter, or
            the parent directory name if the frontmatter does not
            declare one.
        passed: ``True`` if every check below succeeded.
        declared_capabilities: Capability strings read from
            ``metadata.certior.capabilities``.
        parent_permissions: The parent guard's permission set the
            declaration was checked against.
        missing_capabilities: Capabilities declared by the skill that
            are *not* in the parent's permissions. Empty if the
            subset check passed (or the parent holds the ``"*"``
            wildcard).
        declared_no_capabilities: ``True`` if the skill omits the
            ``metadata.certior.capabilities`` field entirely. By
            default this fails the audit (fail-closed); set
            ``allow_undeclared=True`` on :func:`audit_skill` to
            treat it as the empty-set declaration instead.
        fingerprint: Hex SHA-256 of the ``SKILL.md`` file contents at
            audit time, suitable for pinning ("approve this exact
            version, fail later runs if it changes").
        expected_fingerprint: If supplied to :func:`audit_skill`,
            the fingerprint the file was checked against. ``None``
            when no pin was supplied.
        fingerprint_matches: ``True`` if either no pin was supplied
            *or* the file's current fingerprint equals the pin.
        reasons: Human-readable failure reasons. Empty on pass.
    """

    skill_path: Path
    skill_name: str
    passed: bool
    declared_capabilities: List[str]
    parent_permissions: List[str]
    missing_capabilities: List[str]
    declared_no_capabilities: bool
    fingerprint: str
    expected_fingerprint: Optional[str]
    fingerprint_matches: bool
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "skill_path": str(self.skill_path),
            "skill_name": self.skill_name,
            "passed": self.passed,
            "declared_capabilities": list(self.declared_capabilities),
            "parent_permissions": list(self.parent_permissions),
            "missing_capabilities": list(self.missing_capabilities),
            "declared_no_capabilities": self.declared_no_capabilities,
            "fingerprint": self.fingerprint,
            "expected_fingerprint": self.expected_fingerprint,
            "fingerprint_matches": self.fingerprint_matches,
            "reasons": list(self.reasons),
        }


# ── Fingerprint ───────────────────────────────────────────────────────


def skill_fingerprint(skill_md_path: Any) -> str:
    """Return the hex SHA-256 of a ``SKILL.md`` file's bytes.

    The digest is taken over the raw bytes of the file, so any change
    - frontmatter, body, or trailing whitespace - produces a new
    fingerprint. Use this when pinning a reviewed skill so a later
    edit cannot silently re-enter the pipeline as the approved
    version.
    """
    path = Path(skill_md_path)
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Internals ─────────────────────────────────────────────────────────


def _read_skill_name(skill_md_path: Path) -> str:
    """Best-effort read of the skill ``name`` field.

    Falls back to the parent directory name if the frontmatter
    cannot be parsed or does not declare a name. This is informational
    only - it does not affect the audit verdict.
    """
    import re

    try:
        text = skill_md_path.read_text(encoding="utf-8")
    except OSError:
        return skill_md_path.parent.name

    m = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", text, flags=re.DOTALL)
    if not m:
        return skill_md_path.parent.name

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:  # pragma: no cover
        return skill_md_path.parent.name

    try:
        data = yaml.safe_load(m.group(1)) or {}
    except Exception:
        return skill_md_path.parent.name

    name = data.get("name") if isinstance(data, dict) else None
    return name if isinstance(name, str) and name else skill_md_path.parent.name


def _declared_capabilities(
    skill_md_path: Path,
) -> "tuple[List[str], bool]":
    """Run the SKILL.md loader and report whether the field was absent.

    The loader returns ``[]`` both when the field is absent and when
    it is explicitly an empty list. We distinguish them here by
    re-reading the file because the loader emits a warning but does
    not signal absence in its return value.
    """
    import re

    text = skill_md_path.read_text(encoding="utf-8")
    m = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", text, flags=re.DOTALL)
    declared_no_capabilities = True
    if m:
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(m.group(1)) or {}
            metadata = data.get("metadata") if isinstance(data, dict) else None
            if isinstance(metadata, dict):
                certior_ext = metadata.get("certior")
                if isinstance(certior_ext, dict) and "capabilities" in certior_ext:
                    declared_no_capabilities = False
        except Exception:
            # If the YAML is malformed the loader call below will
            # raise - let it.
            pass

    # Lazy import to avoid a circular dependency: ``openclaw`` re-exports
    # this module's public API, so we can't import from it at module load.
    from certior.adapters.openclaw import load_step_capabilities_from_skill

    caps = load_step_capabilities_from_skill(skill_md_path)
    return caps, declared_no_capabilities


def _subset_check(
    declared: Sequence[str], parent_permissions: Sequence[str]
) -> List[str]:
    """Return capabilities in ``declared`` not in ``parent_permissions``.

    ``"*"`` in the parent set is treated as a wildcard that
    authorises every capability - matching the runtime behaviour of
    ``Guard``.
    """
    parent_set = set(parent_permissions)
    if "*" in parent_set:
        return []
    return [c for c in declared if c not in parent_set]


# ── Public API ────────────────────────────────────────────────────────


def audit_skill(
    skill_md_path: Any,
    parent_guard: Guard,
    *,
    expected_fingerprint: Optional[str] = None,
    allow_undeclared: bool = False,
) -> SkillAuditResult:
    """Audit one ``SKILL.md`` against a parent ``Guard``.

    Three deductive checks run, in order:

    1. **Declaration present.** The skill must declare
       ``metadata.certior.capabilities`` in its frontmatter. A skill
       with no declaration fails the audit unless
       ``allow_undeclared=True`` - in which case the empty set is
       assumed.
    2. **Capability subset.** Every declared capability must appear
       in ``parent_guard.permissions``. ``"*"`` in the parent
       satisfies every capability.
    3. **Fingerprint pin (optional).** If ``expected_fingerprint`` is
       supplied, the file's current SHA-256 must equal it.

    Args:
        skill_md_path: Path to a ``SKILL.md`` file.
        parent_guard: The Certior ``Guard`` whose permissions the
            skill will run under. The skill's declared capabilities
            are checked against ``parent_guard.permissions``.
        expected_fingerprint: Hex SHA-256 the file should match.
            ``None`` disables fingerprint pinning.
        allow_undeclared: If ``True``, treat a missing
            ``metadata.certior.capabilities`` field as the empty
            declaration (and therefore pass any non-empty parent).
            Default is ``False`` (fail-closed).

    Returns:
        A :class:`SkillAuditResult` with the verdict and supporting
        evidence.

    Raises:
        FileNotFoundError: If ``skill_md_path`` does not resolve.
        ValueError: If the file has no YAML frontmatter or the YAML
            is malformed.
    """
    path = Path(skill_md_path).resolve()
    parent_permissions = list(parent_guard.permissions)
    fingerprint = skill_fingerprint(path)
    fingerprint_matches = (
        expected_fingerprint is None or fingerprint == expected_fingerprint
    )

    declared, declared_no_capabilities = _declared_capabilities(path)
    missing = _subset_check(declared, parent_permissions)

    reasons: List[str] = []
    if declared_no_capabilities and not allow_undeclared:
        reasons.append(
            "skill declares no metadata.certior.capabilities "
            "(fail-closed; pass allow_undeclared=True to override)"
        )
    if missing:
        reasons.append(
            "capability_not_in_parent: "
            + ", ".join(sorted(missing))
        )
    if not fingerprint_matches:
        reasons.append(
            f"fingerprint_mismatch: expected {expected_fingerprint}, "
            f"got {fingerprint}"
        )

    passed = not reasons
    return SkillAuditResult(
        skill_path=path,
        skill_name=_read_skill_name(path),
        passed=passed,
        declared_capabilities=list(declared),
        parent_permissions=parent_permissions,
        missing_capabilities=missing,
        declared_no_capabilities=declared_no_capabilities,
        fingerprint=fingerprint,
        expected_fingerprint=expected_fingerprint,
        fingerprint_matches=fingerprint_matches,
        reasons=reasons,
    )


def audit_skills_dir(
    skills_dir: Any,
    parent_guard: Guard,
    *,
    expected_fingerprints: Optional[Mapping[str, str]] = None,
    allow_undeclared: bool = False,
) -> List[SkillAuditResult]:
    """Audit every ``*/SKILL.md`` one level deep under ``skills_dir``.

    Matches the OpenClaw skill layout
    ``~/.openclaw/workspace/skills/<skill>/SKILL.md``. Each skill is
    audited independently with :func:`audit_skill`; results are
    returned in directory-sorted order.

    Args:
        skills_dir: Directory containing one subdirectory per skill.
        parent_guard: Parent guard whose permissions every skill is
            checked against.
        expected_fingerprints: Optional mapping ``{skill_name:
            fingerprint}`` for pinning known-good versions. Skills
            absent from the mapping run without a fingerprint check.
        allow_undeclared: Forwarded to :func:`audit_skill`.

    Returns:
        A list of :class:`SkillAuditResult`, one per ``SKILL.md`` found.
    """
    root = Path(skills_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"{skills_dir} is not a directory")

    pins = dict(expected_fingerprints or {})
    out: List[SkillAuditResult] = []
    for skill_md in sorted(root.glob("*/SKILL.md")):
        skill_name = _read_skill_name(skill_md)
        pin = pins.get(skill_name) or pins.get(skill_md.parent.name)
        out.append(
            audit_skill(
                skill_md,
                parent_guard,
                expected_fingerprint=pin,
                allow_undeclared=allow_undeclared,
            )
        )
    return out
