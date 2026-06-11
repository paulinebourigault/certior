"""
certior.adapters.openclaw_skill_audit_cli - CLI for static skill audit.
=======================================================================

Wraps :func:`certior.adapters.openclaw_skill_audit.audit_skill` and
:func:`audit_skills_dir` for use from a shell. Exits non-zero when
any audited skill fails so the binary can be wired into pre-install
hooks, CI, or release pipelines.

Usage::

    certior-skill-audit <path> \\
        --permission network:http:read \\
        --permission filesystem:read \\
        [--allow-undeclared] \\
        [--expected-fingerprint <skill_name>=<sha256>]... \\
        [--json]

``<path>`` may be either a single ``SKILL.md`` file or a directory
containing ``<skill>/SKILL.md`` subdirectories.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Sequence

from certior.guard import Guard

from certior.adapters.openclaw_skill_audit import (
    SkillAuditResult,
    audit_skill,
    audit_skills_dir,
)


def _parse_fingerprint_pair(raw: str) -> "tuple[str, str]":
    if "=" not in raw:
        raise argparse.ArgumentTypeError(
            f"--expected-fingerprint requires <skill_name>=<sha256>, got: {raw!r}"
        )
    name, _, digest = raw.partition("=")
    name = name.strip()
    digest = digest.strip().lower()
    if not name or not digest:
        raise argparse.ArgumentTypeError(
            f"--expected-fingerprint requires <skill_name>=<sha256>, got: {raw!r}"
        )
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise argparse.ArgumentTypeError(
            f"fingerprint for {name!r} is not a 64-hex-character SHA-256: {digest!r}"
        )
    return name, digest


def _format_human(results: Sequence[SkillAuditResult]) -> str:
    lines: List[str] = []
    pass_count = sum(1 for r in results if r.passed)
    fail_count = len(results) - pass_count
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(f"[{status}] {r.skill_name}  ({r.skill_path})")
        lines.append(f"       declared: {r.declared_capabilities or '∅'}")
        lines.append(f"       parent:   {r.parent_permissions}")
        if r.declared_no_capabilities:
            lines.append("       note:     no metadata.certior.capabilities declared")
        if r.missing_capabilities:
            lines.append(f"       missing:  {r.missing_capabilities}")
        if r.expected_fingerprint is not None:
            ok = "ok" if r.fingerprint_matches else "MISMATCH"
            lines.append(f"       pin:      {ok}  ({r.fingerprint[:16]}…)")
        else:
            lines.append(f"       fp:       {r.fingerprint[:16]}…  (no pin)")
        for reason in r.reasons:
            lines.append(f"       reason:   {reason}")
    lines.append("")
    lines.append(f"Audited {len(results)} skill(s): {pass_count} pass, {fail_count} fail")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certior-skill-audit",
        description=(
            "Statically audit an OpenClaw skill against a parent guard's "
            "permissions. Proves the skill's declared capability surface is "
            "a subset of the parent's. Does NOT scan skill source code for "
            "dangerous patterns - that is a complementary tool's job."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a SKILL.md file or a directory containing <skill>/SKILL.md subdirectories.",
    )
    parser.add_argument(
        "--permission",
        action="append",
        default=[],
        metavar="CAP",
        help=(
            "Parent capability the skill is allowed to declare. Repeatable. "
            "Pass '*' to allow any capability (not recommended outside dev)."
        ),
    )
    parser.add_argument(
        "--allow-undeclared",
        action="store_true",
        help=(
            "Treat a skill with no metadata.certior.capabilities field as "
            "the empty-set declaration (passes any non-empty parent). "
            "Default is fail-closed."
        ),
    )
    parser.add_argument(
        "--expected-fingerprint",
        action="append",
        default=[],
        metavar="NAME=SHA256",
        type=_parse_fingerprint_pair,
        help=(
            "Pin a known-good SKILL.md fingerprint. Repeatable; one per skill. "
            "Audit fails if the file's current SHA-256 differs."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human-readable summary.",
    )
    return parser


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.permission:
        print(
            "certior-skill-audit: error: at least one --permission is required",
            file=sys.stderr,
        )
        return 2

    parent = Guard(permissions=list(args.permission), budget_cents=0)
    pins: Dict[str, str] = dict(args.expected_fingerprint or [])

    path = args.path
    try:
        if path.is_dir():
            results = audit_skills_dir(
                path,
                parent,
                expected_fingerprints=pins,
                allow_undeclared=args.allow_undeclared,
            )
        elif path.is_file():
            single_pin = next(iter(pins.values())) if len(pins) == 1 else None
            results = [
                audit_skill(
                    path,
                    parent,
                    expected_fingerprint=single_pin,
                    allow_undeclared=args.allow_undeclared,
                )
            ]
        else:
            print(
                f"certior-skill-audit: error: {path} is neither a file nor a directory",
                file=sys.stderr,
            )
            return 2
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"certior-skill-audit: error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
    else:
        print(_format_human(results))

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
