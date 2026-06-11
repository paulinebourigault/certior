"""
Skill schema validation - comprehensive VERIFICATION.json validation.
IMPROVED: Full validation coverage for all schema paths.
"""
from __future__ import annotations
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from .exceptions import SkillValidationError

# Required top-level fields
REQUIRED_FIELDS = {"skill_id", "version", "verification_requirements"}

# Valid prover types
VALID_PROVERS = {"z3", "dafny", "lean4"}

# Skill ID pattern
SKILL_ID_PATTERN = re.compile(r'^[a-z_][a-z0-9_]*$')

# Semver pattern
VERSION_PATTERN = re.compile(r'^\d+\.\d+\.\d+$')


def validate_skill_spec(spec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a skill specification against the schema.
    Returns (valid, list_of_errors).
    """
    errors: List[str] = []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in spec:
            errors.append(f"Missing required field: {field}")

    if errors:
        return False, errors

    # Validate skill_id
    sid = spec.get("skill_id", "")
    if not isinstance(sid, str):
        errors.append(f"skill_id must be a string, got {type(sid).__name__}")
    elif not SKILL_ID_PATTERN.match(sid):
        errors.append(f"Invalid skill_id format: '{sid}' (must match [a-z_][a-z0-9_]*)")

    # Validate version
    ver = spec.get("version", "")
    if not isinstance(ver, str):
        errors.append(f"version must be a string, got {type(ver).__name__}")
    elif not VERSION_PATTERN.match(ver):
        errors.append(f"Invalid version format: '{ver}' (must be semver X.Y.Z)")

    # Validate verification_requirements
    vr = spec.get("verification_requirements", {})
    if not isinstance(vr, dict):
        errors.append("verification_requirements must be an object")
        return False, errors

    # capabilities_required is mandatory
    caps = vr.get("capabilities_required")
    if caps is None:
        errors.append("Missing verification_requirements.capabilities_required")
    elif not isinstance(caps, list):
        errors.append("capabilities_required must be a list")
    elif not all(isinstance(c, str) for c in caps):
        errors.append("All capabilities must be strings")

    # Validate resource_constraints
    rc = vr.get("resource_constraints", {})
    if rc:
        _validate_resource_constraints(rc, errors)

    # Validate safety_constraints
    sc = vr.get("safety_constraints", {})
    if sc:
        _validate_safety_constraints(sc, errors)

    # Validate information_flow
    ifc = vr.get("information_flow", {})
    if ifc:
        _validate_information_flow(ifc, errors)

    # Validate formal_properties
    fps = vr.get("formal_properties", [])
    if fps:
        _validate_formal_properties(fps, errors)

    # Validate metadata if present
    meta = spec.get("metadata", {})
    if meta:
        _validate_metadata(meta, errors)

    # Validate compliance_mappings if present
    cm = spec.get("compliance_mappings", {})
    if cm:
        _validate_compliance_mappings(cm, errors)

    return len(errors) == 0, errors


def _validate_resource_constraints(rc: Dict, errors: List[str]):
    int_fields = {
        "max_requests_per_minute": (1, 100000),
        "max_body_size_bytes": (0, 100_000_000),
        "timeout_seconds": (1, 3600),
        "max_memory_mb": (1, 65536),
        "max_rows_per_query": (1, 10_000_000),
        "query_timeout_seconds": (1, 3600),
        "max_file_size_bytes": (0, 10_000_000_000),
    }
    for field, (lo, hi) in int_fields.items():
        if field in rc:
            val = rc[field]
            if not isinstance(val, int):
                errors.append(f"resource_constraints.{field} must be integer")
            elif val < lo or val > hi:
                errors.append(f"resource_constraints.{field}={val} out of range [{lo}, {hi}]")


def _validate_safety_constraints(sc: Dict, errors: List[str]):
    list_fields = [
        "url_allowlist_patterns", "url_blocklist_patterns",
        "content_filters", "forbidden_columns", "allowed_tables",
        "allowed_extensions", "path_allowlist_patterns", "path_blocklist_patterns",
    ]
    for field in list_fields:
        if field in sc:
            val = sc[field]
            if not isinstance(val, list):
                errors.append(f"safety_constraints.{field} must be a list")
            elif not all(isinstance(v, str) for v in val):
                errors.append(f"safety_constraints.{field} items must be strings")
            # Validate regex patterns compile
            if "pattern" in field:
                for i, pattern in enumerate(val):
                    if not isinstance(pattern, str):
                        continue  # Already caught by non-string check above
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        errors.append(f"Invalid regex in {field}[{i}]: {e}")

    bool_fields = ["read_only", "user_agent_required"]
    for field in bool_fields:
        if field in sc and not isinstance(sc[field], bool):
            errors.append(f"safety_constraints.{field} must be boolean")


def _validate_information_flow(ifc: Dict, errors: List[str]):
    for field in ["input_labels", "output_labels"]:
        if field in ifc:
            val = ifc[field]
            if not isinstance(val, list):
                errors.append(f"information_flow.{field} must be a list")
            elif not all(isinstance(v, str) for v in val):
                errors.append(f"information_flow.{field} items must be strings")

    if "forbidden_flows" in ifc:
        ff = ifc["forbidden_flows"]
        if not isinstance(ff, list):
            errors.append("information_flow.forbidden_flows must be a list")
        else:
            for i, flow in enumerate(ff):
                if not isinstance(flow, dict):
                    errors.append(f"forbidden_flows[{i}] must be an object")
                elif "from" not in flow or "to" not in flow:
                    errors.append(f"forbidden_flows[{i}] must have 'from' and 'to'")


def _validate_formal_properties(fps: List, errors: List[str]):
    if not isinstance(fps, list):
        errors.append("formal_properties must be a list")
        return
    for i, fp in enumerate(fps):
        if not isinstance(fp, dict):
            errors.append(f"formal_properties[{i}] must be an object")
            continue
        if "property" not in fp:
            errors.append(f"formal_properties[{i}] missing 'property'")
        if "prover" not in fp:
            errors.append(f"formal_properties[{i}] missing 'prover'")
        elif fp["prover"] not in VALID_PROVERS:
            errors.append(f"formal_properties[{i}] invalid prover: {fp['prover']}")


def _validate_metadata(meta: Dict, errors: List[str]):
    str_fields = ["name", "description", "author"]
    for field in str_fields:
        if field in meta and not isinstance(meta[field], str):
            errors.append(f"metadata.{field} must be a string")
    if "tags" in meta:
        if not isinstance(meta["tags"], list):
            errors.append("metadata.tags must be a list")
        elif not all(isinstance(t, str) for t in meta["tags"]):
            errors.append("metadata.tags items must be strings")


def _validate_compliance_mappings(cm: Dict, errors: List[str]):
    for regime, mapping in cm.items():
        if not isinstance(mapping, dict):
            errors.append(f"compliance_mappings.{regime} must be an object")
            continue
        if "applies" in mapping and not isinstance(mapping["applies"], bool):
            errors.append(f"compliance_mappings.{regime}.applies must be boolean")


def load_and_validate(path: Path) -> Dict[str, Any]:
    """Load and validate a VERIFICATION.json file."""
    if not path.exists():
        raise SkillValidationError(f"File not found: {path}")
    try:
        with open(path) as f:
            spec = json.load(f)
    except json.JSONDecodeError as e:
        raise SkillValidationError(f"Invalid JSON: {e}")

    valid, errors = validate_skill_spec(spec)
    if not valid:
        raise SkillValidationError(
            f"Validation failed with {len(errors)} error(s)",
            errors=errors,
        )
    return spec
