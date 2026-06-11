"""
Tests for skill schema validation.
IMPROVED: Tests ALL validation paths for full coverage.
"""
import pytest
from agentsafe.skills.schema import (
    validate_skill_spec, load_and_validate, SKILL_ID_PATTERN, VERSION_PATTERN,
)
from agentsafe.skills.exceptions import SkillValidationError


class TestValidateSkillSpec:
    def _base_spec(self, **overrides):
        spec = {
            "skill_id": "test_skill",
            "version": "1.0.0",
            "verification_requirements": {
                "capabilities_required": ["test:read"],
            },
        }
        spec.update(overrides)
        return spec

    def test_valid_minimal(self):
        valid, errors = validate_skill_spec(self._base_spec())
        assert valid
        assert len(errors) == 0

    def test_missing_skill_id(self):
        spec = {"version": "1.0.0", "verification_requirements": {"capabilities_required": []}}
        valid, errors = validate_skill_spec(spec)
        assert not valid
        assert any("skill_id" in e for e in errors)

    def test_missing_version(self):
        spec = {"skill_id": "test", "verification_requirements": {"capabilities_required": []}}
        valid, errors = validate_skill_spec(spec)
        assert not valid
        assert any("version" in e for e in errors)

    def test_missing_verification_requirements(self):
        spec = {"skill_id": "test", "version": "1.0.0"}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_invalid_skill_id_format(self):
        valid, errors = validate_skill_spec(self._base_spec(skill_id="Invalid-ID"))
        assert not valid
        assert any("skill_id" in e for e in errors)

    def test_invalid_skill_id_type(self):
        valid, errors = validate_skill_spec(self._base_spec(skill_id=123))
        assert not valid

    def test_invalid_version_format(self):
        valid, errors = validate_skill_spec(self._base_spec(version="1.0"))
        assert not valid
        assert any("version" in e for e in errors)

    def test_invalid_version_type(self):
        valid, errors = validate_skill_spec(self._base_spec(version=1))
        assert not valid

    def test_missing_capabilities(self):
        spec = self._base_spec()
        del spec["verification_requirements"]["capabilities_required"]
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_capabilities_not_list(self):
        spec = self._base_spec()
        spec["verification_requirements"]["capabilities_required"] = "not-a-list"
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_capabilities_non_string_items(self):
        spec = self._base_spec()
        spec["verification_requirements"]["capabilities_required"] = [1, 2]
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_vr_not_dict(self):
        spec = self._base_spec()
        spec["verification_requirements"] = "not-a-dict"
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Resource constraints
    def test_valid_resource_constraints(self):
        spec = self._base_spec()
        spec["verification_requirements"]["resource_constraints"] = {
            "max_requests_per_minute": 60,
            "timeout_seconds": 30,
        }
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_resource_constraint_out_of_range(self):
        spec = self._base_spec()
        spec["verification_requirements"]["resource_constraints"] = {
            "max_requests_per_minute": -1,
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_resource_constraint_wrong_type(self):
        spec = self._base_spec()
        spec["verification_requirements"]["resource_constraints"] = {
            "timeout_seconds": "thirty",
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Safety constraints
    def test_valid_safety_constraints(self):
        spec = self._base_spec()
        spec["verification_requirements"]["safety_constraints"] = {
            "url_allowlist_patterns": ["^https://.*"],
            "read_only": True,
        }
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_safety_constraint_bad_regex(self):
        spec = self._base_spec()
        spec["verification_requirements"]["safety_constraints"] = {
            "url_allowlist_patterns": ["[invalid"],
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid
        assert any("regex" in e.lower() for e in errors)

    def test_safety_constraint_non_list(self):
        spec = self._base_spec()
        spec["verification_requirements"]["safety_constraints"] = {
            "forbidden_columns": "not-a-list",
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_safety_bool_wrong_type(self):
        spec = self._base_spec()
        spec["verification_requirements"]["safety_constraints"] = {
            "read_only": "yes",
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Information flow
    def test_valid_info_flow(self):
        spec = self._base_spec()
        spec["verification_requirements"]["information_flow"] = {
            "input_labels": ["public"],
            "output_labels": ["internal"],
            "forbidden_flows": [{"from": "sensitive", "to": "public"}],
        }
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_info_flow_bad_forbidden(self):
        spec = self._base_spec()
        spec["verification_requirements"]["information_flow"] = {
            "forbidden_flows": [{"from": "a"}],  # missing "to"
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_info_flow_non_list(self):
        spec = self._base_spec()
        spec["verification_requirements"]["information_flow"] = {
            "input_labels": "not-a-list",
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_info_flow_forbidden_not_list(self):
        spec = self._base_spec()
        spec["verification_requirements"]["information_flow"] = {
            "forbidden_flows": "not-a-list",
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_info_flow_forbidden_item_not_dict(self):
        spec = self._base_spec()
        spec["verification_requirements"]["information_flow"] = {
            "forbidden_flows": ["not-a-dict"],
        }
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Formal properties
    def test_valid_formal_properties(self):
        spec = self._base_spec()
        spec["verification_requirements"]["formal_properties"] = [
            {"property": "test", "prover": "z3"},
        ]
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_formal_property_invalid_prover(self):
        spec = self._base_spec()
        spec["verification_requirements"]["formal_properties"] = [
            {"property": "test", "prover": "invalid"},
        ]
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_formal_property_missing_fields(self):
        spec = self._base_spec()
        spec["verification_requirements"]["formal_properties"] = [
            {"property": "test"},  # missing prover
        ]
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_formal_properties_not_list(self):
        spec = self._base_spec()
        spec["verification_requirements"]["formal_properties"] = "not-a-list"
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_formal_property_not_dict(self):
        spec = self._base_spec()
        spec["verification_requirements"]["formal_properties"] = ["not-a-dict"]
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Metadata
    def test_valid_metadata(self):
        spec = self._base_spec()
        spec["metadata"] = {
            "name": "Test", "description": "A test",
            "tags": ["a", "b"],
        }
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_metadata_tags_not_list(self):
        spec = self._base_spec()
        spec["metadata"] = {"tags": "not-a-list"}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_metadata_name_not_string(self):
        spec = self._base_spec()
        spec["metadata"] = {"name": 123}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_metadata_tags_non_string(self):
        spec = self._base_spec()
        spec["metadata"] = {"tags": [1, 2]}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    # Compliance mappings
    def test_valid_compliance(self):
        spec = self._base_spec()
        spec["compliance_mappings"] = {
            "hipaa": {"applies": True, "rationale": "PHI access"},
        }
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_compliance_applies_wrong_type(self):
        spec = self._base_spec()
        spec["compliance_mappings"] = {"hipaa": {"applies": "yes"}}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_compliance_not_dict(self):
        spec = self._base_spec()
        spec["compliance_mappings"] = {"hipaa": "not-a-dict"}
        valid, errors = validate_skill_spec(spec)
        assert not valid


class TestLoadAndValidate:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(SkillValidationError, match="not found"):
            load_and_validate(tmp_path / "nonexistent.json")

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{invalid json")
        with pytest.raises(SkillValidationError, match="Invalid JSON"):
            load_and_validate(f)

    def test_valid_file(self, tmp_path):
        import json
        f = tmp_path / "VERIFICATION.json"
        f.write_text(json.dumps({
            "skill_id": "test", "version": "1.0.0",
            "verification_requirements": {"capabilities_required": ["a"]},
        }))
        spec = load_and_validate(f)
        assert spec["skill_id"] == "test"


class TestEdgeCases:
    """Additional edge cases for full schema coverage."""

    def test_empty_string_skill_id(self):
        spec = {"skill_id": "", "version": "1.0.0",
                "verification_requirements": {"capabilities_required": []}}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_skill_id_starts_with_number(self):
        spec = {"skill_id": "1bad", "version": "1.0.0",
                "verification_requirements": {"capabilities_required": []}}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_version_four_parts(self):
        spec = {"skill_id": "test", "version": "1.0.0.0",
                "verification_requirements": {"capabilities_required": []}}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_resource_constraint_max_boundary(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "resource_constraints": {"max_requests_per_minute": 100001},
                }}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_resource_constraint_zero_timeout(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "resource_constraints": {"timeout_seconds": 0},
                }}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_safety_list_with_non_string_items(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "safety_constraints": {
                        "url_allowlist_patterns": ["ok", 123],
                    },
                }}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_info_flow_labels_non_string(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "information_flow": {
                        "input_labels": [1, 2],
                    },
                }}
        valid, errors = validate_skill_spec(spec)
        assert not valid

    def test_multiple_errors_at_once(self):
        spec = {"skill_id": "BAD!", "version": "bad",
                "verification_requirements": "not-a-dict"}
        valid, errors = validate_skill_spec(spec)
        assert not valid
        assert len(errors) >= 2

    def test_all_resource_constraint_types(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "resource_constraints": {
                        "max_requests_per_minute": 60,
                        "max_body_size_bytes": 1000,
                        "timeout_seconds": 30,
                        "max_memory_mb": 512,
                        "max_rows_per_query": 1000,
                        "query_timeout_seconds": 30,
                        "max_file_size_bytes": 5000000,
                    },
                }}
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_all_safety_list_fields(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "safety_constraints": {
                        "url_allowlist_patterns": ["^https://.*"],
                        "url_blocklist_patterns": [".*\\.onion$"],
                        "content_filters": ["no_malware"],
                        "forbidden_columns": ["ssn"],
                        "allowed_tables": ["public.*"],
                        "allowed_extensions": [".txt"],
                        "path_allowlist_patterns": ["^/data/.*"],
                        "path_blocklist_patterns": [".*\\.key$"],
                        "read_only": True,
                        "user_agent_required": True,
                    },
                }}
        valid, errors = validate_skill_spec(spec)
        assert valid

    def test_formal_property_with_specification(self):
        spec = {"skill_id": "test", "version": "1.0.0",
                "verification_requirements": {
                    "capabilities_required": [],
                    "formal_properties": [
                        {"property": "safety", "prover": "z3",
                         "specification": "forall x: safe(x)"},
                    ],
                }}
        valid, errors = validate_skill_spec(spec)
        assert valid
