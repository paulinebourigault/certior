"""
Tests for deep Z3 skill verification.
IMPROVED v2: Tests verify genuine constraint proofs + counterexample generation.
"""
import pytest
from agentsafe.skills.z3_verifier import (
    SkillZ3Verifier, Z3VerificationResult, verify_skill_constraints,
    _structural_verify,
)

z3 = pytest.importorskip("z3")


def _web_skill_spec():
    return {
        "skill_id": "web_browsing",
        "version": "1.0.0",
        "verification_requirements": {
            "capabilities_required": ["network:http:read", "filesystem:cache:write"],
            "resource_constraints": {
                "max_requests_per_minute": 60,
                "timeout_seconds": 30,
            },
            "safety_constraints": {
                "url_allowlist_patterns": ["^https://.*"],
                "url_blocklist_patterns": [".*\\.onion$"],
            },
            "information_flow": {
                "input_labels": ["public", "internal"],
                "output_labels": ["cached", "internal"],
                "forbidden_flows": [
                    {"from": "sensitive", "to": "public"},
                ],
            },
            "formal_properties": [
                {"property": "no_unauthorized_domains", "prover": "z3"},
                {"property": "rate_limit_respected", "prover": "z3"},
                {"property": "no_data_exfiltration", "prover": "z3"},
            ],
        },
    }


def _db_skill_spec():
    return {
        "skill_id": "database_query",
        "version": "1.0.0",
        "verification_requirements": {
            "capabilities_required": ["database:read"],
            "resource_constraints": {
                "max_rows_per_query": 10000,
                "query_timeout_seconds": 30,
            },
            "safety_constraints": {
                "forbidden_columns": ["password", "ssn", "credit_card"],
                "read_only": True,
            },
            "formal_properties": [
                {"property": "no_forbidden_columns", "prover": "z3"},
                {"property": "row_limit_enforced", "prover": "z3"},
            ],
        },
    }


def _file_skill_spec():
    return {
        "skill_id": "file_operations",
        "version": "1.0.0",
        "verification_requirements": {
            "capabilities_required": ["filesystem:read", "filesystem:write"],
            "resource_constraints": {
                "max_file_size_bytes": 10000000,
                "timeout_seconds": 60,
            },
            "safety_constraints": {
                "path_allowlist_patterns": ["^/data/.*", "^/tmp/.*"],
                "path_blocklist_patterns": [".*\\.env$", ".*\\.key$"],
            },
            "formal_properties": [
                {"property": "no_path_traversal", "prover": "z3"},
                {"property": "size_limit_enforced", "prover": "z3"},
            ],
        },
    }


class TestSkillZ3Verifier:
    def test_web_skill_valid_token(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert result.valid
        assert result.all_proven
        assert len(result.properties_proven) >= 5
        assert result.solve_time_ms > 0
        assert len(result.counterexamples) == 0

    def test_web_skill_missing_capability(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _web_skill_spec(),
            ["network:http:read"],  # Missing filesystem:cache:write
        )
        assert not result.valid
        assert any("missing" in p for p in result.properties_failed)
        assert len(result.counterexamples) > 0  # Has counterexample

    def test_db_skill_no_forbidden_columns(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:read"],
            runtime_context={"query_columns": ["name", "email"]},
        )
        assert result.valid

    def test_db_skill_forbidden_column_access(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:read"],
            runtime_context={"query_columns": ["name", "password"]},
        )
        assert not result.valid
        assert any("forbidden" in p.lower() for p in result.properties_failed)
        assert len(result.counterexamples) > 0

    def test_db_skill_multiple_forbidden_columns(self):
        """Test detecting multiple forbidden column violations."""
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:read"],
            runtime_context={"query_columns": ["password", "ssn", "name"]},
        )
        assert not result.valid

    def test_file_skill_valid(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _file_skill_spec(),
            ["filesystem:read", "filesystem:write"],
        )
        assert result.valid

    def test_file_skill_missing_write(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _file_skill_spec(),
            ["filesystem:read"],
        )
        assert not result.valid

    def test_wildcard_capability(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:*"],
        )
        assert result.valid
        assert any("covered" in p for p in result.properties_proven)

    def test_information_flow_proof(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert any("no_level_downgrade" in p for p in result.properties_proven)
        assert any("forbidden_flow" in p for p in result.properties_proven)
        assert any("lattice_valid" in p for p in result.properties_proven)

    def test_rate_limit_proof(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert any("rate_limit" in p for p in result.properties_proven)

    def test_no_exfiltration_proof(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert any("exfiltration" in p.lower() or "GET+body" in p for p in result.properties_proven)

    def test_path_traversal_proof(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _file_skill_spec(),
            ["filesystem:read", "filesystem:write"],
        )
        assert any("traversal" in p for p in result.properties_proven)

    def test_read_only_proof(self):
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:read"],
        )
        assert any("read_only" in p or "write" in p.lower() for p in result.properties_proven)

    def test_no_required_capabilities(self):
        """Skill with no required capabilities always passes."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": [],
            }
        }
        result = v.verify_skill(spec, [])
        assert result.valid

    def test_unknown_formal_property(self):
        """Unknown formal properties are accepted (no encoding)."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": ["a"],
                "formal_properties": [
                    {"property": "custom_property", "prover": "z3"},
                ],
            }
        }
        result = v.verify_skill(spec, ["a"])
        assert result.valid

    def test_bounded_model_checking_rate(self):
        """Verify the BMC rate limit proof uses actual state transitions."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": [],
                "resource_constraints": {"max_requests_per_minute": 5},
            }
        }
        result = v.verify_skill(spec, [])
        assert result.valid
        assert any("BMC" in p for p in result.properties_proven)

    def test_timeout_out_of_range(self):
        """Timeout exceeding 300s should fail."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": [],
                "resource_constraints": {"timeout_seconds": 500},
            }
        }
        result = v.verify_skill(spec, [])
        assert not result.valid
        assert any("timeout" in p for p in result.properties_failed)

    def test_url_filter_no_allowlist(self):
        """Empty URL allowlist should fail."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": [],
                "safety_constraints": {
                    "url_allowlist_patterns": [],
                    "url_blocklist_patterns": [".*"],
                },
            }
        }
        result = v.verify_skill(spec, [])
        assert not result.valid

    def test_empty_path_allowlist(self):
        """Empty path allowlist should fail."""
        v = SkillZ3Verifier()
        spec = {
            "verification_requirements": {
                "capabilities_required": [],
                "safety_constraints": {
                    "path_allowlist_patterns": [],
                },
            }
        }
        result = v.verify_skill(spec, [])
        assert not result.valid

    def test_column_exclusion_without_query(self):
        """Abstract exclusion proof when no query columns provided."""
        v = SkillZ3Verifier()
        result = v.verify_skill(
            _db_skill_spec(),
            ["database:read"],
        )
        assert result.valid
        assert any("excluded" in p for p in result.properties_proven)


class TestVerifySkillConstraints:
    def test_convenience_function(self):
        result = verify_skill_constraints(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert result.valid

    def test_with_context(self):
        result = verify_skill_constraints(
            _db_skill_spec(),
            ["database:read"],
            context={"query_columns": ["name"]},
        )
        assert result.valid

    def test_with_forbidden_context(self):
        result = verify_skill_constraints(
            _db_skill_spec(),
            ["database:read"],
            context={"query_columns": ["password"]},
        )
        assert not result.valid


class TestStructuralFallback:
    def test_structural_verify_pass(self):
        result = _structural_verify(
            _web_skill_spec(),
            ["network:http:read", "filesystem:cache:write"],
        )
        assert result.valid

    def test_structural_verify_fail(self):
        result = _structural_verify(
            _web_skill_spec(),
            ["network:http:read"],
        )
        assert not result.valid

    def test_structural_wildcard(self):
        result = _structural_verify(
            _db_skill_spec(),
            ["database:*"],
        )
        assert result.valid
