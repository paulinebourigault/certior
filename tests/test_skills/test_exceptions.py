"""Tests for skill exceptions - full coverage."""
import pytest
from agentsafe.skills.exceptions import (
    SkillError, SkillNotFoundError, SkillValidationError,
    CapabilityError, ResourceConstraintError, InformationFlowError,
    URLNotAllowedError, URLBlockedError, ForbiddenColumnError,
    PathNotAllowedError,
)


class TestExceptions:
    def test_skill_error_base(self):
        e = SkillError("base error")
        assert str(e) == "base error"
        assert isinstance(e, Exception)

    def test_skill_not_found(self):
        e = SkillNotFoundError("not found")
        assert isinstance(e, SkillError)

    def test_validation_error_with_errors(self):
        e = SkillValidationError("failed", errors=["err1", "err2"])
        assert e.errors == ["err1", "err2"]
        assert "failed" in str(e)

    def test_validation_error_no_errors(self):
        e = SkillValidationError("failed")
        assert e.errors == []

    def test_capability_error_with_missing(self):
        e = CapabilityError({"perm_a", "perm_b"})
        assert e.missing == {"perm_a", "perm_b"}
        assert "Missing" in str(e)

    def test_capability_error_custom_message(self):
        e = CapabilityError({"x"}, message="custom msg")
        assert str(e) == "custom msg"

    def test_resource_constraint_error(self):
        e = ResourceConstraintError("rate limit")
        assert isinstance(e, SkillError)

    def test_information_flow_error(self):
        e = InformationFlowError("sensitive", "public")
        assert e.flow_from == "sensitive"
        assert e.flow_to == "public"
        assert "Forbidden flow" in str(e)

    def test_url_not_allowed(self):
        e = URLNotAllowedError("https://bad.com")
        assert isinstance(e, SkillError)

    def test_url_blocked(self):
        e = URLBlockedError("https://bad.onion")
        assert isinstance(e, SkillError)

    def test_forbidden_column_error(self):
        e = ForbiddenColumnError({"password", "ssn"})
        assert e.columns == {"password", "ssn"}
        assert "Forbidden columns" in str(e)

    def test_path_not_allowed(self):
        e = PathNotAllowedError("/etc/passwd")
        assert isinstance(e, SkillError)

    def test_hierarchy(self):
        """All skill errors inherit from SkillError."""
        for cls in [
            SkillNotFoundError, SkillValidationError,
            ResourceConstraintError, URLNotAllowedError,
            URLBlockedError, PathNotAllowedError,
        ]:
            assert issubclass(cls, SkillError)
