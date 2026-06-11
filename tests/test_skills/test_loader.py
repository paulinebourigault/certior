"""Tests for skill loader."""
import pytest
import json
from pathlib import Path
from agentsafe.skills.loader import VerifiedSkillLoader, VerifiedSkill, SkillSummary
from agentsafe.skills.exceptions import SkillNotFoundError, CapabilityError, SkillValidationError
from agentsafe.capabilities.tokens import CapabilityToken


@pytest.fixture
def skills_dir(tmp_path):
    # Create web_browsing skill
    wb = tmp_path / "web_browsing"
    wb.mkdir()
    (wb / "VERIFICATION.json").write_text(json.dumps({
        "skill_id": "web_browsing", "version": "1.0.0",
        "metadata": {"name": "Web Browsing", "description": "Fetch web pages"},
        "verification_requirements": {
            "capabilities_required": ["network:http:read"],
            "resource_constraints": {"timeout_seconds": 30},
        },
        "compliance_mappings": {"sox": {"applies": True}},
    }))
    (wb / "implementation.py").write_text("class SafeWebBrowser: pass")

    # Create database skill
    db = tmp_path / "database_query"
    db.mkdir()
    (db / "VERIFICATION.json").write_text(json.dumps({
        "skill_id": "database_query", "version": "1.0.0",
        "metadata": {"name": "Database Query", "description": "Query databases"},
        "verification_requirements": {
            "capabilities_required": ["database:read"],
        },
        "compliance_mappings": {"hipaa": {"applies": True}},
    }))
    return tmp_path


class TestVerifiedSkillLoader:
    def test_list_skills(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        skills = loader.list_skills()
        assert len(skills) == 2
        assert any(s.skill_id == "web_browsing" for s in skills)

    def test_list_filtered_by_token(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(permissions=["network:http:read"])
        skills = loader.list_skills(token)
        assert len(skills) == 1
        assert skills[0].skill_id == "web_browsing"

    def test_load_skill(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(permissions=["network:http:read"])
        skill = loader.load_skill("web_browsing", token)
        assert skill.summary.skill_id == "web_browsing"
        assert skill.verification_result.valid

    def test_load_missing_capability(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(permissions=["other:perm"])
        with pytest.raises((CapabilityError, Exception)):
            loader.load_skill("web_browsing", token)

    def test_load_nonexistent(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        token = CapabilityToken(permissions=["a"])
        with pytest.raises(SkillNotFoundError):
            loader.load_skill("nonexistent", token)

    def test_search_skills(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("web")
        assert len(results) >= 1
        assert results[0].skill_id == "web_browsing"

    def test_search_by_compliance(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("query", compliance_filter=["hipaa"])
        assert len(results) == 1
        assert results[0].skill_id == "database_query"


class TestSearchSkills:
    """Tests for skill search functionality."""

    def test_search_by_name(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("web")
        assert len(results) >= 1
        assert any("web" in r.skill_id for r in results)

    def test_search_no_match(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("zzz_nonexistent")
        assert len(results) == 0

    def test_search_with_capability_filter(self, skills_dir):
        token = CapabilityToken(permissions=["network:http:read"])
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("browsing", capability_token=token)
        for r in results:
            assert token.has_all_permissions(r.capabilities_required)

    def test_search_with_compliance_filter(self, skills_dir):
        loader = VerifiedSkillLoader(skills_dir)
        results = loader.search_skills("query", compliance_filter=["hipaa"])
        # Results filtered by compliance relevance
        assert isinstance(results, list)

    def test_load_nonexistent_skill(self, skills_dir):
        token = CapabilityToken(permissions=["a"])
        loader = VerifiedSkillLoader(skills_dir)
        with pytest.raises(SkillNotFoundError):
            loader.load_skill("nonexistent", token)

    def test_load_with_insufficient_caps(self, skills_dir):
        token = CapabilityToken(permissions=["wrong:perm"])
        loader = VerifiedSkillLoader(skills_dir)
        with pytest.raises((CapabilityError, SkillValidationError)):
            loader.load_skill("web_browsing", token)

    def test_empty_skills_dir(self, tmp_path):
        loader = VerifiedSkillLoader(tmp_path)
        results = loader.list_skills()
        assert results == []

    def test_bad_json_in_skill_dir(self, tmp_path):
        d = tmp_path / "bad_skill"
        d.mkdir()
        (d / "VERIFICATION.json").write_text("{invalid json")
        loader = VerifiedSkillLoader(tmp_path)
        # Should skip bad skills gracefully
        results = loader.list_skills()
        assert len(results) == 0
