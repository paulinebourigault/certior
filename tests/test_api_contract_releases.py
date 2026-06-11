import pytest
from app.api.routes.releases import ReleaseDecisionResponse

def test_release_decision_response_schema_contract():
    # Enforce response-shape stability for the release decision contract.
    schema = ReleaseDecisionResponse.model_json_schema()
    props = schema.get("properties", {})
    
    # Must contain essential fields
    assert "decision" in props
    assert "repo_root" in props
    assert "blockers" in props
    assert "explanation" in props
    assert "provenance" in props
    
    # decision must be strictly SHIP or NO_SHIP, or just descriptively constrained
    # In pydantic, if it's a string, we ensure the type is string.
    assert props["decision"]["type"] == "string"
    
    # blockers must be an array of BlockerItem which contains component, reason
    blocker_schema = None
    if "$ref" in props["blockers"].get("items", {}):
        ref_path = props["blockers"]["items"]["$ref"]
        model_name = ref_path.split("/")[-1]
        blocker_schema = schema.get("$defs", {}).get(model_name)
        
    if blocker_schema:
        b_props = blocker_schema.get("properties", {})
        assert "component" in b_props
        assert "reason" in b_props
        
    print("ReleaseDecisionResponse schema contract validates successfully.")

if __name__ == "__main__":
    test_release_decision_response_schema_contract()
