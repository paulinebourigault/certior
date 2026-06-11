#!/usr/bin/env python3
"""
Example GitHub/Slack Approval Bot using Certior Release API.
It queries the decision API, and generates a comment payload.
"""
import os
import sys
import requests
import json

def fetch_decision(repo: str, commit: str) -> dict:
    api_url = os.getenv("CERTIOR_API_URL", "http://localhost:8000")
    resp = requests.get(
        f"{api_url}/api/v1/releases/decision",
        params={"repo_root": repo, "commit_sha": commit}
    )
    resp.raise_for_status()
    return resp.json()

def generate_report(decision_data: dict) -> str:
    decision = decision_data.get("decision", "NO_SHIP")
    if decision == "SHIP":
        return f"✅ **Certior Release Approved**: Ready to ship."
    
    blockers = decision_data.get("blockers", [])
    report = [f"❌ **Certior Release Rejected** ({len(blockers)} blocker(s))"]
    
    for b in blockers:
        report.append(f"- **{b.get('component')}**: {b.get('reason')}")
        if b.get('remediation_suggestion'):
            report.append(f"  _Fix_: `{b.get('remediation_suggestion')}`")
            
    return "\n".join(report)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: approval_bot.py <repo> <commit_sha>")
        sys.exit(1)
        
    repo, commit = sys.argv[1], sys.argv[2]
    try:
        data = fetch_decision(repo, commit)
        print(generate_report(data))
    except Exception as e:
        print(f"Failed to check Certior API: {e}")
        sys.exit(1)
