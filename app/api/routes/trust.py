from fastapi import APIRouter, Response
from pydantic import BaseModel
import os
import logging
from agentsafe.verification_graph.tools import VerificationGraphTools

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trust", tags=["trust"])

def _get_tools() -> VerificationGraphTools:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")
    return VerificationGraphTools(dsn)

def _generate_svg(status: str, color: str) -> str:
    # A simple, clean, dynamic SVG for GitHub READMEs
    width = 150
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="{width}" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h65v20H0z"/>
    <path fill="{color}" d="M65 0h85v20H65z"/>
    <path fill="url(#b)" d="M0 0h{width}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="32.5" y="15" fill="#010101" fill-opacity=".3">Certior</text>
    <text x="32.5" y="14">Certior</text>
    <text x="106.5" y="15" fill="#010101" fill-opacity=".3">{status}</text>
    <text x="106.5" y="14">{status}</text>
  </g>
</svg>"""

@router.get("/badge")
async def get_trust_badge(repo: str, commit: str | None = None):
    """
    Trust-badge endpoint.

    Returns an SVG badge indicating the agent's current formal trust
    status, suitable for embedding in a README.
    """
    try:
        tools = _get_tools()
        raw_result = await tools.release_decision(repo_root=repo, commit_sha=commit)
        decision_dict = raw_result.get("decision", {})
        
        if decision_dict.get("decision_status") == "attested":
            svg = _generate_svg("Assured", "#4c1") # Green
        else:
            svg = _generate_svg("Blocked", "#e05d44") # Red
            
        return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": "no-cache"})
    except Exception as e:
        log.error(f"Failed to generate trust badge for {repo}: {e}")
        # Default to neutral/unknown on error
        svg = _generate_svg("Unknown", "#9f9f9f") # Grey
        return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": "no-cache"})
