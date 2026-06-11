"""
Production-ready use-case templates for single-agent and multi-agent operation.
"""
from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, List

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1", tags=["use-cases"])


def _studio_url() -> str:
  return os.getenv("CERTIOR_STUDIO_URL", "http://127.0.0.1:3001")


class UseCaseTaskTemplate(BaseModel):
    name: str
    purpose: str
    payload: Dict[str, Any]


class MultiAgentWorkflowTemplate(BaseModel):
    name: str
    orchestration_pattern: str
    stages: List[UseCaseTaskTemplate]


class ProductionUseCasesResponse(BaseModel):
    auth_hint: str
    single_agent: UseCaseTaskTemplate
    multi_agent: MultiAgentWorkflowTemplate


class StageDefinition(BaseModel):
    stage_id: str
    role: str
    compliance_policy: str
    depends_on: List[str]
    success_criteria: str
    request_payload: Dict[str, Any]


class RunbookStep(BaseModel):
    step: int
    action: str
    endpoint: str
    method: str
    expected_outcome: str


class ProductionPlaybookResponse(BaseModel):
    architecture: str
    auth_strategy: str
    single_agent_controls: List[str]
    multi_agent_controls: List[str]
    multi_agent_stages: List[StageDefinition]
    runbook: List[RunbookStep]
    operational_kpis: List[str]


class DemoStep(BaseModel):
    step: int
    title: str
    objective: str
    command: str
    expected_result: str


class ProductionDemoResponse(BaseModel):
    prerequisites: List[str]
    variables: Dict[str, str]
    steps: List[DemoStep]
    success_criteria: List[str]


def _render_page(title: str, subtitle: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} - Certior</title>
<style>
*{{box-sizing:border-box}} body{{margin:0;font-family:Inter,system-ui,-apple-system,sans-serif;background:#020617;color:#cbd5e1}}
.wrap{{max-width:980px;margin:0 auto;padding:2rem}}
.top{{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1rem}}
.brand{{font-size:1.3rem;color:#f1f5f9;font-weight:700}}
.nav a{{color:#93c5fd;text-decoration:none;font-size:.9rem;margin-left:.9rem}}
.hero{{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:1.25rem 1.35rem;margin:1rem 0 1.1rem}}
.hero h1{{margin:0 0 .3rem;color:#f8fafc;font-size:1.3rem}}
.hero p{{margin:0;color:#94a3b8;font-size:.94rem}}
.grid{{display:grid;grid-template-columns:1fr;gap:.9rem}}
.card{{background:#0b1220;border:1px solid #1e293b;border-radius:12px;padding:1rem 1.05rem}}
.card h2{{margin:.1rem 0 .55rem;font-size:1rem;color:#e2e8f0}}
.muted{{color:#94a3b8;font-size:.9rem}}
pre{{margin:.5rem 0 0;background:#020617;border:1px solid #334155;border-radius:8px;padding:.7rem;overflow:auto;color:#a7f3d0;font-size:.78rem;line-height:1.35}}
ul{{margin:.3rem 0 .2rem 1.1rem;padding:0}} li{{margin:.35rem 0}}
.step{{border-top:1px solid #1e293b;padding-top:.75rem;margin-top:.75rem}}
.pill{{display:inline-block;border:1px solid #334155;border-radius:999px;padding:.15rem .55rem;font-size:.72rem;color:#93c5fd}}
</style>
</head>
<body><div class="wrap">
  <div class="top"><div class="brand">Certior Production Guides</div><div class="nav">
    <a href="/">Home</a><a href="/docs">Docs</a><a href="/api/v1/use-cases/production/page">Templates</a>
    <a href="/api/v1/use-cases/production/playbook/page">Playbook</a>
    <a href="/api/v1/use-cases/production/demo/page">Live Demo</a>
  </div></div>
  <section class="hero"><h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></section>
  <div class="grid">{body}</div>
</div></body></html>"""
    )


def _json_pre(data: Any) -> str:
    return f"<pre>{html.escape(json.dumps(data, indent=2))}</pre>"


@router.get("/use-cases/production", response_model=ProductionUseCasesResponse)
async def production_use_cases() -> ProductionUseCasesResponse:
    """Return high-signal production templates for single-agent and multi-agent execution."""
    return ProductionUseCasesResponse(
        auth_hint="Send API key via Authorization: Bearer <ck-...> or X-API-Key header.",
        single_agent=UseCaseTaskTemplate(
            name="HIPAA-compliant patient discharge summary",
            purpose=(
                "Single-agent workflow demonstrating PHI-safe clinical summarization "
                "with Z3-proven data classification, Lean4 information flow control, "
                "and Dafny-verified capability attenuation."
            ),
            payload={
                "task": (
                    "Summarize the following patient encounter into a discharge summary "
                    "with diagnosis, treatment plan, and follow-up instructions. "
                    "Redact all direct patient identifiers (name, SSN, DOB, MRN). "
                    "Apply minimum-necessary principle - include only clinically relevant details.\n\n"
                    "--- ENCOUNTER NOTES ---\n"
                    "Patient: Jane Doe, DOB 1987-04-12, MRN 00482917, SSN 321-54-9876\n"
                    "Admission: 2026-02-28. Discharge: 2026-03-04.\n"
                    "Chief Complaint: Acute chest pain radiating to left arm, onset 6 hours prior.\n"
                    "History: Type 2 diabetes (metformin 1000mg BID), hypertension (lisinopril 20mg daily), "
                    "former smoker (quit 2019). Family history of MI (father, age 58).\n"
                    "Hospital Course: Troponin I elevated at 2.4 ng/mL on admission. "
                    "ECG showed ST-segment depression in leads V3-V5. Cardiology consult obtained. "
                    "Cardiac catheterization on 03-01 revealed 85% stenosis of the LAD. "
                    "Successful PCI with drug-eluting stent placement. Post-procedure EF 52%. "
                    "Started on dual antiplatelet therapy (aspirin 81mg + clopidogrel 75mg). "
                    "Monitored 72h; no recurrent chest pain, stable hemodynamics.\n"
                    "Discharge Dx: NSTEMI secondary to LAD stenosis, s/p PCI with DES.\n"
                    "Discharge Meds: Aspirin 81mg daily, Clopidogrel 75mg daily x12 months, "
                    "Atorvastatin 80mg daily, Metoprolol succinate 50mg daily, "
                    "Metformin 1000mg BID, Lisinopril 20mg daily.\n"
                    "Follow-up: Cardiology in 2 weeks, PCP in 1 week, cardiac rehab referral placed.\n"
                    "--- END NOTES ---"
                ),
                "compliance_policy": "hipaa",
                "budget_cents": 2000,
                "provider": "openai",
                "model": "gpt-4o",
            },
        ),
        multi_agent=MultiAgentWorkflowTemplate(
            name="Clinical intake → Privacy review → Release decision",
            orchestration_pattern=(
                "Sequential pipeline: Agent A generates clinical draft, "
                "Agent B reviews for PHI/privilege leakage, "
                "Agent C makes release decision based on review outcome. "
                "Each stage runs under its own compliance policy with independent verification."
            ),
            stages=[
                UseCaseTaskTemplate(
                    name="Agent A - Clinical intake specialist",
                    purpose=(
                        "Generates a structured, minimum-necessary clinical intake note. "
                        "Z3 verifies PHI access permissions and data classification levels. "
                        "Lean4 proves no sensitive-to-public information downgrade."
                    ),
                    payload={
                        "task": (
                            "From the provided encounter notes, generate a structured intake note "
                            "with: chief complaint, history of present illness, assessment, and plan. "
                            "Classify each section's sensitivity level. "
                            "Redact all direct identifiers per HIPAA Safe Harbor.\n\n"
                            "--- ENCOUNTER NOTES ---\n"
                            "Patient: Jane Doe, DOB 1987-04-12, MRN 00482917, SSN 321-54-9876\n"
                            "Admission: 2026-02-28. Discharge: 2026-03-04.\n"
                            "Chief Complaint: Acute chest pain radiating to left arm, onset 6 hours prior.\n"
                            "History: Type 2 diabetes (metformin 1000mg BID), hypertension (lisinopril 20mg daily), "
                            "former smoker (quit 2019). Family history of MI (father, age 58).\n"
                            "Hospital Course: Troponin I elevated at 2.4 ng/mL. ECG: ST-depression V3-V5. "
                            "Cath on 03-01: 85% LAD stenosis. PCI with DES. Post-procedure EF 52%. "
                            "DAPT started (ASA 81mg + clopidogrel 75mg). Stable 72h.\n"
                            "Discharge Dx: NSTEMI s/p PCI with DES.\n"
                            "Discharge Meds: ASA 81mg, Clopidogrel 75mg x12mo, Atorvastatin 80mg, "
                            "Metoprolol XL 50mg, Metformin 1000mg BID, Lisinopril 20mg.\n"
                            "Follow-up: Cardiology 2wk, PCP 1wk, cardiac rehab referral.\n"
                            "--- END NOTES ---"
                        ),
                        "compliance_policy": "hipaa",
                        "budget_cents": 1500,
                        "provider": "openai",
                        "model": "gpt-4o",
                    },
                ),
                UseCaseTaskTemplate(
                    name="Agent B - Privacy & privilege reviewer",
                    purpose=(
                        "Reviews Agent A's output for residual PHI, privileged content, "
                        "or minimum-necessary violations. Z3 verifies privilege boundary "
                        "constraints. Returns structured GO/NO-GO assessment."
                    ),
                    payload={
                        "task": (
                            "Review the clinical intake note for: "
                            "(1) any residual PHI or re-identification risk, "
                            "(2) attorney-client or work-product privilege leakage, "
                            "(3) minimum-necessary compliance. "
                            "Return a structured assessment with GO/NO-GO recommendation "
                            "and specific findings for each category."
                        ),
                        "compliance_policy": "legal_privilege",
                        "budget_cents": 1200,
                        "provider": "openai",
                        "model": "gpt-4o",
                    },
                ),
                UseCaseTaskTemplate(
                    name="Agent C - Release coordinator",
                    purpose=(
                        "Makes final release decision based on Agent B's review. "
                        "Only releases if review returned GO. Generates audit-ready "
                        "compliance attestation."
                    ),
                    payload={
                        "task": (
                            "Based on the privacy review assessment: "
                            "if GO - produce the final release package with attestation; "
                            "if NO-GO - produce a hold notice with remediation steps required."
                        ),
                        "compliance_policy": "default",
                        "budget_cents": 800,
                        "provider": "openai",
                        "model": "gpt-4o",
                    },
                ),
            ],
        ),
    )


@router.get("/use-cases/production/page", include_in_schema=False)
async def production_use_cases_page() -> HTMLResponse:
    data = await production_use_cases()
    body = (
        f'<section class="card"><h2>Authentication</h2><p class="muted">{html.escape(data.auth_hint)}</p></section>'
        f'<section class="card"><h2>Single-agent template</h2><p class="muted">{html.escape(data.single_agent.purpose)}</p>{_json_pre(data.single_agent.payload)}</section>'
        f'<section class="card"><h2>Multi-agent pattern</h2><p class="muted">{html.escape(data.multi_agent.orchestration_pattern)}</p></section>'
    )
    for stage in data.multi_agent.stages:
        body += (
            f'<section class="card"><h2>{html.escape(stage.name)}</h2>'
            f'<p class="muted">{html.escape(stage.purpose)}</p>{_json_pre(stage.payload)}</section>'
        )
    return _render_page(
        title="Production templates",
        subtitle="Polished reference templates for single-agent and multi-agent submissions.",
        body=body,
    )


@router.get("/use-cases/production/playbook", response_model=ProductionPlaybookResponse)
async def production_playbook() -> ProductionPlaybookResponse:
    """Return an in-depth production playbook for enterprise orchestration."""
    return ProductionPlaybookResponse(
        architecture=(
            "Coordinator-driven multi-agent framework: each specialist stage runs as an independent "
            "execution with explicit compliance policy boundaries, then a final reviewer stage makes release decision."
        ),
        auth_strategy=(
            "Use dedicated service API key per environment, rotate via /api/v1/auth/rotate, and "
            "avoid embedding keys in browser URLs."
        ),
        single_agent_controls=[
            "Pin compliance policy (e.g., hipaa) on every request.",
            "Set explicit budget_cents per execution to cap spend.",
            "Export compliance package after completion for immutable evidence.",
        ],
        multi_agent_controls=[
            "Use stricter policy for reviewer stage than intake stage.",
            "Treat every stage output as untrusted input for downstream stages.",
            "Block release when reviewer stage status is failed/blocked/cancelled.",
            "Persist execution IDs and attach compliance exports to ticketing system.",
        ],
        multi_agent_stages=[
            StageDefinition(
                stage_id="intake",
                role="Clinical intake specialist",
                compliance_policy="hipaa",
                depends_on=[],
                success_criteria=(
                    "Structured clinical note produced with sensitivity labels "
                    "and all direct identifiers redacted per Safe Harbor."
                ),
                request_payload={
                    "task": (
                        "From the provided encounter notes, generate a structured intake note "
                        "with: chief complaint, HPI, assessment, and plan. "
                        "Classify each section's sensitivity level. "
                        "Redact all direct identifiers per HIPAA Safe Harbor.\n\n"
                        "--- ENCOUNTER NOTES ---\n"
                        "Patient: Jane Doe, DOB 1987-04-12, MRN 00482917, SSN 321-54-9876\n"
                        "Admission: 2026-02-28. Discharge: 2026-03-04.\n"
                        "Chief Complaint: Acute chest pain radiating to left arm.\n"
                        "History: T2DM, HTN, former smoker. Family hx MI.\n"
                        "Course: Troponin 2.4, ST-depression V3-V5. Cath: 85% LAD. "
                        "PCI with DES. EF 52%. DAPT started. Stable 72h.\n"
                        "Dx: NSTEMI s/p PCI. Meds: ASA, Plavix, statin, BB, metformin, ACEi.\n"
                        "F/U: Cards 2wk, PCP 1wk, cardiac rehab.\n"
                        "--- END NOTES ---"
                    ),
                    "compliance_policy": "hipaa",
                    "budget_cents": 1500,
                    "provider": "openai",
                    "model": "gpt-4o",
                },
            ),
            StageDefinition(
                stage_id="review",
                role="Privacy/legal reviewer",
                compliance_policy="legal_privilege",
                depends_on=["intake"],
                success_criteria=(
                    "GO/NO-GO decision with structured findings for PHI, "
                    "privilege leakage, and minimum-necessary compliance."
                ),
                request_payload={
                    "task": (
                        "Review the clinical intake note for: "
                        "(1) residual PHI or re-identification risk, "
                        "(2) privilege leakage, "
                        "(3) minimum-necessary compliance. "
                        "Return structured GO/NO-GO with findings per category."
                    ),
                    "compliance_policy": "legal_privilege",
                    "budget_cents": 1200,
                    "provider": "openai",
                    "model": "gpt-4o",
                },
            ),
            StageDefinition(
                stage_id="release",
                role="Release coordinator",
                compliance_policy="default",
                depends_on=["review"],
                success_criteria="Final package released only if review returned GO.",
                request_payload={
                    "task": (
                        "Based on the privacy review: "
                        "if GO - produce final release package with attestation; "
                        "if NO-GO - produce hold notice with remediation steps."
                    ),
                    "compliance_policy": "default",
                    "budget_cents": 800,
                    "provider": "openai",
                    "model": "gpt-4o",
                },
            ),
        ],
        runbook=[
            RunbookStep(
                step=1,
                action="Submit stage task",
                endpoint="/api/v1/tasks",
                method="POST",
                expected_outcome="201 with execution_id and websocket_url",
            ),
            RunbookStep(
                step=2,
                action="Track stage status",
                endpoint="/api/v1/executions/{execution_id}",
                method="GET",
                expected_outcome="status reaches completed/failed/blocked/cancelled",
            ),
            RunbookStep(
                step=3,
                action="Stream events during execution",
                endpoint="/ws/executions/{execution_id}",
                method="WS",
                expected_outcome="step-level updates and terminal state",
            ),
            RunbookStep(
                step=4,
                action="Export compliance evidence",
                endpoint="/api/v1/compliance/{execution_id}/export?preset=<policy>",
                method="GET",
                expected_outcome="JSON/PDF audit package attached to operations record",
            ),
        ],
        operational_kpis=[
            "Task completion rate by policy",
            "Policy-ceiling denial rate (403) by team/workload",
            "Median execution latency per stage",
            "Audit export success rate",
        ],
    )


@router.get("/use-cases/production/playbook/page", include_in_schema=False)
async def production_playbook_page() -> HTMLResponse:
    data = await production_playbook()
    controls = "".join(f"<li>{html.escape(v)}</li>" for v in data.single_agent_controls)
    mcontrols = "".join(f"<li>{html.escape(v)}</li>" for v in data.multi_agent_controls)
    kpis = "".join(f"<li>{html.escape(v)}</li>" for v in data.operational_kpis)
    body = (
        f'<section class="card"><h2>Architecture</h2><p class="muted">{html.escape(data.architecture)}</p></section>'
        f'<section class="card"><h2>Authentication strategy</h2><p class="muted">{html.escape(data.auth_strategy)}</p></section>'
        f'<section class="card"><h2>Single-agent controls</h2><ul>{controls}</ul></section>'
        f'<section class="card"><h2>Multi-agent controls</h2><ul>{mcontrols}</ul></section>'
    )
    for stage in data.multi_agent_stages:
        deps = ", ".join(stage.depends_on) if stage.depends_on else "none"
        body += (
            f'<section class="card"><h2>Stage: {html.escape(stage.stage_id)}</h2>'
            f'<p class="muted"><span class="pill">{html.escape(stage.role)}</span> '
            f'policy={html.escape(stage.compliance_policy)} depends_on={html.escape(deps)}</p>'
            f'<p class="muted">{html.escape(stage.success_criteria)}</p>{_json_pre(stage.request_payload)}</section>'
        )
    runbook_items = "".join(
        f'<div class="step"><h2>Step {s.step}: {html.escape(s.action)}</h2>'
        f'<p class="muted">{html.escape(s.method)} {html.escape(s.endpoint)}</p>'
        f'<p class="muted">Expected: {html.escape(s.expected_outcome)}</p></div>'
        for s in data.runbook
    )
    body += f'<section class="card"><h2>Runbook</h2>{runbook_items}</section>'
    body += f'<section class="card"><h2>Operational KPIs</h2><ul>{kpis}</ul></section>'
    return _render_page(
        title="Production playbook",
        subtitle="Governance and orchestration controls for complex multi-agent deployments.",
        body=body,
    )


@router.get("/use-cases/production/demo", response_model=ProductionDemoResponse)
async def production_demo() -> ProductionDemoResponse:
    """Return an executable end-to-end demo with real API steps."""
    return ProductionDemoResponse(
        prerequisites=[
            "Server running at http://127.0.0.1:8000",
            "A valid Certior API key (ck-...)",
            "jq installed for parsing JSON in shell",
        ],
        variables={
            "BASE_URL": "http://127.0.0.1:8000",
            "CERTIOR_API_KEY": "ck-REPLACE_ME",
            "MODEL": "gpt-4o",
        },
        steps=[
            DemoStep(
                step=1,
                title="Check server health",
                objective="Verify platform is up before task submission.",
                command='curl -sS "$BASE_URL/health" | jq',
                expected_result='JSON with {"status":"ok"} and mode/tool metadata.',
            ),
            DemoStep(
                step=2,
                title="Switch provider/model",
                objective="Pin runtime to OpenAI model used by your production demo.",
                command=(
                    "curl -sS -X POST \"$BASE_URL/api/v1/settings/provider\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" "
                    "-H \"Content-Type: application/json\" "
                    "-d '{\"provider\":\"openai\",\"model\":\"'\"$MODEL\"'\"}' | jq"
                ),
                expected_result='200 response with "Switched to OpenAI (GPT) (...)" message.',
            ),
            DemoStep(
                step=3,
                title="Run single-agent HIPAA task",
                objective="Execute HIPAA-compliant clinical summarization with policy-matched verification.",
                command=(
                    "SINGLE_EX=$(curl -sS -X POST \"$BASE_URL/api/v1/tasks\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" -H \"Content-Type: application/json\" "
                    "-d '{\"task\":\"Summarize a patient encounter into a discharge summary. "
                    "Redact all direct identifiers. Apply minimum-necessary principle.\","
                    "\"compliance_policy\":\"hipaa\",\"budget_cents\":2000,"
                    "\"provider\":\"openai\",\"model\":\"'\"$MODEL\"'\"}' | jq -r .execution_id); "
                    "echo \"$SINGLE_EX\""
                ),
                expected_result="Prints a non-empty execution UUID.",
            ),
            DemoStep(
                step=4,
                title="Poll single-agent execution",
                objective="Wait until the run reaches terminal state.",
                command=(
                    "while true; do "
                    "STATUS=$(curl -sS \"$BASE_URL/api/v1/executions/$SINGLE_EX\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" | jq -r .status); "
                    "echo \"single-agent status=$STATUS\"; "
                    "case \"$STATUS\" in completed|failed|blocked|cancelled) break;; esac; "
                    "sleep 2; "
                    "done"
                ),
                expected_result="Status transitions and ends at completed (or other terminal status).",
            ),
            DemoStep(
                step=5,
                title="Run multi-agent stage A (clinical intake)",
                objective="Launch clinical intake specialist under HIPAA with Z3 PHI-access verification.",
                command=(
                    "EX_A=$(curl -sS -X POST \"$BASE_URL/api/v1/tasks\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" -H \"Content-Type: application/json\" "
                    "-d '{\"task\":\"Generate structured intake note with sensitivity labels. "
                    "Redact all direct identifiers per HIPAA Safe Harbor.\","
                    "\"compliance_policy\":\"hipaa\",\"budget_cents\":1500,"
                    "\"provider\":\"openai\",\"model\":\"'\"$MODEL\"'\"}' | jq -r .execution_id); "
                    "echo \"$EX_A\""
                ),
                expected_result="Prints stage A execution UUID.",
            ),
            DemoStep(
                step=6,
                title="Run multi-agent stage B (privacy reviewer)",
                objective="Launch privacy/privilege reviewer with Z3 privilege-boundary verification.",
                command=(
                    "EX_B=$(curl -sS -X POST \"$BASE_URL/api/v1/tasks\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" -H \"Content-Type: application/json\" "
                    "-d '{\"task\":\"Review intake note for residual PHI, privilege leakage, "
                    "and minimum-necessary compliance. Return structured GO/NO-GO.\","
                    "\"compliance_policy\":\"legal_privilege\",\"budget_cents\":1200,"
                    "\"provider\":\"openai\",\"model\":\"'\"$MODEL\"'\"}' | jq -r .execution_id); "
                    "echo \"$EX_B\""
                ),
                expected_result="Prints stage B execution UUID.",
            ),
            DemoStep(
                step=7,
                title="Export compliance evidence",
                objective="Generate auditable compliance package for each stage.",
                command=(
                    "curl -sS \"$BASE_URL/api/v1/compliance/$SINGLE_EX/export?preset=hipaa\" "
                    "-H \"X-API-Key: $CERTIOR_API_KEY\" | jq '.attestation, .policy_applied.name'"
                ),
                expected_result="Returns attestation block and policy details for audit proof.",
            ),
        ],
        success_criteria=[
            "At least one execution reaches completed state.",
            "Compliance export returns attestation.compliant=true for valid runs.",
            "Execution IDs are persisted in your ticket/runbook.",
        ],
    )


@router.get("/use-cases/production/demo/page", include_in_schema=False)
async def production_demo_page() -> HTMLResponse:
    data = await production_demo()
    prereq = "".join(f"<li>{html.escape(v)}</li>" for v in data.prerequisites)
    vars_block = _json_pre(data.variables)
    success = "".join(f"<li>{html.escape(v)}</li>" for v in data.success_criteria)
    steps = ""
    for s in data.steps:
        steps += (
            f'<div class="step"><h2>Step {s.step}: {html.escape(s.title)}</h2>'
            f'<p class="muted">{html.escape(s.objective)}</p>'
            f'{_json_pre({"command": s.command})}'
            f'<p class="muted">Expected: {html.escape(s.expected_result)}</p></div>'
        )
    body = (
        f'<section class="card"><h2>Prerequisites</h2><ul>{prereq}</ul></section>'
        f'<section class="card"><h2>Environment variables</h2>{vars_block}</section>'
        f'<section class="card"><h2>Step-by-step execution</h2>{steps}</section>'
        f'<section class="card"><h2>Success criteria</h2><ul>{success}</ul></section>'
    )
    return _render_page(
        title="Live production demo",
        subtitle="Executable commands with expected outcomes for a real end-to-end run.",
        body=body,
    )


@router.get("/use-cases/production/studio", include_in_schema=False)
async def production_studio_page() -> HTMLResponse:
  """Redirect to the primary Certior Studio frontend."""
  return RedirectResponse(url=_studio_url(), status_code=307)
