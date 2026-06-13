"""
Certior playground — watch an AI agent get caught.

The agent transcripts are faithful replays of real GPT-4o runs (recorded in
demos/live/). Every Certior verdict on this page — allow, block, and the signed
receipt — is computed live with real Z3 at the moment you click, by the same
`certior` package that's on PyPI.
"""
import base64
import html
import pathlib

import gradio as gr
from certior import Guard

from storyboards import SCENARIOS

POLICY = "hipaa"

# warm palette — coherent with certior.io
CREAM = "#f8efe3"; CARD = "#fffdf8"; INK = "#2a2017"; MUTED = "#7a6a58"; BODY = "#5c4f42"
GOLD = "#b56b2a"; GREEN = "#157a3a"; RED = "#c1392b"
BALOO = "'Baloo 2',system-ui,sans-serif"

# the real logo, base64-embedded so the header matches certior.io (falls back to 🛡️)
try:
    _logo = base64.b64encode((pathlib.Path(__file__).parent / "logo.png").read_bytes()).decode()
    LOGO = f"<img src='data:image/png;base64,{_logo}' alt='' style='height:36px;vertical-align:-9px;margin-right:9px'/>"
except Exception:
    LOGO = "🛡️ "

# Studio glass-box loop, base64-embedded so it plays on the Space with no file-serving
# config (falls back to the hosted copy on certior.io if the bundled file is missing).
try:
    _vid = base64.b64encode((pathlib.Path(__file__).parent / "studio-hero-loop.mp4").read_bytes()).decode()
    STUDIO_SRC = f"data:video/mp4;base64,{_vid}"
except Exception:
    STUDIO_SRC = "https://certior.io/studio-hero-loop.mp4"

# Lean attestation (static per policy revision). The model the live Z3 verdicts
# enforce is machine-checked in Lean 4; we surface its fingerprint and the one
# command that re-checks it (0 `sorry`, standard axioms only) on every receipt.
try:
    _att = Guard(policy=POLICY, permissions=["*"]).policy_attestation
    LEAN_FP = _att["fingerprint"]
    LAKE_CMD = _att["audit_command"]
except Exception:
    LEAN_FP = ""
    LAKE_CMD = "cd lean4/CertiorLattice && lake build Certior.Audit"


# ── live Certior verdicts (Z3) ────────────────────────
def verify(need, held):
    g = Guard(policy=POLICY, permissions=list(held), agent_id="agent")
    return g.verify(tool="action", required_capabilities=list(need), cost_cents=1)


def verify_step(step):
    """Live verdict for one step — handles capability and budget gates."""
    if "budget" in step:
        g = Guard(policy="default", permissions=["compute:run"],
                  budget_cents=step["budget"], agent_id="orchestrator")
        return g.verify(tool="action", required_capabilities=["compute:run"],
                        cost_cents=step["cost"])
    return verify(step["need"], step["held"])


def _chip(text, color, bg):
    return (f"<span style='font:800 11px Nunito,sans-serif;color:{color};"
            f"background:{bg};padding:3px 9px;border-radius:999px;white-space:nowrap'>{text}</span>")


def _step_row(step, enforced):
    actor = html.escape(step["actor"]); tool = html.escape(step["tool"]); ret = html.escape(step["ret"])
    need = "budget" if "budget" in step else " ".join(step["need"])

    if not enforced:
        badge = _chip("▶ executed", RED, "rgba(239,107,107,.16)"); border = "rgba(193,57,43,.22)"; bg = "rgba(239,107,107,.05)"
    else:
        r = verify_step(step)
        if r.allowed:
            badge = _chip("✓ allowed", GREEN, "rgba(22,163,74,.14)"); border = "rgba(22,163,74,.28)"; bg = "rgba(22,163,74,.05)"
        else:
            badge = _chip("✗ BLOCKED", RED, "rgba(239,107,107,.2)"); border = "rgba(193,57,43,.5)"; bg = "rgba(239,107,107,.09)"

    return f"""
    <div style="border:1px solid {border};border-radius:12px;padding:10px 12px;margin:8px 0;background:{bg}">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
        <code style="font:700 12.5px ui-monospace,monospace;color:{INK}">{actor} → {tool}</code>
        {badge}
      </div>
      <div style="font-size:11.5px;color:{MUTED};margin-top:5px">needs <code style="color:{GOLD}">{html.escape(need)}</code></div>
      <div style="font-size:12px;color:{BODY};margin-top:4px">{ret}</div>
    </div>"""


def _cert_html(r):
    """Render the signed receipt for an allowed VerifyResult, with the Lean
    fingerprint and the one command that re-verifies the policy model offline."""
    if r is None or r.certificate is None:
        return ""
    c = r.certificate.to_dict()
    props = "".join(
        f"<div style='font:700 11px ui-monospace,monospace;color:{GREEN}'>✓ {html.escape(p)}</div>"
        for p in c["verified_properties"])
    lean = (f"<div style='font:600 10.5px ui-monospace,monospace;color:{MUTED};margin-top:6px'>"
            f"policy model machine-checked in Lean 4 · fingerprint {html.escape(LEAN_FP)}</div>"
            f"<div style='font:600 10.5px ui-monospace,monospace;color:{MUTED};margin-top:2px'>"
            f"re-verify it yourself: <span style='color:{GOLD}'>{html.escape(LAKE_CMD)}</span></div>")
    return f"""
    <div style="border:1px dashed rgba(22,163,74,.45);border-radius:12px;padding:12px;margin-top:10px;background:rgba(22,163,74,.07)">
      <div style="font:800 11px Nunito,sans-serif;color:{GREEN};letter-spacing:1px">SIGNED RECEIPT · minted live by Z3</div>
      <div style="font:600 11px ui-monospace,monospace;color:{BODY};margin-top:6px">id {html.escape(c['id'][:18])}…</div>
      <div style="font:600 11px ui-monospace,monospace;color:{BODY}">theorem {html.escape(c['theorem'])}</div>
      <div style="margin-top:6px">{props}</div>
      <div style="font:600 11px ui-monospace,monospace;color:{MUTED};margin-top:6px">prover {c['prover']} · verifiable offline</div>
      {lean}
    </div>"""


def _receipt_html(step):
    return _cert_html(verify_step(step))


def _col(title, sub, color, inner):
    return f"""
    <div style="border:1px solid {color}33;border-radius:18px;padding:16px;background:{CARD};height:100%;box-shadow:0 18px 40px -26px rgba(58,36,16,.35)">
      <div style="font-family:{BALOO};font-weight:800;font-size:15px;color:{color};letter-spacing:.2px">{title}</div>
      <div style="font-size:12px;color:{MUTED};margin:2px 0 10px">{sub}</div>
      {inner}
    </div>"""


def run_scenario(key):
    sc = SCENARIOS[key]; steps = sc["steps"]

    off_rows = "".join(_step_row(s, enforced=False) for s in steps)
    off_tail = (f"<div style='font-size:11.5px;color:{MUTED};font-style:italic;margin:6px 2px'>"
                f"{html.escape(sc['off_tail'])}</div>" if sc.get("off_tail") else "")
    off_verdict = f"""
      <div style="margin-top:12px;border-radius:14px;padding:12px;background:rgba(239,107,107,.12);border:1px solid rgba(193,57,43,.35)">
        <div style="font-family:{BALOO};font-weight:800;font-size:17px;color:{RED}">☠ {html.escape(sc.get('off_label', 'BREACH'))}</div>
        <div style="font-size:12px;color:#9a4339;margin-top:3px">{html.escape(sc['off_outcome'])}</div>
      </div>"""
    off = _col("WITHOUT CERTIOR", "the agent is on its own", RED, off_rows + off_tail + off_verdict)

    on_rows = "".join(_step_row(s, enforced=True) for s in steps)
    blocked = next((s for s in steps if not verify_step(s).allowed), None)
    reason = verify_step(blocked).reason if blocked else ""
    on_verdict = f"""
      <div style="margin-top:12px;border-radius:14px;padding:12px;background:rgba(22,163,74,.12);border:1px solid rgba(22,163,74,.4)">
        <div style="font-family:{BALOO};font-weight:800;font-size:17px;color:{GREEN}">🛡 {html.escape(sc.get('on_label', 'BLOCKED'))}</div>
        <div style="font:700 12px ui-monospace,monospace;color:{GREEN};margin-top:4px">CertiorBlocked: {html.escape(reason)}</div>
        <div style="font-size:12px;color:#3f6b4a;margin-top:4px">{html.escape(sc['on_outcome'])}</div>
      </div>"""
    on = _col("WITH CERTIOR", "every action proven before it runs", GREEN,
              on_rows + _receipt_html(steps[0]) + on_verdict)

    return gr.update(value=off, visible=True), gr.update(value=on, visible=True)


def setup_html(key):
    sc = SCENARIOS[key]
    return f"""
    <div style="border:1px solid rgba(42,32,23,.12);border-radius:18px;padding:16px 18px;background:{CARD};box-shadow:0 18px 40px -28px rgba(58,36,16,.3)">
      <div style="font-family:{BALOO};font-weight:800;font-size:19px;color:{INK}">{sc['emoji']} {sc['title']}</div>
      <div style="font:800 11px Nunito,sans-serif;color:{GOLD};letter-spacing:.5px;margin:3px 0 10px">{sc['subtitle'].upper()}</div>
      <div style="font-size:13.5px;color:{BODY};line-height:1.65">{sc['setup']}</div>
    </div>"""


# ── live "build your own boundary" verifier (real Z3, no API key) ──────
CAP_CHOICES = ["network:http:read", "network:http:write", "filesystem:read",
               "filesystem:write", "db:read", "db:write", "email:send", "secrets:read"]


def _verdict_card(title, detail, color, bg, border):
    return (f"<div style='border-radius:14px;padding:13px 15px;background:{bg};border:1px solid {border}'>"
            f"<div style='font-family:{BALOO};font-weight:800;font-size:17px;color:{color}'>{title}</div>"
            f"<div style='font:700 12px ui-monospace,monospace;color:{color};margin-top:4px'>{html.escape(detail)}</div></div>")


def build_boundary(held, need, budget, cost, content):
    """Run a real Guard.verify() on user-chosen inputs — live Z3, no API key."""
    g = Guard(policy=POLICY, permissions=list(held), budget_cents=int(budget), agent_id="you")
    r = g.verify(tool="your_action", required_capabilities=list(need),
                 cost_cents=int(cost), content=(content or None))
    if r.allowed:
        card = _verdict_card("✓ ALLOWED",
                             "every required capability is held, within budget, content clean",
                             GREEN, "rgba(22,163,74,.12)", "rgba(22,163,74,.4)")
        body = card + _cert_html(r)
    else:
        viol = "; ".join(f"{v.category}: {v.detail}" for v in r.violations) if r.violations else (r.reason or "")
        card = _verdict_card("✗ BLOCKED", f"CertiorBlocked: {r.reason}",
                             RED, "rgba(239,107,107,.12)", "rgba(193,57,43,.4)")
        detail = (f"<div style='font:600 11.5px ui-monospace,monospace;color:{BODY};margin-top:8px'>"
                  f"{html.escape(viol)}</div>" if viol else "")
        body = card + detail
    return gr.update(value=f"<div style='margin-top:10px'>{body}</div>", visible=True)


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Baloo+2:wght@600;700;800&family=Nunito:wght@400;600;700;800&display=swap');
.gradio-container {max-width: 1060px !important; margin: auto; background: #f8efe3 !important; font-family: 'Nunito', sans-serif !important;}
body, gradio-app {background: #f8efe3 !important;}
footer {display:none !important;}
#hero {text-align:center; padding: 10px 0 4px;}
label span, .gr-form span {font-family:'Nunito',sans-serif !important;}
#single-r, #multi-r {border:none !important; box-shadow:none !important; background:transparent !important;}
#single-r label:has(input), #multi-r label:has(input) {
  border:1px solid rgba(42,32,23,.12); border-radius:14px; padding:10px 13px; margin:4px 0;
  background:#fffdf8; transition:all .12s; font-weight:700;
}
#single-r label:has(input):hover, #multi-r label:has(input):hover {
  background:rgba(244,162,89,.16); border-color:rgba(244,162,89,.6);
}
#run-btn, #run-btn button {
  background:#f4a259 !important; color:#3a2410 !important; border:none !important;
  font-family:'Baloo 2',sans-serif !important; font-weight:800 !important;
  border-radius:999px !important; box-shadow:0 14px 30px -12px rgba(244,162,89,.7) !important;
}
#run-btn:hover, #run-btn button:hover {background:#ef9647 !important;}
"""

# The layout is light/warm; force light mode so it's consistent for every viewer.
FORCE_LIGHT = """() => {
  const url = new URL(window.location);
  if (url.searchParams.get('__theme') !== 'light') {
    url.searchParams.set('__theme', 'light');
    window.location.replace(url.href);
  }
}"""

with gr.Blocks(theme=gr.themes.Base(primary_hue="orange", neutral_hue="stone"),
               css=CSS, js=FORCE_LIGHT, title="Certior — watch an AI agent get caught") as demo:
    gr.HTML(f"""
    <div id="hero">
      <div style="font-family:{BALOO};font-weight:800;font-size:32px;color:{INK}">{LOGO}Certior playground</div>
      <div style="font-size:15px;color:{MUTED};margin-top:6px;max-width:680px;margin-inline:auto;line-height:1.55">
        A prompt that says “don’t” is not a security boundary. <b style="color:{INK}">A capability check on the action is.</b><br>
        Watch single-agent and multi-agent systems get hijacked, then watch Certior block the action with a proof.
      </div>
      <div style="font:800 12px Nunito,sans-serif;color:{GOLD};margin-top:8px;letter-spacing:.3px">
        zero install · no API key · every verdict computed live by Z3
      </div>
    </div>
    """)

    gr.HTML(f"<div style='font:800 12px Nunito,sans-serif;color:{GOLD};letter-spacing:1px;margin:12px 2px 0'>PICK AN ATTACK</div>")
    current = gr.State("exfil")
    with gr.Row(equal_height=False):
        single_r = gr.Radio(
            choices=[(f"{SCENARIOS['exfil']['emoji']}  Patient-data exfiltration", "exfil"),
                     (f"{SCENARIOS['sox']['emoji']}  Invoice fraud · SOX $480k", "sox"),
                     (f"{SCENARIOS['runaway']['emoji']}  Runaway budget blowout", "runaway")],
            value="exfil", label="Single-agent", elem_id="single-r")
        multi_r = gr.Radio(
            choices=[(f"{SCENARIOS['deleg']['emoji']}  Delegation escalation · CrewAI", "deleg"),
                     (f"{SCENARIOS['webinject']['emoji']}  Web page hijacks the agent · LangChain", "webinject")],
            value=None, label="Multi-agent", elem_id="multi-r")
    setup = gr.HTML(setup_html("exfil"))
    btn = gr.Button("▶  Run the attack", variant="primary", size="lg", elem_id="run-btn")

    with gr.Row(equal_height=True):
        off_col = gr.HTML(visible=False)
        on_col = gr.HTML(visible=False)

    # ── build your own boundary (live Z3, no key) ──
    gr.HTML(f"""
    <div style="margin-top:22px;border-top:1px solid rgba(42,32,23,.12);padding-top:18px">
      <div style="font:800 12px Nunito,sans-serif;color:{GOLD};letter-spacing:1px">BUILD YOUR OWN BOUNDARY</div>
      <div style="font-family:{BALOO};font-weight:800;font-size:21px;color:{INK};margin-top:4px">Try it on your own inputs — live.</div>
      <div style="color:{BODY};font-size:13.5px;line-height:1.6;margin-top:5px;max-width:690px">
        Pick what the agent <b>holds</b> and what an action <b>needs</b>, set a budget, optionally paste text.
        Hit verify — this runs the real <code style="color:{GOLD}">certior</code> package with Z3 right here, no API key.
      </div>
    </div>
    """)
    with gr.Row():
        held_in = gr.CheckboxGroup(CAP_CHOICES, value=["network:http:read", "filesystem:read", "db:read"],
                                   label="Capabilities the agent HOLDS")
        need_in = gr.CheckboxGroup(CAP_CHOICES, value=["db:write"],
                                   label="Capabilities this action NEEDS")
    with gr.Row():
        budget_in = gr.Slider(0, 5000, value=1000, step=50, label="Budget (cents)")
        cost_in = gr.Slider(0, 5000, value=10, step=10, label="This action costs (cents)")
    content_in = gr.Textbox(label="Optional — text the action would send (the HIPAA content gate scans it)",
                            placeholder="e.g. Discharge summary for John Doe, SSN 123-45-6789 …", lines=2)
    verify_btn = gr.Button("⚖  Verify with Certior (live Z3)", variant="primary", size="lg", elem_id="run-btn")
    custom_out = gr.HTML(visible=False)
    verify_btn.click(build_boundary, [held_in, need_in, budget_in, cost_in, content_in], custom_out)

    gr.HTML(f"""
    <div style="margin-top:22px;border-top:1px solid rgba(42,32,23,.12);padding-top:16px;color:{BODY};font-size:13.5px;line-height:1.65">
      <b style="color:{INK}">What just happened.</b> The model fell for the injection both times — Certior doesn’t make the model safer,
      it makes the model’s <i>actions</i> provably bounded. Z3 checks every tool call against a policy that’s
      machine-checked in Lean; allowed calls get a signed receipt an auditor can re-verify offline.
      <div style="margin-top:12px;display:flex;align-items:center;flex-wrap:wrap;gap:10px">
        <code style="background:#fffdf8;color:{GOLD};border:1px solid rgba(42,32,23,.12);padding:6px 12px;border-radius:8px;font-size:13px">pip install certior</code>
        <a href="https://colab.research.google.com/github/paulinebourigault/certior/blob/main/notebooks/quickstart.ipynb" target="_blank" rel="noopener">
          <img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open the quickstart in Colab" style="height:24px;vertical-align:middle"/>
        </a>
      </div>
      <div style="margin-top:9px">
        <a href="https://certior.io" style="color:{GOLD};font-weight:800">certior.io</a> ·
        <a href="https://docs.certior.io" style="color:{GOLD};font-weight:800">docs</a> ·
        <a href="https://docs.certior.io/quickstart" style="color:{GOLD};font-weight:800">5-line quickstart</a>
      </div>
    </div>
    """)

    gr.HTML(f"""
    <div style="margin-top:22px;border-top:1px solid rgba(42,32,23,.12);padding-top:18px">
      <div style="font:800 12px Nunito,sans-serif;color:{GOLD};letter-spacing:1px;margin-bottom:8px">SEE IT IN THE CONTROL PLANE</div>
      <div style="font-family:{BALOO};font-weight:800;font-size:21px;color:{INK};margin-bottom:5px">Certior Studio — the agent glass box</div>
      <div style="color:{BODY};font-size:13.5px;line-height:1.6;margin-bottom:13px;max-width:660px">
        The same checks you just ran, as a live control plane. Every hand-off is a node on the graph —
        watch a privilege escalation get blocked <i>before</i> it runs, with the Lean-verified proof attached.
      </div>
      <video src="{STUDIO_SRC}" autoplay muted loop playsinline
             style="width:100%;max-width:920px;border-radius:16px;border:1px solid rgba(42,32,23,.12);box-shadow:0 8px 30px rgba(42,32,23,.10);display:block"></video>
    </div>
    """)

    def pick_single(v):
        return v, gr.update(value=None), setup_html(v), gr.update(visible=False), gr.update(visible=False)

    def pick_multi(v):
        return v, gr.update(value=None), setup_html(v), gr.update(visible=False), gr.update(visible=False)

    single_r.input(pick_single, single_r, [current, multi_r, setup, off_col, on_col])
    multi_r.input(pick_multi, multi_r, [current, single_r, setup, off_col, on_col])
    btn.click(run_scenario, current, [off_col, on_col])


if __name__ == "__main__":
    # HF Spaces proxies the app from 0.0.0.0:7860; the localhost default fails there.
    demo.launch(server_name="0.0.0.0", server_port=7860)
