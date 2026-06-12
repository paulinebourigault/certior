"""
Certior playground — watch a real AI agent get caught.
======================================================

The agent transcripts are faithful replays of real GPT-4o runs 
(recorded in demos/live/). Every Certior verdict on this page —
allow, block, and the signed receipt — is computed live with real Z3 at the
moment you click, by the same `certior` package that's on PyPI.
"""
import html

import gradio as gr
from certior import Guard

from storyboards import SCENARIOS

POLICY = "hipaa"
INK = "#0f172a"


# ── live Certior verdicts (Z3) ────────────────────────
def verify(need, held):
    g = Guard(policy=POLICY, permissions=list(held), agent_id="agent")
    return g.verify(tool="action", required_capabilities=list(need), cost_cents=1)


def verify_step(step):
    """Live verdict for one step — handles capability and budget gates.

    Budget steps carry {budget, cost}: the per-step `budget` is the real
    remaining ceiling at that point in the recorded run, so the verdict (and
    its "need X, have Y" reason) is reproduced live by Z3, not hard-coded.
    """
    if "budget" in step:
        g = Guard(policy="default", permissions=["compute:run"],
                  budget_cents=step["budget"], agent_id="orchestrator")
        return g.verify(tool="action", required_capabilities=["compute:run"],
                        cost_cents=step["cost"])
    return verify(step["need"], step["held"])


def _chip(text, color, bg):
    return (f"<span style='font:600 11px ui-monospace,monospace;color:{color};"
            f"background:{bg};padding:2px 8px;border-radius:999px;white-space:nowrap'>{text}</span>")


def _step_row(step, enforced):
    """One transcript row. enforced=False → agent just runs. True → Certior gates it."""
    actor = html.escape(step["actor"])
    tool = html.escape(step["tool"])
    ret = html.escape(step["ret"])
    need = "budget" if "budget" in step else " ".join(step["need"])

    if not enforced:
        badge = _chip("▶ executed", "#fca5a5", "rgba(220,38,38,.15)")
        border = "rgba(220,38,38,.25)"
    else:
        r = verify_step(step)
        if r.allowed:
            badge = _chip("✓ allowed", "#6ee7b7", "rgba(16,185,129,.15)")
            border = "rgba(16,185,129,.25)"
        else:
            badge = _chip("✗ BLOCKED", "#fca5a5", "rgba(220,38,38,.2)")
            border = "rgba(220,38,38,.5)"

    return f"""
    <div style="border:1px solid {border};border-radius:10px;padding:10px 12px;margin:8px 0;background:rgba(255,255,255,.02)">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
        <code style="font:600 12.5px ui-monospace,monospace;color:#e2e8f0">{actor} → {tool}</code>
        {badge}
      </div>
      <div style="font-size:11.5px;color:#94a3b8;margin-top:5px">needs <code style="color:#cbd5e1">{html.escape(need)}</code></div>
      <div style="font-size:12px;color:#cbd5e1;margin-top:4px">{ret}</div>
    </div>"""


def _receipt_html(step):
    """Render a freshly-minted, real signed receipt from an allowed step."""
    r = verify_step(step)
    if r.certificate is None:
        return ""
    c = r.certificate.to_dict()
    props = "".join(
        f"<div style='font:11px ui-monospace,monospace;color:#6ee7b7'>✓ {html.escape(p)}</div>"
        for p in c["verified_properties"]
    )
    return f"""
    <div style="border:1px dashed rgba(16,185,129,.5);border-radius:10px;padding:12px;margin-top:10px;background:rgba(16,185,129,.06)">
      <div style="font:600 11px ui-monospace,monospace;color:#34d399;letter-spacing:1px">SIGNED RECEIPT · minted live by Z3</div>
      <div style="font:11px ui-monospace,monospace;color:#cbd5e1;margin-top:6px">id {html.escape(c['id'][:18])}…</div>
      <div style="font:11px ui-monospace,monospace;color:#cbd5e1">theorem {html.escape(c['theorem'])}</div>
      <div style="margin-top:6px">{props}</div>
      <div style="font:11px ui-monospace,monospace;color:#94a3b8;margin-top:6px">prover {c['prover']} · verifiable offline</div>
    </div>"""


def _col(title, sub, color, inner):
    return f"""
    <div style="border:1px solid {color}55;border-radius:14px;padding:16px;background:{INK};height:100%">
      <div style="font:700 13px ui-sans-serif;color:{color};letter-spacing:.5px">{title}</div>
      <div style="font-size:11.5px;color:#94a3b8;margin:2px 0 10px">{sub}</div>
      {inner}
    </div>"""


def run_scenario(key):
    sc = SCENARIOS[key]
    steps = sc["steps"]

    # WITHOUT — every step just executes; ends badly
    off_rows = "".join(_step_row(s, enforced=False) for s in steps)
    off_tail = (f"<div style='font-size:11.5px;color:#94a3b8;font-style:italic;margin:6px 2px'>"
                f"{html.escape(sc['off_tail'])}</div>" if sc.get("off_tail") else "")
    off_verdict = f"""
      <div style="margin-top:12px;border-radius:10px;padding:12px;background:rgba(220,38,38,.15);border:1px solid rgba(220,38,38,.5)">
        <div style="font:800 16px ui-sans-serif;color:#fca5a5">☠ {html.escape(sc.get('off_label', 'BREACH'))}</div>
        <div style="font-size:12px;color:#fecaca;margin-top:3px">{html.escape(sc['off_outcome'])}</div>
      </div>"""
    off = _col("WITHOUT CERTIOR", "the agent is on its own", "#ef4444", off_rows + off_tail + off_verdict)

    # WITH — Certior gates each step live; the bad action is blocked
    on_rows = "".join(_step_row(s, enforced=True) for s in steps)
    blocked = next((s for s in steps if not verify_step(s).allowed), None)
    reason = verify_step(blocked).reason if blocked else ""
    on_verdict = f"""
      <div style="margin-top:12px;border-radius:10px;padding:12px;background:rgba(16,185,129,.13);border:1px solid rgba(16,185,129,.5)">
        <div style="font:800 16px ui-sans-serif;color:#6ee7b7">🛡 {html.escape(sc.get('on_label', 'BLOCKED'))}</div>
        <div style="font:12px ui-monospace,monospace;color:#a7f3d0;margin-top:4px">CertiorBlocked: {html.escape(reason)}</div>
        <div style="font-size:12px;color:#d1fae5;margin-top:4px">{html.escape(sc['on_outcome'])}</div>
      </div>"""
    on = _col("WITH CERTIOR", "every action proven before it runs", "#10b981",
              on_rows + _receipt_html(steps[0]) + on_verdict)

    return gr.update(value=off, visible=True), gr.update(value=on, visible=True)


def setup_html(key):
    sc = SCENARIOS[key]
    return f"""
    <div style="border:1px solid #1e293b;border-radius:14px;padding:16px 18px;background:#0b1220">
      <div style="font:800 18px ui-sans-serif;color:#e2e8f0">{sc['emoji']} {sc['title']}</div>
      <div style="font:600 11px ui-monospace,monospace;color:#64748b;letter-spacing:.5px;margin:3px 0 10px">{sc['subtitle'].upper()}</div>
      <div style="font-size:13.5px;color:#cbd5e1;line-height:1.6">{sc['setup']}</div>
    </div>"""


CSS = """
.gradio-container {max-width: 1080px !important; margin: auto;}
footer {display:none !important;}
#hero {text-align:center; padding: 8px 0 4px;}
#single-r, #multi-r {border:none !important; box-shadow:none !important; background:transparent !important;}
#single-r label:has(input), #multi-r label:has(input) {
  border:1px solid rgba(148,163,184,.22); border-radius:10px; padding:9px 12px;
  margin:3px 0; background:rgba(255,255,255,.03); transition:all .12s;
}
#single-r label:has(input):hover, #multi-r label:has(input):hover {
  background:rgba(16,185,129,.10); border-color:rgba(16,185,129,.45);
}
"""

# The layout uses dark cards on a dark page; force dark mode so it's consistent
# for every viewer (and the light hero/footer text stays readable).
FORCE_DARK = """() => {
  const url = new URL(window.location);
  if (url.searchParams.get('__theme') !== 'dark') {
    url.searchParams.set('__theme', 'dark');
    window.location.replace(url.href);
  }
}"""

with gr.Blocks(theme=gr.themes.Base(primary_hue="emerald", neutral_hue="slate"),
               css=CSS, js=FORCE_DARK, title="Certior — watch an AI agent get caught") as demo:
    gr.HTML("""
    <div id="hero">
      <div style="font:800 30px ui-sans-serif;color:#f1f5f9">🛡️ Certior playground</div>
      <div style="font-size:15px;color:#cbd5e1;margin-top:6px;max-width:680px;margin-inline:auto;line-height:1.5">
        A prompt that says “don’t” is not a security boundary. <b>A capability check on the action is.</b><br>
        Watch <b>real</b> GPT-4o agents — single-agent and multi-agent — get hijacked, then watch Certior block the action with a proof.
      </div>
      <div style="font:600 11px ui-monospace,monospace;color:#10b981;margin-top:8px">
        zero install · no API key · every verdict computed live by Z3
      </div>
    </div>
    """)

    gr.HTML("<div style='font:700 12px ui-monospace,monospace;color:#94a3b8;letter-spacing:1px;margin:10px 2px 0'>PICK AN ATTACK</div>")
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
    btn = gr.Button("▶  Run the attack", variant="primary", size="lg")

    with gr.Row(equal_height=True):
        off_col = gr.HTML(visible=False)
        on_col = gr.HTML(visible=False)

    gr.HTML("""
    <div style="margin-top:18px;border-top:1px solid rgba(255,255,255,.12);padding-top:16px;color:#cbd5e1;font-size:13.5px;line-height:1.6">
      <b style="color:#f1f5f9">What just happened.</b> The model fell for the injection both times — Certior doesn’t make the model safer,
      it makes the model’s <i>actions</i> provably bounded. Z3 checks every tool call against a policy that’s
      machine-checked in Lean; allowed calls get a signed receipt an auditor can re-verify offline.
      <div style="margin-top:12px">
        <code style="background:#020617;color:#6ee7b7;border:1px solid rgba(255,255,255,.12);padding:6px 12px;border-radius:8px;font-size:13px">pip install certior</code>
        &nbsp;&nbsp;
        <a href="https://certior.io" style="color:#6ee7b7;font-weight:600">certior.io</a> ·
        <a href="https://docs.certior.io" style="color:#6ee7b7;font-weight:600">docs</a> ·
        <a href="https://docs.certior.io/quickstart" style="color:#6ee7b7;font-weight:600">5-line quickstart</a>
      </div>
    </div>
    """)

    # Two grouped radios; .input fires only on user clicks (not the programmatic
    # clear of the other group), so selecting one deselects the other cleanly.
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
