---
title: Certior Playground
emoji: 🛡️
colorFrom: gray
colorTo: green
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: true
license: apache-2.0
short_description: Watch an AI agent get prompt-injected, then caught with a proof.
---

# Certior playground

A prompt that says “don’t” is not a security boundary. **A capability check on the
action is.** This Space shows a GPT-4o agent getting prompt-injected into
exfiltrating patient records — then shows [Certior](https://certior.io) blocking the
exact same action, with a signed proof.

Four attacks:

- **🩺 Patient-data exfiltration** — a single OpenAI function-calling agent emails the
  patient database to an outside address. Certior blocks the send: it never held
  `email:send:external`.
- **🔗 Delegation escalation (CrewAI)** — a read-only sub-agent in a multi-agent crew is
  told to email the export outside. It can’t escalate past the authority it was
  delegated. This is the wedge nothing else in agent-safety does.
- **💸 Invoice fraud / SOX threshold** — a forged “CEO-approved” invoice walks a $480,000
  wire through an accounts-payable agent. Certior blocks it: approving over the SOX
  threshold needs `finance:approve:high_value`, which the agent was never granted.
- **🔥 Runaway delegation** — told to “be exhaustive”, an agent spawns 31 paid workers
  ($620). Certior’s hard budget ceiling halts it at $40.

The transcripts are faithful replays of real GPT-4o runs; 
every Certior verdict — allow, block, and the signed receipt — is computed live
by real Z3 from the `certior` package on each click.

```bash
pip install certior   # the same package that runs this page
```

· [certior.io](https://certior.io) · [docs](https://docs.certior.io) · [quickstart](https://docs.certior.io/quickstart)

## Run locally

```bash
pip install -r requirements.txt
python app.py
```
