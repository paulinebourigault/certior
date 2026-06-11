# Certior Examples

Runnable demos covering the SDK, every shipped adapter, and the FastAPI server surface.

## Start here

Three examples answer the three first questions a new dev usually has:

| Question | Example | Needs server | Needs LLM key |
|---|---|:---:|:---:|
| "What does the SDK actually look like?" | [`wrapper_quickstart.py`](wrapper_quickstart.py) | No | No |
| "Does it work with my OpenAI agent?" | [`openai_agent_demo.py`](openai_agent_demo.py) | No | Yes |
| "How does the runtime gate fire? What evidence comes out?" | [`08_all_provers_showcase.py`](08_all_provers_showcase.py) | No | No |

```bash
python examples/wrapper_quickstart.py
```

## All examples

| # | File | Server | LLM | What it shows |
|---|---|:---:|:---:|---|
| - | [`wrapper_quickstart.py`](wrapper_quickstart.py) | No | No | The 5-line SDK recipe + every proof obligation |
| - | [`openai_agent_demo.py`](openai_agent_demo.py) | No | Yes | OpenAI tool calling: jailbreak blocked, PII blocked, budget exhausted, certs inspected |
| 01 | [`01_health_check.py`](01_health_check.py) | ✅ | No | Server health, auth, compliance presets |
| 02 | [`02_verified_task.py`](02_verified_task.py) | ✅ | Recommended | Submit a task → poll → results with proof certificates |
| 03 | [`03_hipaa_compliance.py`](03_hipaa_compliance.py) | No | No | PII detection, redaction, SOX / Legal scanning, compliance export |
| 04 | [`04_z3_verification.py`](04_z3_verification.py) | No | No | Z3 proofs, capability tokens, URL/path safety, proof certificates |
| 05 | [`05_websocket_stream.py`](05_websocket_stream.py) | ✅ | Recommended | Real-time WebSocket streaming of execution events |
| 06 | [`06_protected_release_workflow.py`](06_protected_release_workflow.py) | ✅ | Recommended | Single-agent hard reject for protected public release; contrasted with allowed de-identified summary |
| 07 | [`07_multi_agent_reviewed_release.py`](07_multi_agent_reviewed_release.py) | ✅ | Recommended | Reviewer stage + release stage workflow - release succeeds only with a compliant upstream execution ID |
| 08 | [`08_all_provers_showcase.py`](08_all_provers_showcase.py) | No | No | Z3 + Lean + Dafny / seccomp evidence in one run; Lean-blocked downgrade |
| 09 | [`09_agent_framework_adapter.py`](09_agent_framework_adapter.py) | No | No | LangChain / CrewAI / generic adapter integration patterns |
| 10 | [`10_openclaw_pipeline_demo.py`](10_openclaw_pipeline_demo.py) | No | No | OpenClaw `GuardedPipeline` delegation chain end-to-end |
| - | [`seed_glass_box_demo.py`](seed_glass_box_demo.py) | ✅ | No | Seed a glass-box trace for inspection in Studio |
| - | [`_helpers.py`](_helpers.py) | - | - | Shared helpers used by the demos above (not runnable on its own) |

## Prerequisites

```bash
pip install -e ".[all]"   # SDK + server + every adapter
```

For server-backed examples (`01`, `02`, `05`, `06`, `07`), start the server first:

```bash
./run.sh
```

For OpenAI-backed examples, set `OPENAI_API_KEY` in `.env` or your environment. The "Recommended" LLM column means the example degrades gracefully without a key but the demo is less interesting.

## Sample evidence

To see what a Certior audit export looks like, run example `03`:

```bash
python examples/03_hipaa_compliance.py
```

It writes a HIPAA-preset compliance export PDF to your working directory.

## Recommended starting order

If you are new to the codebase, run the examples in this order:

1. **`wrapper_quickstart.py`** - the SDK in around five lines, no server, no LLM.
2. **`07_multi_agent_reviewed_release.py`** - workflow-stage approval and release gates end to end.
3. **`08_all_provers_showcase.py`** - the enforcement grounded in Z3, Lean, and Dafny evidence.
