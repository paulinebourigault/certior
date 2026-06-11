---
title: "OpenClaw"
description: "GuardedAgent enforces, CertiorCallbackHandler accounts, GuardedPipeline delegates with subset checks. Addresses every threat in arXiv:2603.12644."
---

The OpenClaw adapter ships three integration points, each with a distinct, clearly documented job.

## `GuardedAgent` - the enforcement primitive

```python
from openclaw_sdk import Agent
from certior import Guard
from certior.adapters.openclaw import GuardedAgent

guard = Guard(policy="default", permissions=["network:http:read"], budget_cents=5000)

agent = Agent(...)
safe_agent = GuardedAgent(agent, guard)
result = safe_agent.run(prompt="...")
```

`GuardedAgent` wraps an OpenClaw `Agent` and raises `CertiorBlocked` outside OpenClaw's exception-swallowing callback chain. This is the only adapter surface that actually halts the call on a block.

## `CertiorCallbackHandler` - observability + accounting

```python
from openclaw_sdk import Agent
from certior.adapters.openclaw import CertiorCallbackHandler

agent = Agent(callbacks=[CertiorCallbackHandler(guard)])
```

The callback handler debits the guard's budget per execution and runs the content scanner. It emits an audit-trail entry on every call.

It does **not** enforce blocks. OpenClaw's `CompositeCallbackHandler` swallows handler exceptions ("so one failing handler does not block the others"). Use `GuardedAgent` for enforcement and the callback handler for accounting.

## `GuardedPipeline` - delegation with subset checks

```python
from openclaw_sdk import Pipeline
from certior.adapters.openclaw import GuardedPipeline, CertiorCallbackHandler

handler = CertiorCallbackHandler(guard)
pipeline = GuardedPipeline(
    Pipeline(client),
    guard,
    step_capabilities={
        "researcher": ["network:http:read"],
        "writer":     ["filesystem:read"],
    },
)
pipeline.add_step(researcher_step)   # subset check runs here
pipeline.add_step(writer_step)
```

`GuardedPipeline(pipeline, guard, step_capabilities=None)` proxies an OpenClaw `Pipeline` and checks each `add_step` call against the parent guard's permissions. A step whose declared capability surface is not a subset of the parent is rejected at registration time, before any LLM ever sees the pipeline. The optional `step_capabilities` mapping declares each step's capability surface up front; steps not present in the mapping fall back to the empty set (most restrictive). Per-step budget and content gates fire through the `CertiorCallbackHandler` running alongside - the supported pattern is to use both together to avoid double-charging.

## Skill-level capability declaration

Steps in an OpenClaw pipeline can carry their capability surface in their `SKILL.md` frontmatter under `metadata.certior.capabilities`. Certior reads it with:

```python
from certior.adapters.openclaw import (
    load_step_capabilities_from_skill,
    load_step_capabilities_from_skills_dir,
)

caps = load_step_capabilities_from_skill("skills/researcher/SKILL.md")
all_caps = load_step_capabilities_from_skills_dir("skills/")
```

Use this to declare each step's capability surface in the skill itself, then verify the whole pipeline at registration time.

## Static pre-install skill audit

Before a skill is wired into a pipeline, audit it statically with [`certior-skill-audit`](/integrations/skill-audit). The audit proves the skill's declared capability surface is a subset of a parent guard's permissions, with SHA-256 fingerprint pinning for drift detection.

## What this covers

Certior's OpenClaw integration addresses the eight threats enumerated in *Uncovering Security Threats and Architecting Defenses in Autonomous Agents: A Case Study of OpenClaw* ([arXiv:2603.12644](https://arxiv.org/pdf/2603.12644)). The per-threat mapping lives in the GitHub source at [`docs/openclaw-defenses.md`](https://github.com/paulinebourigault/certior/blob/main/docs/openclaw-defenses.md).

## See also

- [Skill audit CLI](/integrations/skill-audit) - pre-install audit recipe.
- [Capability model](/concepts/capability-model) - the subset rule the delegation checks enforce.
