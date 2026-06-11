# Auditing OpenClaw skills with `certior-skill-audit`

`certior-skill-audit` is a pre-install / pre-load audit for OpenClaw
skills. Given a `SKILL.md` and a parent `Guard`'s permission set, it
proves the skill's declared capability surface is a **subset** of the
parent before the skill is wired into a pipeline. If the subset
relation does not hold, the audit fails and the binary exits non-zero
- so it can be wired into pre-install hooks, CI, or release
pipelines.

The check is intentionally narrow. See "Scope and non-goals" below
for what this tool does and does not do.

## Install

`certior-skill-audit` ships with the `certior` pip package - no
extra install required.

```bash
pip install certior
certior-skill-audit --help
```

It does not require `openclaw-sdk` to be installed; the audit is
purely static on the `SKILL.md` file.

## What it checks

Three deductive checks, in order:

1. **Declaration present.** The skill must declare
   `metadata.certior.capabilities` in its `SKILL.md` frontmatter. A
   skill with no declaration fails the audit (fail-closed) unless
   `--allow-undeclared` is passed.
2. **Capability subset.** Every declared capability must appear in
   the parent guard's `--permission` list. `*` in the parent
   satisfies every capability.
3. **Fingerprint pin (optional).** If `--expected-fingerprint
   <name>=<sha256>` is supplied for a skill, the audit fails when the
   file's current SHA-256 differs.

A skill passes only when **all three checks pass**.

## The SKILL.md extension field

OpenClaw's own `SKILL.md` schema does not include a capability field
(`metadata.requires.bins` and `metadata.requires.env` are the closest
neighbours, and they describe *prerequisites*, not the capability
surface). Certior adds an **opt-in extension** under `metadata.certior`:

```yaml
---
name: research
description: Search public AI safety research and summarise findings
homepage: https://example.com/research-skill
metadata:
  openclaw:
    requires:
      env: ["TAVILY_API_KEY"]
  certior:
    capabilities:
      - "network:http:read"
---

When the user asks for AI research, use the `web_search` tool…
```

The extension is opt-in by design. Certior does not infer
capabilities from `metadata.requires.bins` heuristics because that
would create false security - a skill that declares no binaries
could still issue HTTP calls or read files.

## Usage

### Audit a single skill

```bash
$ certior-skill-audit ./my-skill/SKILL.md \
      --permission network:http:read \
      --permission filesystem:read

[PASS] research  (/home/.../my-skill/SKILL.md)
       declared: ['network:http:read']
       parent:   ['network:http:read', 'filesystem:read']
       fp:       27d2a906e6eebb80…  (no pin)

Audited 1 skill(s): 1 pass, 0 fail
```

Exits `0` on pass, `1` on audit failure, `2` on usage error.

### Audit a whole skills directory

Mirrors OpenClaw's `~/.openclaw/workspace/skills/<skill>/SKILL.md`
layout:

```bash
$ certior-skill-audit ~/.openclaw/workspace/skills \
      --permission network:http:read \
      --permission filesystem:read

[PASS] research  (/.../research/SKILL.md)
       declared: ['network:http:read']
       parent:   ['network:http:read', 'filesystem:read']
       fp:       27d2a906e6eebb80…  (no pin)
[FAIL] exfiltrator  (/.../exfiltrator/SKILL.md)
       declared: ['database:admin']
       parent:   ['network:http:read', 'filesystem:read']
       missing:  ['database:admin']
       reason:   capability_not_in_parent: database:admin

Audited 2 skill(s): 1 pass, 1 fail
```

### Pin a known-good version

After reviewing a skill, capture its fingerprint and pin it. The
audit then fails if the file changes:

```bash
$ certior-skill-audit ./research/SKILL.md --permission network:http:read --json \
      | jq -r '.[0].fingerprint'
27d2a906e6eebb80…

$ certior-skill-audit ~/.openclaw/workspace/skills \
      --permission network:http:read \
      --expected-fingerprint research=27d2a906e6eebb80…
```

A later run finds `fingerprint_mismatch: expected …, got …` if the
file is edited.

### Machine-readable output

`--json` emits a JSON array suitable for piping into another tool:

```bash
certior-skill-audit ~/.openclaw/workspace/skills \
    --permission network:http:read \
    --json
```

Each result includes `skill_path`, `skill_name`, `passed`,
`declared_capabilities`, `parent_permissions`, `missing_capabilities`,
`fingerprint`, `expected_fingerprint`, `fingerprint_matches`, and a
list of `reasons`.

## Library API

The same checks are available as Python functions for use inside a
release pipeline or test harness:

```python
from certior import Guard
from certior.adapters.openclaw import (
    audit_skill, audit_skills_dir, skill_fingerprint,
)

parent = Guard(permissions=["network:http:read", "filesystem:read"], budget_cents=0)

# One skill
result = audit_skill("./research/SKILL.md", parent)
assert result.passed, result.reasons

# A whole directory, with pins
pins = {"research": "27d2a906e6eebb80…"}
results = audit_skills_dir(
    "~/.openclaw/workspace/skills", parent,
    expected_fingerprints=pins,
)
for r in results:
    print(r.skill_name, r.passed, r.reasons)
```

## Scope and non-goals

This tool is **deliberately narrow**. It does not:

- **Scan skill source code for dangerous patterns.** No regex hunts
  for `eval`, `curl ... | bash`, reverse shells, file persistence,
  etc. Tools that do that - for example
  [ClawGuard](https://github.com/NY1024/ClawGuard) - are
  **complementary**: they scan the implementation; this scans the
  *capability claim*. Run both if you want both.
- **Verify intent.** Whether the skill code matches the description
  in the frontmatter is an LLM-judgement problem, not amenable to
  formal proof.
- **Detect supply-chain compromise.** A `SKILL.md` that declares the
  correct capabilities can still pull a malicious dependency. Pair
  this audit with the host runtime's sandbox (Linux seccomp, Docker,
  Firecracker, gVisor, the OpenClaw skill sandbox) for defence in
  depth.

What this tool *does* give you: a **deductive** check that the
skill's declared capability surface fits inside the parent guard's
permissions. The *soundness* of that subset rule against the
delegation threat model is what Lean's `delegationSafety` theorem
establishes offline; the auditor runs that rule statically against a
skill so delegation safety can be assessed before the first call.

## Threat-model coverage

The audit addresses two of the eight threats enumerated in
[arXiv:2603.12644](https://arxiv.org/pdf/2603.12644):

| # | Threat                                | How `certior-skill-audit` helps                                                                                                                                              |
|:-:|---------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2 | Tool Calling Chain Exploitation (ClawDrain) | A skill that declares more capabilities than the parent holds is rejected at audit time, so it never enters the pipeline. Even if the skill is loaded, `GuardedPipeline` re-checks at `add_step` time. |
| 8 | Privilege Escalation via Tool Chains         | The audit catches escalation declarations statically. The same rule re-runs at request time inside `GuardedAgent` / `GuardedPipeline`, so any drift is caught twice. |

For the other six threats - prompt injection, unauthorised capability
access at runtime, data exfiltration, resource exhaustion, command
injection, tool-result tampering - use the runtime gates
(`GuardedAgent`, `CertiorCallbackHandler`). See
[`openclaw-defenses.md`](./openclaw-defenses.md) for the full mapping.
