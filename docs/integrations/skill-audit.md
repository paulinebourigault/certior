---
title: "Skill audit CLI"
description: "certior-skill-audit proves a skill's declared capability surface is a subset of a parent guard's permissions before the skill is wired in."
---

`certior-skill-audit` is a pre-install / pre-load audit for skills. Given a `SKILL.md` and a parent `Guard`'s permission set, it proves the skill's declared capability surface is a subset of the parent before the skill enters a pipeline. If the subset relation does not hold, the audit fails and the binary exits non-zero.

Use it in pre-install hooks, CI, or release pipelines.

## Install

The CLI ships with the `certior` package:

```bash
pip install certior
```

## Audit one skill

```bash
certior-skill-audit \
    --permission network:http:read \
    --permission filesystem:read \
    skills/researcher/SKILL.md
```

Exits `0` if the skill's `metadata.certior.capabilities` is a subset of the supplied permissions. Exits non-zero otherwise. Use `--permission` repeatedly to declare each parent capability.

## Audit a directory of skills

```bash
certior-skill-audit \
    --permission network:http:read \
    --permission filesystem:read \
    skills/
```

Walks the directory and audits every `SKILL.md` found. Exits non-zero if any skill fails.

## Pin a fingerprint

```bash
certior-skill-audit \
    --permission network:http:read \
    --expected-fingerprint researcher=sha256:8c5e... \
    skills/researcher/SKILL.md
```

`--expected-fingerprint NAME=SHA256` enforces that the skill's content hash matches the pinned value. Use this to catch drift between a reviewed version and what is on disk at install time.

## Allow undeclared capabilities

```bash
certior-skill-audit --allow-undeclared --permission network:http:read skills/legacy/
```

By default, a skill with no declared capability metadata fails the audit (you cannot prove a subset of an unknown set). `--allow-undeclared` admits such skills - useful when migrating an existing pipeline incrementally.

## JSON output

```bash
certior-skill-audit --json --permission network:http:read skills/
```

Emits per-skill audit results as JSON for machine consumption.

## Programmatic API

The CLI is a thin wrapper over `certior.adapters.openclaw_skill_audit`:

```python
from certior import Guard
from certior.adapters.openclaw_skill_audit import audit_skill, audit_skills_dir

parent = Guard(permissions=["network:http:read"])

result = audit_skill("skills/researcher/SKILL.md", parent_guard=parent)
print(result.passed, result.reasons)

all_results = audit_skills_dir("skills/", parent_guard=parent)
```

Each result carries the skill name, the declared capability set, the verdict, the reason on failure, and the skill fingerprint.

## What this does not do

The audit is intentionally narrow. It does **not** scan the skill's source code for dangerous patterns (regex SAST). That is a complementary tool's job. Certior verifies that the **declared** capability surface fits inside the parent's; tools like Semgrep or Bandit verify that the **implementation** does not exceed its declaration.

## See also

- [GitHub Action](/integrations/github-action) - the same check, gating pull requests.
- [Capability model](/concepts/capability-model) - what "subset" means.
