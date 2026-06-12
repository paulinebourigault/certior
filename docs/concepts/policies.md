---
title: "Compliance policies"
description: "Four built-in presets - default, hipaa, sox, legal_privilege - bundle content rules, permission ceilings, audit retention, and proof obligations."
---

A `Policy` is the active compliance preset on a guard. It tunes the **content gate**: which patterns to redact, which to block, what audit retention applies, and what permissions are or are not allowed under this regime.

The four presets are defined in `agentsafe/compliance/presets.py`.

## Choosing a policy

```python
from certior import Guard

guard = Guard(policy="hipaa", budget_cents=5000)
```

The `policy` argument accepts a string or a `Policy` enum value (`Policy.DEFAULT`, `Policy.HIPAA`, `Policy.SOX`, `Policy.LEGAL`, `Policy.LEGAL_PRIVILEGE`). Strings are normalized to the enum.

## The four presets

### `default`

The baseline. The content gate runs Certior's standard scanner; the capability ceiling is unrestricted (`max_permissions=["*"]`); audit retention is 365 days. Use this for development and for non-regulated production where you still want capability + budget enforcement without strict content rules.

### `hipaa`

PHI handling. Activates PII detection and auto-redaction on prompts and tool outputs (names, dates, SSNs, MRNs, addresses, phone numbers). Permission ceiling restricts capabilities the HIPAA preset deems out-of-scope. Audit retention is 2,190 days (6 years).

### `sox`

Material non-public information. Activates MNPI keyword and pattern detection; tightens audit with `segregation_of_duties=True` and 2,555-day (7-year) retention. Use this for any agent that can read or write financial-reporting data.

### `legal_privilege`

Attorney-client privilege. Blocks routing privileged content across information-flow boundaries, preserves privilege markers, and flags disclosures to non-privileged destinations. Retention is 3,650 days (10 years).

## What each preset configures

Each `ComplianceConfig` carries:

```python
@dataclass
class ComplianceConfig:
    name: str
    content_safety: ContentSafetyPolicy     # the scanner rules
    permissions: list[str]                   # default capability set
    max_permissions: list[str]               # absolute ceiling
    forbidden_permissions: list[str]         # hard deny list
    information_flow_rules: list[FlowRule]   # routing constraints
    audit: AuditConfig                       # retention, tamper-proofness
    required_proofs: list[str]               # obligations Z3 must discharge
```

When you set `policy="hipaa"`, Guard builds a `_safety_policy` from that config and the scanner is bound to its rules. The `max_permissions` ceiling shown above is the *server-side* enforcement boundary (the Cloud task API intersects requested permissions against it). The local SDK `Guard` uses the `permissions=` you pass as-is — pass a set that already fits the ceiling you intend to enforce.

## Custom policies

To extend a preset with domain-specific keywords or rules, build a `ContentSafetyPolicy` directly and inject it. See `agentsafe/safety/scanner.py` and `agentsafe/compliance/presets.py` for the data model. Custom policies are intentionally code-defined rather than free-form YAML.

> The content gate is keyword + regex against an auditable rule set - predictable, fast, and never sends content to a third party. It catches the documented patterns exactly; it does not infer violations from paraphrases.

## See also

- [How it works](/concepts/how-it-works) - the content gate's place in the pipeline.
- [Capability model](/concepts/capability-model) - how the permission ceiling interacts with the content gate.
- [Compliance API](/api/compliance) - listing presets and exporting an execution's compliance package.
