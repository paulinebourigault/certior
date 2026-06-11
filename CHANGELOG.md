# Changelog

All notable changes to Certior are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once 1.0 ships; during the 0.x series, **minor version bumps may include breaking changes**.

## [0.1.0a1] - 2026-06-08

Metadata-only release: deduped the redundant `Repository` / `Source Code` URLs in the PyPI project-links sidebar. No code or behaviour changes.

## [0.1.0a0] - 2026-06-08

First public alpha release of the `certior` SDK on PyPI. Install with `pip install certior`. The release reserves the project name and exposes the SDK shape to a small group of design partners while the API and adapter coverage continue to firm up.

### Added
- **SDK** - `Guard`, `VerifyResult`, `Policy`, `CertiorBlocked` exported from the top-level `certior` package.
- **OpenAI tool-calling adapter** - `certior.adapters.tool_use.verify_tool_calls` accepts the byte-exact shape that `response.choices[0].message.tool_calls` returns; no SDK migration or proxy required.
- **Anthropic `tool_use` adapter** - same `verify_tool_calls` entry point; native shape.
- **LangChain adapter** - `certior.adapters.langchain.CertiorCallbackHandler`.
- **CrewAI adapter** - `certior.adapters.crewai`.
- **OpenClaw adapter** - three integration surfaces with distinct, clearly documented jobs:
  - `certior.adapters.openclaw.GuardedAgent` - runtime enforcement primitive; raises `CertiorBlocked` outside OpenClaw's exception-swallowing callback chain so blocked verdicts actually halt the call.
  - `certior.adapters.openclaw.CertiorCallbackHandler` - observability + accounting; debits budget and runs the content scanner per execution, emits audit-trail entries. Documented as **not** an enforcement primitive because OpenClaw's `CompositeCallbackHandler` swallows handler exceptions.
  - `certior.adapters.openclaw.GuardedPipeline` - proxy over an OpenClaw `Pipeline` that checks per-step capability subsetting at `add_step` time.
  - `certior.adapters.openclaw.load_step_capabilities_from_skill[s_dir]` - parses `metadata.certior.capabilities` from a skill's `SKILL.md`.
  - `certior.adapters.openclaw.audit_skill` / `audit_skills_dir` - static pre-install audit proving a skill's declared capability surface is a subset of a parent `Guard`'s permissions, with SHA-256 fingerprint pinning. Does **not** scan skill source code for dangerous patterns; that is a complementary tool's job. See `docs/openclaw-skill-audit.md`.
  - `certior-skill-audit` CLI - wraps the audit functions; exits non-zero on audit failure so it can be wired into pre-install hooks and CI.
  - Addresses the eight threats enumerated in *Uncovering Security Threats and Architecting Defenses in Autonomous Agents: A Case Study of OpenClaw* (arXiv:2603.12644); see `docs/openclaw-defenses.md` for the per-threat mapping.
- **MCP adapter** - MCP tools normalise the same as OpenAI / Anthropic shapes through `verify_tool_calls`.
- **Three formal gates per tool call** - capability, content, budget - all proven by Z3 with a signed certificate on success.
- **Compliance presets** - `hipaa`, `sox`, `legal_privilege`, `default`.
- **Lean-checked policy model** - every certificate carries the policy fingerprint `cc3e0c7431fd8a53`; four headline guarantees (`delegationSafety`, `ifcSoundness`, `compositionSoundness`, lattice validity) audited in CI against Lean's three standard axioms.
- **CLI tools** - `certior-graph`, `certior-graph-ingest`, `certior-ops`, `certior-doctor`, `certior-runtime-evidence`, `certior-release-status`, `certior-validate-manifest`, `certior-skill-audit`.
- **Signed certificates** with tamper-detection; verifiable offline using the embedded signature and policy fingerprint.
- **Apache-2.0 license**.

### Known limitations
- The server (`app/`) and Studio frontend ship via the full repository (`git clone https://github.com/paulinebourigault/certior`), not via the pip package. This is intentional - the pip package is the SDK + runtime; the server is a separate deployment artifact.
- Adapter test coverage is unit-test scoped with mocked LLM clients. Real-LLM smoke tests are run manually before each release; live-LLM cassette playback in CI is planned for the `0.1` line.
- The PostgreSQL persistence backend is workable but not production-stable. For development, SQLite (the default when `DATABASE_URL` is unset) is the recommended path; for production, expect rough edges in the `0.1.x` series.
- Lean live verification requires the `certior-flow-check` binary built from `lean4/CertiorPlan/`. The pip package ships without a pre-built binary (~93 MB compiled); without it the runtime uses a Python subset check whose soundness Lean has proven. Build with `scripts/build-lean-binary.sh` and point `CERTIOR_FLOW_CHECK_BINARY` at the produced path. See `docs/lean-binary.md`; the `lean-binary-ci` GitHub Actions workflow verifies the build remains green on every commit.

### API stability
- This is an alpha release. Public symbols (`Guard`, `VerifyResult`, `Policy`, `CertiorBlocked`, and the adapters listed above) may change in minor version bumps. Deprecation warnings will accompany changes where practical, but compatibility is not promised until `1.0.0`.
- Pin to `certior==0.1.*` if you want only patch-level changes within the alpha line.

[0.1.0a0]: https://github.com/paulinebourigault/certior/releases/tag/v0.1.0a0
