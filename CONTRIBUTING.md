# Contributing to Certior

Thanks for considering a contribution. Certior is in active development and
small, well-scoped patches are easiest to review.

## Before you start

- **Security issues:** do **not** open a public issue. Follow
  [`SECURITY.md`](SECURITY.md) instead.
- **Larger changes:** open a discussion or an issue first to align on
  approach. Avoid surprise PRs that touch policy semantics, the wire
  format of signed certificates, or the Lean model.

## Development setup

```bash
git clone https://github.com/paulinebourigault/certior
cd certior
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,api,postgres,redis,observability,llm,openai-llm]"
pre-commit install        # optional but recommended
```

Run the test suite:

```bash
pytest
```

Run a specific area:

```bash
pytest tests/test_safety/         # content gates
pytest tests/test_agents/         # agent integration
pytest tests/test_verification_graph/
```

## Branch and PR workflow

1. Fork the repository and create a topic branch off `main`:
   `git checkout -b feature/short-description`
2. Make your change, keeping commits focused and the diff small.
3. Add or update tests covering the new behaviour.
4. Run `pytest` locally and make sure CI is green.
5. Open a pull request against `main` using the PR template.

## Commit messages

Use the imperative mood and describe **why**, not just **what**.

Good: `Block delegate calls when subagent capability set exceeds parent`
Avoid: `Update agent.py`

If your change is user-visible, add a line to
[`CHANGELOG.md`](CHANGELOG.md) under the unreleased section.

## Code style

- Python: `ruff` for linting, `black`-compatible formatting (line length 100)
- TypeScript: project uses Next.js defaults; run `npm run lint` in
  `app/frontend/`
- Lean 4: follow the conventions in `lean4/CertiorLattice/` -
  no `sorry`, no extra axioms beyond the three standard Lean axioms

## Merge policy

Mergeable changes:
- Bug fixes with a regression test
- New adapter integrations (Anthropic, OpenAI, LangChain, CrewAI, MCP,
  framework-agnostic loops)
- Documentation improvements
- Performance fixes that include a measurement
- New policy presets backed by a clear compliance rationale

Not mergeable:
- Changes that weaken the formal guarantees without a justification
  reviewed against the Lean model
- Adding heavy runtime dependencies to the `certior` core package
  (prefer an optional extra)
- Code that mocks the database in integration tests where a real
  connection is feasible

## Licensing

All contributions are accepted under the project's
[Apache-2.0 license](LICENSE). By submitting a pull request you
confirm you have the right to license your contribution under those
terms.

## Code of conduct

Participation in this project is governed by
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
