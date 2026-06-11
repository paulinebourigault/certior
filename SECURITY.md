# Security policy

Certior is a security-focused tool. Vulnerability reports are taken seriously and triaged within 48 hours.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.** Working exploits posted publicly put downstream users at immediate risk.

Instead, email **hello@certior.io** with:

- A clear description of the issue and the conditions under which it triggers
- A minimal reproducer (code snippet, payload, configuration) if one exists
- The Certior version (`pip show certior | grep Version`) and Python version
- Your assessment of severity (informational / low / medium / high / critical)
- Whether you intend to disclose publicly, and on what timeline

A PGP key is available on request if you want to encrypt the report.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of report | within 48 hours |
| Initial severity assessment | within 7 days |
| Fix for confirmed high/critical issues | within 14 days |
| Coordinated disclosure | as agreed with reporter; default 90 days |

If a fix requires a coordinated release with downstream tooling (LangChain, CrewAI, MCP servers), the disclosure timeline may extend; you will be kept informed.

## Supported versions

During the 0.x series, only the **latest minor version** receives security fixes. Once 1.0 ships, this policy will be revised to cover the latest two minor versions.

| Version | Supported |
| --- | --- |
| 0.1.x (current alpha) | ✓ |
| < 0.1   | ✗ |

## Scope

In scope:

- The `certior` PyPI package (`from certior import *`)
- The `agentsafe` runtime layer bundled in the same package
- The example code under [`examples/`](https://github.com/paulinebourigault/certior/tree/main/examples)
- The reference server in [`app/`](https://github.com/paulinebourigault/certior/tree/main/app) when used per documented deployment instructions
- The Lean policy model in [`lean4/`](https://github.com/paulinebourigault/certior/tree/main/lean4) - proof-rot or unsound theorem reports welcome

Out of scope (but still worth reporting if striking):

- Vulnerabilities in the underlying LLM provider (OpenAI, Anthropic, etc.)
- Vulnerabilities in third-party dependencies - please report to the upstream maintainer; Certior will follow with a pinned version
- Issues that require an attacker to already have shell access to the host running Certior

## Hall of fame

Reporters of valid, confirmed issues will be acknowledged in the project release notes unless they prefer to remain anonymous.

## Responsible disclosure

This project commits to:

- No legal action against good-faith researchers
- No non-disclosure agreement as a precondition for review
- Public credit for reporters (with their consent)
- A CVE for any confirmed high/critical issue affecting released versions
