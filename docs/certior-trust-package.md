# Certior Trust Package & Assurance Model

This document serves as the canonical Trust Package for Certior. It clarifies our exact assurance model to customers, independent auditors, and security integrators.

## 1. What Certior Proves

Certior is a formally verified agent orchestration platform. When Certior issues a **Release Decision** or executes an **Agentic Action**, it proves the following properties hold true mathematically:
* **Capability Containment:** An agent can never execute an operation (e.g., shell command, database query) that exceeds the cryptographic capabilities granted to it prior to execution.
* **Compliance Ceilings (Policy Boundaries):** Domain-specific constraints (such as HIPAA isolation, SOX non-repudiation, or SOC2 change management rules) are checked universally using a Lean 4 mathematical lattice and a Z3 runtime dependency solver.
* **Lineage & Provenance:** Every piece of runtime evidence (e.g., test results, static analysis findings) is deterministically bound to a specific snapshot of code (Commit SHA), policies, and cryptographic runtime state.

## 2. What Certior Does Not Prove

To ensure trust, we are explicit about our boundaries. Certior **does not** prove:
* **LLM Output Correctness:** We cannot mathematically prove the LLM's natural language output is "correct" or "helpful". We only prove that the LLM's *actions* remain within permitted structural bounds.
* **Upstream Data Integrity:** If an external system (like a CI runner or webhook source) lies about the content of a commit, Certior records the lie truthfully. We rely on cryptographic signatures of the pipeline to trust the upstream node.
* **Zero-Day Sandboxing:** While we enforce policy statically and dynamically, the underlying transport container must be secured by standard DevSecOps practices (gVisor, Seccomp profiles, least privilege).

## 3. How Runtime Evidence Binds To Proof Claims

For evidence to be accepted into the "Verification Graph", the following pipeline executes:
1. **Creation:** A runtime worker produces a claim.
2. **Attestation:** The claim is enriched with a `CertiorCapabilityToken` containing the execution bounds.
3. **Graph Ingest:** The ingest microservice hashes the payload and links it as a strictly directed edge from the specific code Commit SHA.
4. **Export Validation:** A compliance audit package (`GET /compliance/.../export`) extracts this subgraph. It verifies the capability lattice natively using Lean 4 before printing the PDF/JSON evidence record.

## 4. How Release Decisions Are Formed

Certior prevents deployment of unacceptable code configurations via the **Canonical Release Decision**. The decision is purely deterministic:
* `GET /api/v1/releases/decision` traverses the verification graph.
* It collects all active compliance policies for the repository.
* It evaluates the presence and freshness of all required runtime evidence (e.g., SAST scans, functional tests, peer review sign-offs).
* If *any* policy fails, or evidence is missing/stale, the decision universally resolves to **NO_SHIP / BLOCKED**.
* Only when all proofs are structurally valid, signed, and fresh will the endpoint return **SHIP / PROMOTABLE**. Human approvers can then lock this via `POST /api/v1/releases/promote`. 

## 5. Operational Assumptions

For the assurance model to hold, customers operating Certior must guarantee:
* **Database Isolation:** The PostgreSQL verification graph cannot be directly mutated by raw SQL outside of the Certior `agentsafe` ORM logic.
* **Identity Immutability:** JWT or API keys given to Approvers must map strictly back to single human identities. Role separation relies heavily on `APPROVER`, `AUDITOR`, and `POLICY_AUTHOR` distinctions.
* **Key Rotation:** LLM API keys must be injected securely via platform secrets management (e.g., Vault, Kubernetes Secrets) rather than hardcoded configurations, preventing unauthorized direct agent usage outside the verified execution loop.

---
*Maintained by the Certior Operations and Engineering teams. Updated alongside major release-decision changes.*
