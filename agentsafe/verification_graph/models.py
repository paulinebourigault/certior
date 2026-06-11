from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Optional


def stable_id(*parts: str) -> str:
    joined = "::".join(parts)
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()
    return digest


def json_ready(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def classify_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix == ".lean":
        return "lean"
    if suffix == ".dfy":
        return "dafny"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return "config"
    return "other"


EDGE_TAXONOMY: dict[str, dict[str, Any]] = {
    "DECLARES": {
        "category": "structure",
        "description": "A source file, package, or module declares a component or declaration.",
    },
    "IMPORTS": {
        "category": "structure",
        "description": "A Python or Lean module imports another module.",
    },
    "CALLS": {
        "category": "structure",
        "description": "A bounded, manifest-authorized Python declaration calls a verification-critical symbol.",
    },
    "TESTS": {
        "category": "curated_alignment",
        "description": "A component is covered by a maintained test path.",
    },
    "MIRRORS_MODEL": {
        "category": "curated_alignment",
        "description": "A runtime bridge mirrors a Dafny model component.",
    },
    "IMPLEMENTS_PROPERTY": {
        "category": "curated_alignment",
        "description": "A component implements a verified property surface.",
    },
    "PROVES": {
        "category": "curated_alignment",
        "description": "A proof-bearing component or runtime artifact proves a verified property.",
    },
    "BUILDS_BINARY": {
        "category": "build",
        "description": "A Lean package builds a runtime-facing binary.",
    },
    "EXPORTS_EVIDENCE": {
        "category": "curated_alignment",
        "description": "A bridge exports a proof artifact or evidence type.",
    },
    "CONFIGURES": {
        "category": "curated_alignment",
        "description": "A bridge or component configures a runtime entrypoint used in attestation.",
    },
    "USES_POLICY": {
        "category": "runtime_evidence",
        "description": "An execution or workflow stage uses a policy profile.",
    },
    "USES_VERIFICATION_PROFILE": {
        "category": "runtime_evidence",
        "description": "An execution uses a persisted verification profile.",
    },
    "EMITS_EVIDENCE": {
        "category": "runtime_evidence",
        "description": "An execution emits a runtime artifact or certificate.",
    },
    "SUPPORTS_PROPERTY": {
        "category": "runtime_evidence",
        "description": "A runtime artifact supports a verified property during execution.",
    },
    "PRODUCES": {
        "category": "runtime_evidence",
        "description": "An execution produces a runtime artifact.",
    },
    "ATTESTS_ARTIFACT": {
        "category": "release_lineage",
        "description": "An execution attests to a release artifact.",
    },
    "BINDS_ARTIFACT": {
        "category": "release_lineage",
        "description": "A release-binding artifact binds an approved runtime artifact.",
    },
    "DEPENDS_ON_EXECUTION": {
        "category": "release_lineage",
        "description": "An execution depends on an upstream execution.",
    },
    "CONTAINS_STAGE": {
        "category": "workflow_lineage",
        "description": "A workflow contains a workflow stage.",
    },
    "EXECUTES": {
        "category": "workflow_lineage",
        "description": "A workflow stage executes an execution artifact.",
    },
    "DEPENDS_ON_STAGE": {
        "category": "workflow_lineage",
        "description": "A workflow stage depends on an upstream workflow stage.",
    },
    "USES_PROOF": {
        "category": "reserved",
        "description": "Reserved for future direct proof dependency edges.",
    },
    "ENFORCES_POLICY": {
        "category": "reserved",
        "description": "Reserved for future runtime enforcement edges.",
    },
    "DEGRADES_TO": {
        "category": "reserved",
        "description": "Reserved for future degraded-mode lineage.",
    },
    "GENERATES": {
        "category": "reserved",
        "description": "Reserved for future artifact generation edges.",
    },
}


@dataclass(frozen=True)
class RepoIdentity:
    repo_id: str
    name: str
    root_path: str
    branch: str
    commit_sha: str
    is_dirty: bool


@dataclass(frozen=True)
class SourceFileRecord:
    id: str
    path: str
    sha256: str
    language: str
    size_bytes: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComponentRecord:
    id: str
    name: str
    display_name: str
    kind: str
    language: str
    source_path: Optional[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeclarationRecord:
    id: str
    component_id: Optional[str]
    qualified_name: str
    kind: str
    language: str
    source_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifiedPropertyRecord:
    id: str
    property_key: str
    name: str
    proof_system: str
    source_path: Optional[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProofArtifactRecord:
    id: str
    artifact_key: str
    name: str
    proof_system: str
    source_path: Optional[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeArtifactRecord:
    id: str
    artifact_key: str
    artifact_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionArtifactRecord:
    id: str
    artifact_key: str
    execution_id: str
    artifact_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyProfileRecord:
    id: str
    profile_key: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkflowProfileRecord:
    id: str
    profile_key: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdgeRecord:
    id: str
    edge_type: str
    source_ref: str
    source_kind: str
    target_ref: str
    target_kind: str
    provenance_kind: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.edge_type not in EDGE_TAXONOMY:
            allowed = ", ".join(sorted(EDGE_TAXONOMY))
            raise ValueError(f"unknown edge_type '{self.edge_type}'; expected one of: {allowed}")


@dataclass(frozen=True)
class IngestIssueRecord:
    id: str
    severity: str
    code: str
    message: str
    path: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SnapshotBundle:
    files: list[SourceFileRecord]
    components: list[ComponentRecord]
    declarations: list[DeclarationRecord]
    properties: list[VerifiedPropertyRecord]
    proof_artifacts: list[ProofArtifactRecord]
    runtime_artifacts: list[RuntimeArtifactRecord] = field(default_factory=list)
    execution_artifacts: list[ExecutionArtifactRecord] = field(default_factory=list)
    policy_profiles: list[PolicyProfileRecord] = field(default_factory=list)
    workflow_profiles: list[WorkflowProfileRecord] = field(default_factory=list)
    edges: list[GraphEdgeRecord] = field(default_factory=list)
    issues: list[IngestIssueRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)