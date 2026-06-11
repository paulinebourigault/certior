from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from .models import (
    ComponentRecord,
    DeclarationRecord,
    ExecutionArtifactRecord,
    GraphEdgeRecord,
    IngestIssueRecord,
    PolicyProfileRecord,
    ProofArtifactRecord,
    RepoIdentity,
    RuntimeArtifactRecord,
    SnapshotBundle,
    SourceFileRecord,
    VerifiedPropertyRecord,
    WorkflowProfileRecord,
    stable_id,
)

log = logging.getLogger(__name__)

try:
    import asyncpg  # type: ignore[import-untyped]
    _HAS_ASYNCPG = True
except ImportError:
    asyncpg = None  # type: ignore[assignment]
    _HAS_ASYNCPG = False


def _require_asyncpg() -> None:
    if not _HAS_ASYNCPG:
        raise ImportError(
            "asyncpg is required for verification graph persistence. "
            "Install: pip install 'certior[postgres]' or pip install asyncpg"
        )


_DDL = """
CREATE TABLE IF NOT EXISTS repos (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_commits (
    id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL,
    dirty BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE(repo_id, commit_sha, dirty)
);
CREATE TABLE IF NOT EXISTS ingest_snapshots (
    id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL,
    commit_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at DOUBLE PRECISION NOT NULL,
    completed_at DOUBLE PRECISION,
    manifest_version TEXT NOT NULL DEFAULT '1',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS snapshot_promotions (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    repo_id TEXT NOT NULL,
    status TEXT NOT NULL,
    release_label TEXT,
    created_at DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE(snapshot_id, status)
);
CREATE TABLE IF NOT EXISTS source_files (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    language TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS components (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    language TEXT NOT NULL,
    source_path TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS declarations (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    component_id TEXT,
    qualified_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    language TEXT NOT NULL,
    source_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS verified_properties (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    property_key TEXT NOT NULL,
    name TEXT NOT NULL,
    proof_system TEXT NOT NULL,
    source_path TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS proof_artifacts (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    artifact_key TEXT NOT NULL,
    name TEXT NOT NULL,
    proof_system TEXT NOT NULL,
    source_path TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS runtime_artifacts (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    artifact_key TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS execution_artifacts (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    artifact_key TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS policy_profiles (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    profile_key TEXT NOT NULL,
    name TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS workflow_profiles (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    profile_key TEXT NOT NULL,
    name TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    provenance_kind TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS ingest_issues (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    path TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_snapshot_repo ON ingest_snapshots (repo_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshot_promotions_repo_status ON snapshot_promotions (repo_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_component_name ON components (snapshot_id, name);
CREATE INDEX IF NOT EXISTS idx_component_display_name ON components (snapshot_id, display_name);
CREATE INDEX IF NOT EXISTS idx_decl_name ON declarations (snapshot_id, qualified_name);
CREATE INDEX IF NOT EXISTS idx_edge_lookup ON graph_edges (snapshot_id, edge_type, source_ref, target_ref);
CREATE INDEX IF NOT EXISTS idx_property_key ON verified_properties (snapshot_id, property_key);
CREATE INDEX IF NOT EXISTS idx_runtime_artifact_lookup ON runtime_artifacts (snapshot_id, artifact_key, artifact_type);
CREATE INDEX IF NOT EXISTS idx_execution_artifact_lookup ON execution_artifacts (snapshot_id, artifact_key, execution_id);
CREATE INDEX IF NOT EXISTS idx_workflow_profile_lookup ON workflow_profiles (snapshot_id, profile_key);
CREATE INDEX IF NOT EXISTS idx_policy_profile_lookup ON policy_profiles (snapshot_id, profile_key);
CREATE INDEX IF NOT EXISTS idx_ingest_issue_lookup ON ingest_issues (snapshot_id, severity, code);

DROP VIEW IF EXISTS verification_release_attestation_readiness;
DROP VIEW IF EXISTS verification_ingest_health;
DROP VIEW IF EXISTS verification_stale_verification;
DROP VIEW IF EXISTS verification_runtime_evidence_freshness;
DROP VIEW IF EXISTS verification_proof_coverage;
DROP VIEW IF EXISTS verification_proof_runtime_trace;

CREATE OR REPLACE VIEW verification_proof_runtime_trace AS
WITH property_evidence AS (
        SELECT ge.snapshot_id,
                     ge.target_ref AS property_key,
                     vp.name AS property_name,
                     vp.proof_system AS property_proof_system,
                     ge.source_ref AS evidence_ref,
                     ge.source_kind AS evidence_kind,
                     ge.edge_type AS evidence_edge_type,
                     ge.provenance_kind,
                     ge.confidence
        FROM graph_edges ge
        JOIN verified_properties vp
            ON vp.snapshot_id = ge.snapshot_id
         AND vp.property_key = ge.target_ref
        WHERE ge.target_kind = 'verified_property'
            AND ge.source_kind IN ('execution_artifact', 'runtime_artifact')
            AND ge.edge_type IN ('PROVES', 'SUPPORTS_PROPERTY')
), execution_binding AS (
        SELECT pe.snapshot_id,
                     pe.property_key,
                     pe.property_name,
                     pe.property_proof_system,
                     pe.evidence_ref,
                     pe.evidence_kind,
                     pe.evidence_edge_type,
                     pe.provenance_kind,
                     pe.confidence,
                     COALESCE(exec_self.artifact_key, emit_exec.artifact_key) AS execution_ref,
                     COALESCE(exec_self.execution_id, emit_exec.execution_id) AS execution_id,
                     COALESCE(exec_self.artifact_type, emit_exec.artifact_type) AS execution_artifact_type,
                     runtime_self.artifact_key AS runtime_artifact_ref,
                     runtime_self.artifact_type AS runtime_artifact_type
        FROM property_evidence pe
        LEFT JOIN execution_artifacts exec_self
            ON exec_self.snapshot_id = pe.snapshot_id
         AND pe.evidence_kind = 'execution_artifact'
         AND exec_self.artifact_key = pe.evidence_ref
        LEFT JOIN runtime_artifacts runtime_self
            ON runtime_self.snapshot_id = pe.snapshot_id
         AND pe.evidence_kind = 'runtime_artifact'
         AND runtime_self.artifact_key = pe.evidence_ref
        LEFT JOIN graph_edges emitted
            ON emitted.snapshot_id = pe.snapshot_id
         AND pe.evidence_kind = 'runtime_artifact'
         AND emitted.edge_type = 'EMITS_EVIDENCE'
         AND emitted.target_ref = pe.evidence_ref
         AND emitted.source_kind = 'execution_artifact'
        LEFT JOIN execution_artifacts emit_exec
            ON emit_exec.snapshot_id = pe.snapshot_id
         AND emit_exec.artifact_key = emitted.source_ref
)
SELECT s.id AS snapshot_id,
             r.root_path,
             rc.commit_sha,
             rc.dirty,
             eb.property_key,
             eb.property_name,
             eb.property_proof_system,
             eb.evidence_ref,
             eb.evidence_kind,
             eb.evidence_edge_type,
             eb.provenance_kind,
             eb.confidence,
             eb.execution_ref,
             eb.execution_id,
             eb.execution_artifact_type,
             eb.runtime_artifact_ref,
             eb.runtime_artifact_type,
             COALESCE(exec_policy.target_ref, stage_policy.target_ref) AS policy_ref,
             stage_exec.source_ref AS workflow_stage_ref,
             workflow_stage.source_ref AS workflow_ref
FROM execution_binding eb
JOIN ingest_snapshots s
    ON s.id = eb.snapshot_id
JOIN repos r
    ON r.id = s.repo_id
JOIN repo_commits rc
    ON rc.id = s.commit_id
LEFT JOIN graph_edges exec_policy
    ON exec_policy.snapshot_id = eb.snapshot_id
 AND exec_policy.edge_type = 'USES_POLICY'
 AND exec_policy.source_ref = COALESCE(eb.execution_ref, '')
LEFT JOIN graph_edges stage_exec
    ON stage_exec.snapshot_id = eb.snapshot_id
 AND stage_exec.edge_type = 'EXECUTES'
 AND stage_exec.target_ref = COALESCE(eb.execution_ref, '')
LEFT JOIN graph_edges stage_policy
    ON stage_policy.snapshot_id = eb.snapshot_id
 AND stage_policy.edge_type = 'USES_POLICY'
 AND stage_policy.source_ref = stage_exec.source_ref
LEFT JOIN graph_edges workflow_stage
    ON workflow_stage.snapshot_id = eb.snapshot_id
 AND workflow_stage.edge_type = 'CONTAINS_STAGE'
 AND workflow_stage.target_ref = stage_exec.source_ref;

CREATE OR REPLACE VIEW verification_runtime_evidence_freshness AS
WITH evidence_rows AS (
        SELECT ptrt.snapshot_id,
                     ptrt.root_path,
                     ptrt.commit_sha,
                     ptrt.dirty,
                     ptrt.property_key,
                     ptrt.property_name,
                     ptrt.property_proof_system,
                     ptrt.evidence_ref,
                     ptrt.evidence_kind,
                     ptrt.execution_ref,
                     ptrt.execution_id,
                     ptrt.execution_artifact_type,
                     ptrt.runtime_artifact_ref,
                     ptrt.runtime_artifact_type,
                     ptrt.policy_ref,
                     ptrt.workflow_ref,
                     s.started_at AS snapshot_started_at,
                     s.completed_at AS snapshot_completed_at,
                     s.metadata AS snapshot_metadata,
                     ea.metadata AS execution_metadata,
                     ra.metadata AS runtime_metadata,
                     COALESCE(
                         NULLIF(ea.metadata->>'exported_at', '')::double precision,
                         NULLIF(ea.metadata->>'completed_at', '')::double precision,
                         NULLIF(ea.metadata->>'created_at', '')::double precision,
                         NULLIF(ra.metadata->>'exported_at', '')::double precision,
                         NULLIF(ra.metadata->>'completed_at', '')::double precision,
                         NULLIF(ra.metadata->>'created_at', '')::double precision
                     ) AS evidence_timestamp,
                     COALESCE(ea.metadata->>'source_commit_sha', ra.metadata->>'source_commit_sha') AS evidence_commit_sha,
                     COALESCE(ea.metadata->>'build_identity', ra.metadata->>'build_identity') AS evidence_build_identity,
                     COALESCE((ea.metadata->>'attestation_scope')::boolean, (ra.metadata->>'attestation_scope')::boolean, FALSE) AS evidence_attestation_scope,
                     COALESCE(ra.metadata->>'identity_kind', ea.metadata->>'identity_kind', ptrt.evidence_kind) AS identity_kind,
                     COALESCE(ra.metadata->>'identity_key', ea.metadata->>'identity_key', ptrt.evidence_ref) AS identity_key,
                     s.metadata->>'build_identity' AS snapshot_build_identity
        FROM verification_proof_runtime_trace ptrt
        JOIN ingest_snapshots s
            ON s.id = ptrt.snapshot_id
        LEFT JOIN execution_artifacts ea
            ON ea.snapshot_id = ptrt.snapshot_id
           AND ea.artifact_key = ptrt.execution_ref
        LEFT JOIN runtime_artifacts ra
            ON ra.snapshot_id = ptrt.snapshot_id
           AND ra.artifact_key = ptrt.evidence_ref
), ranked_evidence AS (
        SELECT er.*,
                     CASE
                         WHEN er.evidence_timestamp IS NULL THEN 'unknown_export_time'
                         WHEN er.evidence_commit_sha IS NOT NULL AND er.evidence_commit_sha <> er.commit_sha THEN 'stale_commit_mismatch'
                         WHEN er.snapshot_build_identity IS NOT NULL AND er.evidence_build_identity IS NOT NULL AND er.evidence_build_identity <> er.snapshot_build_identity THEN 'stale_build_mismatch'
                         WHEN er.snapshot_completed_at IS NOT NULL AND er.evidence_timestamp > er.snapshot_completed_at + 60 THEN 'future_export_time'
                         WHEN er.snapshot_started_at IS NOT NULL AND er.evidence_timestamp < er.snapshot_started_at - 604800 THEN 'stale_export_time'
                         WHEN er.evidence_attestation_scope = TRUE AND er.evidence_build_identity IS NULL THEN 'timestamp_only'
                         ELSE 'fresh'
                     END AS freshness_state,
                     row_number() OVER (
                         PARTITION BY er.snapshot_id, er.property_key
                         ORDER BY COALESCE(er.evidence_timestamp, 0) DESC, er.evidence_ref
                     ) AS evidence_rank
        FROM evidence_rows er
)
SELECT snapshot_id,
             root_path,
             commit_sha,
             dirty,
             property_key,
             property_name,
             property_proof_system,
             evidence_ref,
             evidence_kind,
             execution_ref,
             execution_id,
             execution_artifact_type,
             runtime_artifact_ref,
             runtime_artifact_type,
             policy_ref,
             workflow_ref,
             identity_kind,
             identity_key,
             evidence_timestamp,
             evidence_commit_sha,
             evidence_build_identity,
             evidence_attestation_scope,
             snapshot_started_at,
             snapshot_completed_at,
             freshness_state,
             (freshness_state IN ('fresh', 'timestamp_only')) AS is_fresh,
             (freshness_state = 'timestamp_only') AS missing_build_identity,
             evidence_rank
FROM ranked_evidence;

CREATE OR REPLACE VIEW verification_proof_coverage AS
WITH canonical_components AS (
        SELECT c.snapshot_id,
                     c.name,
                     c.display_name,
                     c.kind,
                     c.language,
                     c.source_path,
                     COALESCE((c.metadata->>'runtime_critical')::boolean, false) AS runtime_critical,
                     CASE
                         WHEN c.kind IN ('lean_package', 'lean_binary') THEN COALESCE(
                             (
                                 SELECT manifest.name
                                 FROM components manifest
                                 WHERE manifest.snapshot_id = c.snapshot_id
                                   AND manifest.kind = c.kind
                                   AND (manifest.metadata ? 'phase' OR manifest.metadata ? 'proof_family')
                                   AND lower(manifest.display_name) = lower(c.display_name)
                                 ORDER BY manifest.name
                                 LIMIT 1
                             ),
                             c.name
                         )
                         ELSE c.name
                     END AS canonical_component_name,
                     CASE
                         WHEN c.metadata ? 'phase' OR c.metadata ? 'proof_family' THEN 0
                         ELSE 1
                     END AS identity_rank
        FROM components c
), canonical_inventory AS (
        SELECT cc.snapshot_id,
                     cc.canonical_component_name AS component_name,
                     (array_agg(cc.display_name ORDER BY cc.identity_rank, cc.name))[1] AS display_name,
                     (array_agg(cc.kind ORDER BY cc.identity_rank, cc.name))[1] AS component_kind,
                     (array_agg(cc.language ORDER BY cc.identity_rank, cc.name))[1] AS component_language,
                     (array_agg(cc.source_path ORDER BY CASE WHEN cc.source_path IS NULL THEN 1 ELSE 0 END, cc.identity_rank, cc.name))[1] AS component_source_path,
                     bool_or(cc.runtime_critical) AS runtime_critical,
                     array_agg(DISTINCT cc.name ORDER BY cc.name) AS component_aliases
        FROM canonical_components cc
        GROUP BY cc.snapshot_id, cc.canonical_component_name
), direct_component_properties AS (
        SELECT DISTINCT cc.snapshot_id,
                        cc.canonical_component_name AS component_name,
                        ge.target_ref AS property_key
        FROM graph_edges ge
        JOIN canonical_components cc
            ON cc.snapshot_id = ge.snapshot_id
           AND cc.name = ge.source_ref
        WHERE ge.source_kind = 'component'
          AND ge.target_kind = 'verified_property'
          AND ge.edge_type IN ('IMPLEMENTS_PROPERTY', 'PROVES')
), configured_component_properties AS (
        SELECT DISTINCT cfg.snapshot_id,
                        configured.canonical_component_name AS component_name,
                        direct.property_key
        FROM graph_edges cfg
        JOIN canonical_components source_component
            ON source_component.snapshot_id = cfg.snapshot_id
           AND source_component.name = cfg.source_ref
        JOIN canonical_components configured
            ON configured.snapshot_id = cfg.snapshot_id
           AND configured.name = cfg.target_ref
        JOIN direct_component_properties direct
            ON direct.snapshot_id = cfg.snapshot_id
           AND direct.component_name = source_component.canonical_component_name
        WHERE cfg.edge_type = 'CONFIGURES'
          AND cfg.source_kind = 'component'
          AND cfg.target_kind = 'component'
), propagated_component_properties AS (
        SELECT snapshot_id, component_name, property_key
        FROM direct_component_properties
        UNION
        SELECT snapshot_id, component_name, property_key
        FROM configured_component_properties
), built_component_properties AS (
        SELECT DISTINCT build.snapshot_id,
                        builder.canonical_component_name AS component_name,
                        propagated.property_key
        FROM graph_edges build
        JOIN canonical_components builder
            ON builder.snapshot_id = build.snapshot_id
           AND builder.name = build.source_ref
        JOIN canonical_components built
            ON built.snapshot_id = build.snapshot_id
           AND built.name = build.target_ref
        JOIN propagated_component_properties propagated
            ON propagated.snapshot_id = build.snapshot_id
           AND propagated.component_name = built.canonical_component_name
        WHERE build.edge_type = 'BUILDS_BINARY'
          AND build.source_kind = 'component'
          AND build.target_kind = 'component'
), component_property_links AS (
        SELECT snapshot_id, component_name, property_key
        FROM propagated_component_properties
        UNION
        SELECT snapshot_id, component_name, property_key
        FROM built_component_properties
), component_properties AS (
        SELECT ci.snapshot_id,
                     ci.component_name,
                     ci.display_name,
                     ci.component_kind,
                     ci.component_language,
                     ci.component_source_path,
                     ci.runtime_critical,
                     ci.component_aliases,
                     vp.property_key,
                     vp.name AS property_name,
                     vp.proof_system AS property_proof_system,
                     (
                         COALESCE((vp.metadata->'release_attestation_components') ? ci.component_name, false)
                         AND (
                             jsonb_typeof(COALESCE(vp.metadata->'release_attestation_properties', '[]'::jsonb)) <> 'array'
                             OR jsonb_array_length(COALESCE(vp.metadata->'release_attestation_properties', '[]'::jsonb)) = 0
                             OR (vp.metadata->'release_attestation_properties') ? vp.property_key
                         )
                     ) AS attestation_scope
        FROM canonical_inventory ci
        LEFT JOIN component_property_links cpl
            ON cpl.snapshot_id = ci.snapshot_id
         AND cpl.component_name = ci.component_name
        LEFT JOIN verified_properties vp
            ON vp.snapshot_id = ci.snapshot_id
         AND vp.property_key = cpl.property_key
), component_tests AS (
        SELECT cc.snapshot_id,
                     cc.canonical_component_name AS component_name,
                     count(DISTINCT ge.target_ref) AS test_count
        FROM graph_edges ge
        JOIN canonical_components cc
            ON cc.snapshot_id = ge.snapshot_id
           AND cc.name = ge.source_ref
        WHERE ge.edge_type = 'TESTS'
        GROUP BY cc.snapshot_id, cc.canonical_component_name
), property_runtime AS (
        SELECT snapshot_id,
                     property_key,
                     count(DISTINCT execution_id) AS execution_count,
                     count(DISTINCT evidence_ref) AS evidence_count,
                     count(DISTINCT workflow_ref) AS workflow_count,
                     count(DISTINCT policy_ref) AS policy_count
        FROM verification_proof_runtime_trace
        GROUP BY snapshot_id, property_key
)
SELECT cp.snapshot_id,
             r.root_path,
             rc.commit_sha,
             rc.dirty,
             cp.component_name,
             cp.display_name,
             cp.component_kind,
             cp.component_language,
             cp.component_source_path,
             cp.runtime_critical,
             cp.component_aliases,
             cp.property_key,
             cp.property_name,
             cp.property_proof_system,
             COALESCE(ct.test_count, 0) AS test_count,
             COALESCE(pr.execution_count, 0) AS execution_count,
             COALESCE(pr.evidence_count, 0) AS evidence_count,
             COALESCE(pr.workflow_count, 0) AS workflow_count,
             COALESCE(pr.policy_count, 0) AS policy_count,
             (COALESCE(pr.evidence_count, 0) > 0) AS has_runtime_evidence,
             cp.attestation_scope
FROM component_properties cp
JOIN ingest_snapshots s
    ON s.id = cp.snapshot_id
JOIN repos r
    ON r.id = s.repo_id
JOIN repo_commits rc
    ON rc.id = s.commit_id
LEFT JOIN component_tests ct
    ON ct.snapshot_id = cp.snapshot_id
 AND ct.component_name = cp.component_name
LEFT JOIN property_runtime pr
    ON pr.snapshot_id = cp.snapshot_id
 AND pr.property_key = cp.property_key;

CREATE OR REPLACE VIEW verification_stale_verification AS
WITH latest_freshness AS (
    SELECT snapshot_id,
             property_key,
             freshness_state,
             is_fresh,
             missing_build_identity,
             evidence_ref,
             identity_kind,
             identity_key,
             evidence_timestamp,
             evidence_commit_sha,
             evidence_build_identity
    FROM verification_runtime_evidence_freshness
    WHERE evidence_rank = 1
)
SELECT snapshot_id,
             root_path,
             commit_sha,
             dirty,
             component_name,
             display_name,
             component_kind,
             component_language,
             component_source_path,
             property_key,
             property_name,
             property_proof_system,
             'error' AS severity,
             'missing_property_coverage' AS stale_reason,
             'Runtime-critical component has no mapped verified property.' AS detail
FROM verification_proof_coverage
WHERE runtime_critical = TRUE
    AND property_key IS NULL
UNION ALL
SELECT verification_proof_coverage.snapshot_id,
             verification_proof_coverage.root_path,
             verification_proof_coverage.commit_sha,
             verification_proof_coverage.dirty,
             verification_proof_coverage.component_name,
             verification_proof_coverage.display_name,
             verification_proof_coverage.component_kind,
             verification_proof_coverage.component_language,
             verification_proof_coverage.component_source_path,
             verification_proof_coverage.property_key,
             verification_proof_coverage.property_name,
             verification_proof_coverage.property_proof_system,
             'warning' AS severity,
             'missing_runtime_evidence' AS stale_reason,
             'Verified property has no bound runtime evidence in this snapshot.' AS detail
FROM verification_proof_coverage
LEFT JOIN latest_freshness lf
    ON lf.snapshot_id = verification_proof_coverage.snapshot_id
 AND lf.property_key = verification_proof_coverage.property_key
WHERE verification_proof_coverage.property_key IS NOT NULL
    AND verification_proof_coverage.attestation_scope = TRUE
    AND lf.property_key IS NULL
UNION ALL
SELECT verification_proof_coverage.snapshot_id,
             verification_proof_coverage.root_path,
             verification_proof_coverage.commit_sha,
             verification_proof_coverage.dirty,
             verification_proof_coverage.component_name,
             verification_proof_coverage.display_name,
             verification_proof_coverage.component_kind,
             verification_proof_coverage.component_language,
             verification_proof_coverage.component_source_path,
             verification_proof_coverage.property_key,
             verification_proof_coverage.property_name,
             verification_proof_coverage.property_proof_system,
             'warning' AS severity,
             'stale_runtime_evidence' AS stale_reason,
             CASE lf.freshness_state
                 WHEN 'stale_commit_mismatch' THEN 'Runtime evidence is bound to a different commit than the current snapshot.'
                 WHEN 'stale_build_mismatch' THEN 'Runtime evidence build identity does not match the current snapshot build identity.'
                 WHEN 'future_export_time' THEN 'Runtime evidence timestamp is newer than the snapshot completion time.'
                 WHEN 'stale_export_time' THEN 'Runtime evidence is older than the allowed freshness window for this snapshot.'
                 ELSE 'Runtime evidence freshness could not be established.'
             END AS detail
FROM verification_proof_coverage
JOIN latest_freshness lf
    ON lf.snapshot_id = verification_proof_coverage.snapshot_id
 AND lf.property_key = verification_proof_coverage.property_key
WHERE verification_proof_coverage.property_key IS NOT NULL
    AND verification_proof_coverage.attestation_scope = TRUE
    AND lf.is_fresh = FALSE
UNION ALL
SELECT snapshot_id,
             root_path,
             commit_sha,
             dirty,
             component_name,
             display_name,
             component_kind,
             component_language,
             component_source_path,
             property_key,
             property_name,
             property_proof_system,
             'warning' AS severity,
             'missing_test_coverage' AS stale_reason,
             'Verified property has no mapped tests in the current snapshot.' AS detail
FROM verification_proof_coverage
WHERE property_key IS NOT NULL
    AND attestation_scope = TRUE
    AND test_count = 0;

CREATE OR REPLACE VIEW verification_ingest_health AS
WITH issue_rows AS (
        SELECT s.id AS snapshot_id,
                     r.root_path,
                     rc.commit_sha,
                     rc.dirty,
                     CASE WHEN ii.severity = 'error' THEN 'blocking' ELSE 'warning' END AS health_state,
                     ii.severity,
                     ii.code,
                     ii.message AS detail,
                     ii.path,
                     ii.metadata,
                     NULL::text AS component_name,
                     NULL::text AS property_key
        FROM ingest_issues ii
        JOIN ingest_snapshots s
            ON s.id = ii.snapshot_id
        JOIN repos r
            ON r.id = s.repo_id
        JOIN repo_commits rc
            ON rc.id = s.commit_id
), stale_rows AS (
        SELECT snapshot_id,
                     root_path,
                     commit_sha,
                     dirty,
                     'stale' AS health_state,
                     severity,
                     stale_reason AS code,
                     detail,
                     component_source_path AS path,
                     jsonb_build_object(
                         'display_name', display_name,
                         'component_kind', component_kind,
                         'property_name', property_name,
                         'property_proof_system', property_proof_system
                     ) AS metadata,
                     component_name,
                     property_key
        FROM verification_stale_verification
), unresolved_alignment AS (
        SELECT s.id AS snapshot_id,
                     r.root_path,
                     rc.commit_sha,
                     rc.dirty,
                     'unresolved_alignment' AS health_state,
                     'warning' AS severity,
                     'alignment_missing' AS code,
                     'Curated verification component lacks alignment edges in the current snapshot.' AS detail,
                     c.source_path AS path,
                     jsonb_build_object(
                         'display_name', c.display_name,
                         'component_kind', c.kind,
                         'phase', c.metadata->>'phase',
                         'proof_family', c.metadata->>'proof_family'
                     ) AS metadata,
                     c.name AS component_name,
                     NULL::text AS property_key
        FROM components c
        JOIN ingest_snapshots s
            ON s.id = c.snapshot_id
        JOIN repos r
            ON r.id = s.repo_id
        JOIN repo_commits rc
            ON rc.id = s.commit_id
        WHERE c.kind IN ('python_bridge', 'dafny_model')
          AND (c.metadata ? 'phase' OR c.metadata ? 'proof_family')
          AND NOT EXISTS (
              SELECT 1
              FROM graph_edges ge
              WHERE ge.snapshot_id = c.snapshot_id
                AND ge.source_ref = c.name
                AND ge.edge_type IN ('MIRRORS_MODEL', 'IMPLEMENTS_PROPERTY', 'PROVES', 'EXPORTS_EVIDENCE', 'CONFIGURES')
          )
)
SELECT * FROM issue_rows
UNION ALL
SELECT * FROM stale_rows
UNION ALL
SELECT * FROM unresolved_alignment;

CREATE OR REPLACE VIEW verification_release_attestation_readiness AS
WITH snapshot_counts AS (
        SELECT s.id AS snapshot_id,
                     r.root_path,
                     rc.commit_sha,
                     rc.dirty,
                     count(DISTINCT ra.artifact_key) AS runtime_artifact_count,
                     count(DISTINCT ea.artifact_key) AS execution_artifact_count,
                     count(DISTINCT CASE WHEN wp.profile_key LIKE 'workflow:%' THEN wp.profile_key END) AS workflow_count,
                     count(DISTINCT CASE WHEN ii.severity = 'error' THEN ii.id END) AS blocking_issue_count,
                     count(DISTINCT CASE WHEN ii.severity <> 'error' THEN ii.id END) AS warning_issue_count
        FROM ingest_snapshots s
        JOIN repos r
            ON r.id = s.repo_id
        JOIN repo_commits rc
            ON rc.id = s.commit_id
        LEFT JOIN runtime_artifacts ra
            ON ra.snapshot_id = s.id
        LEFT JOIN execution_artifacts ea
            ON ea.snapshot_id = s.id
        LEFT JOIN workflow_profiles wp
            ON wp.snapshot_id = s.id
        LEFT JOIN ingest_issues ii
            ON ii.snapshot_id = s.id
        GROUP BY s.id, r.root_path, rc.commit_sha, rc.dirty
), stale_counts AS (
        SELECT snapshot_id,
                     count(*) FILTER (WHERE severity = 'error') AS stale_error_count,
                     count(*) FILTER (WHERE severity = 'warning') AS stale_warning_count,
                     count(*) FILTER (WHERE stale_reason = 'missing_property_coverage') AS uncovered_runtime_critical_count,
             count(*) FILTER (WHERE stale_reason = 'missing_runtime_evidence') AS missing_runtime_evidence_count,
             count(*) FILTER (WHERE stale_reason = 'stale_runtime_evidence') AS stale_runtime_evidence_count
        FROM verification_stale_verification
        GROUP BY snapshot_id
), health_counts AS (
    SELECT snapshot_id,
             count(*) FILTER (WHERE health_state = 'blocking') AS health_blocking_count,
             count(*) FILTER (WHERE health_state = 'warning') AS health_warning_count,
             count(*) FILTER (WHERE health_state = 'stale') AS health_stale_count,
             count(*) FILTER (WHERE health_state = 'unresolved_alignment') AS health_unresolved_alignment_count
    FROM verification_ingest_health
    GROUP BY snapshot_id
)
SELECT sc.snapshot_id,
             sc.root_path,
             sc.commit_sha,
             sc.dirty,
             sc.runtime_artifact_count,
             sc.execution_artifact_count,
             sc.workflow_count,
             sc.blocking_issue_count,
             sc.warning_issue_count,
             COALESCE(st.stale_error_count, 0) AS stale_error_count,
             COALESCE(st.stale_warning_count, 0) AS stale_warning_count,
             COALESCE(st.uncovered_runtime_critical_count, 0) AS uncovered_runtime_critical_count,
             COALESCE(st.missing_runtime_evidence_count, 0) AS missing_runtime_evidence_count,
             COALESCE(st.stale_runtime_evidence_count, 0) AS stale_runtime_evidence_count,
             COALESCE(hc.health_blocking_count, 0) AS health_blocking_count,
             COALESCE(hc.health_warning_count, 0) AS health_warning_count,
             COALESCE(hc.health_stale_count, 0) AS health_stale_count,
             COALESCE(hc.health_unresolved_alignment_count, 0) AS health_unresolved_alignment_count,
             (
                     sc.dirty = FALSE
                     AND sc.blocking_issue_count = 0
                     AND COALESCE(st.stale_error_count, 0) = 0
                     AND COALESCE(st.uncovered_runtime_critical_count, 0) = 0
                     AND COALESCE(st.stale_runtime_evidence_count, 0) = 0
                     AND sc.execution_artifact_count > 0
             ) AS ready_for_attestation
FROM snapshot_counts sc
LEFT JOIN stale_counts st
    ON st.snapshot_id = sc.snapshot_id
LEFT JOIN health_counts hc
    ON hc.snapshot_id = sc.snapshot_id;
"""

_VALID_SNAPSHOT_PROMOTION_STATUSES = {"promoted", "attested"}


def _snapshot_row_id(snapshot_id: str, row_id: str) -> str:
    return stable_id("snapshot_row", snapshot_id, row_id)


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _decode_row(row: Any) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in dict(row).items():
        if key == "metadata" or key.endswith("_metadata"):
            decoded[key] = _decode_json_value(value)
        else:
            decoded[key] = value
    return decoded


class PgVerificationGraphStore:
    def __init__(self, dsn: str, *, min_pool: int = 1, max_pool: int = 5):
        _require_asyncpg()
        self._dsn = dsn
        self._min_pool = min_pool
        self._max_pool = max_pool
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn,
            min_size=self._min_pool,
            max_size=self._max_pool,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_DDL)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def store_snapshot(self, repo: RepoIdentity, bundle: SnapshotBundle) -> str:
        snapshot_id = stable_id("snapshot", repo.root_path, repo.commit_sha, str(time.time()))
        commit_id = stable_id("commit", repo.repo_id, repo.commit_sha, str(repo.is_dirty))
        now = time.time()
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """INSERT INTO repos (id, name, root_path, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5)
                       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at""",
                    repo.repo_id, repo.name, repo.root_path, now, now,
                )
                await conn.execute(
                    """INSERT INTO repo_commits (id, repo_id, commit_sha, branch, dirty, created_at, metadata)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)
                       ON CONFLICT (id) DO NOTHING""",
                    commit_id, repo.repo_id, repo.commit_sha, repo.branch, repo.is_dirty, now,
                    json.dumps({"branch": repo.branch}),
                )
                await conn.execute(
                    """INSERT INTO ingest_snapshots (id, repo_id, commit_id, status, started_at, completed_at, manifest_version, metadata)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                    snapshot_id, repo.repo_id, commit_id, "completed", now, now, "1", json.dumps(bundle.metadata),
                )
                await self._insert_files(conn, snapshot_id, bundle.files)
                await self._insert_components(conn, snapshot_id, bundle.components)
                await self._insert_declarations(conn, snapshot_id, bundle.declarations)
                await self._insert_properties(conn, snapshot_id, bundle.properties)
                await self._insert_proof_artifacts(conn, snapshot_id, bundle.proof_artifacts)
                await self._insert_runtime_artifacts(conn, snapshot_id, bundle.runtime_artifacts)
                await self._insert_execution_artifacts(conn, snapshot_id, bundle.execution_artifacts)
                await self._insert_policy_profiles(conn, snapshot_id, bundle.policy_profiles)
                await self._insert_workflow_profiles(conn, snapshot_id, bundle.workflow_profiles)
                await self._insert_edges(conn, snapshot_id, bundle.edges)
                await self._insert_issues(conn, snapshot_id, bundle.issues)
        return snapshot_id

    async def _insert_files(self, conn, snapshot_id: str, rows: list[SourceFileRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO source_files (id, snapshot_id, path, sha256, language, size_bytes, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.path, row.sha256, row.language, row.size_bytes, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_components(self, conn, snapshot_id: str, rows: list[ComponentRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO components (id, snapshot_id, name, display_name, kind, language, source_path, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.name, row.display_name, row.kind, row.language, row.source_path, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_declarations(self, conn, snapshot_id: str, rows: list[DeclarationRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO declarations (id, snapshot_id, component_id, qualified_name, kind, language, source_path, line_start, line_end, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            [
                (
                    _snapshot_row_id(snapshot_id, row.id),
                    snapshot_id,
                    _snapshot_row_id(snapshot_id, row.component_id) if row.component_id else None,
                    row.qualified_name,
                    row.kind,
                    row.language,
                    row.source_path,
                    row.line_start,
                    row.line_end,
                    json.dumps(row.metadata),
                )
                for row in rows
            ],
        )

    async def _insert_properties(self, conn, snapshot_id: str, rows: list[VerifiedPropertyRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO verified_properties (id, snapshot_id, property_key, name, proof_system, source_path, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.property_key, row.name, row.proof_system, row.source_path, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_proof_artifacts(self, conn, snapshot_id: str, rows: list[ProofArtifactRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO proof_artifacts (id, snapshot_id, artifact_key, name, proof_system, source_path, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.artifact_key, row.name, row.proof_system, row.source_path, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_runtime_artifacts(self, conn, snapshot_id: str, rows: list[RuntimeArtifactRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO runtime_artifacts (id, snapshot_id, artifact_key, artifact_type, metadata) VALUES ($1,$2,$3,$4,$5)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.artifact_key, row.artifact_type, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_execution_artifacts(self, conn, snapshot_id: str, rows: list[ExecutionArtifactRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO execution_artifacts (id, snapshot_id, artifact_key, execution_id, artifact_type, metadata) VALUES ($1,$2,$3,$4,$5,$6)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.artifact_key, row.execution_id, row.artifact_type, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_policy_profiles(self, conn, snapshot_id: str, rows: list[PolicyProfileRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO policy_profiles (id, snapshot_id, profile_key, name, metadata) VALUES ($1,$2,$3,$4,$5)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.profile_key, row.name, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_workflow_profiles(self, conn, snapshot_id: str, rows: list[WorkflowProfileRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO workflow_profiles (id, snapshot_id, profile_key, name, metadata) VALUES ($1,$2,$3,$4,$5)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.profile_key, row.name, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_edges(self, conn, snapshot_id: str, rows: list[GraphEdgeRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO graph_edges (id, snapshot_id, edge_type, source_ref, source_kind, target_ref, target_kind, provenance_kind, confidence, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.edge_type, row.source_ref, row.source_kind, row.target_ref, row.target_kind, row.provenance_kind, row.confidence, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def _insert_issues(self, conn, snapshot_id: str, rows: list[IngestIssueRecord]) -> None:
        if not rows:
            return
        await conn.executemany(
            "INSERT INTO ingest_issues (id, snapshot_id, severity, code, message, path, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            [
                (_snapshot_row_id(snapshot_id, row.id), snapshot_id, row.severity, row.code, row.message, row.path, json.dumps(row.metadata))
                for row in rows
            ],
        )

    async def latest_snapshot_for_repo(self, repo_root: str) -> Optional[dict[str, Any]]:
        return await self.resolve_snapshot(repo_root)

    async def _snapshot_promotion(self, conn, snapshot_id: str, *, status: str | None = None) -> Optional[dict[str, Any]]:
        params: list[Any] = [snapshot_id]
        clauses = ["sp.snapshot_id = $1"]
        if status is not None:
            params.append(status)
            clauses.append(f"sp.status = ${len(params)}")
        where_clause = " AND ".join(clauses)
        row = await conn.fetchrow(
            f"""SELECT sp.id AS promotion_id,
                        sp.status,
                        sp.release_label,
                        sp.created_at,
                        sp.metadata
                 FROM snapshot_promotions sp
                 WHERE {where_clause}
                 ORDER BY CASE sp.status WHEN 'attested' THEN 0 ELSE 1 END, sp.created_at DESC
                 LIMIT 1""",
            *params,
        )
        return _decode_row(row) if row else None

    async def _latest_snapshot_promotion(
        self,
        conn,
        repo_root: str,
        *,
        status: str | None = None,
        exclude_snapshot_id: str | None = None,
    ) -> Optional[dict[str, Any]]:
        params: list[Any] = [repo_root]
        clauses = ["r.root_path = $1"]
        if status is not None:
            params.append(status)
            clauses.append(f"sp.status = ${len(params)}")
        if exclude_snapshot_id is not None:
            params.append(exclude_snapshot_id)
            clauses.append(f"s.id <> ${len(params)}")
        where_clause = " AND ".join(clauses)
        row = await conn.fetchrow(
            f"""SELECT sp.id AS promotion_id,
                       sp.snapshot_id,
                       sp.status,
                       sp.release_label,
                       sp.created_at,
                       sp.metadata,
                       s.started_at,
                       s.completed_at,
                       r.id AS repo_id,
                       r.name,
                       r.root_path,
                       c.commit_sha,
                       c.branch,
                       c.dirty
                FROM snapshot_promotions sp
                JOIN ingest_snapshots s ON s.id = sp.snapshot_id
                JOIN repos r ON r.id = s.repo_id
                JOIN repo_commits c ON c.id = s.commit_id
                WHERE {where_clause}
                ORDER BY sp.created_at DESC
                LIMIT 1""",
            *params,
        )
        return _decode_row(row) if row else None

    async def resolve_snapshot(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> Optional[dict[str, Any]]:
        clauses = ["r.root_path = $1"]
        params: list[Any] = [repo_root]
        if snapshot_id is not None:
            params.append(snapshot_id)
            clauses.append(f"s.id = ${len(params)}")
        if commit_sha is not None:
            params.append(commit_sha)
            clauses.append(f"c.commit_sha = ${len(params)}")
        where_clause = " AND ".join(clauses)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""SELECT s.id AS snapshot_id, s.started_at, s.completed_at, s.status, s.metadata,
                          r.id AS repo_id, r.name, r.root_path,
                          c.commit_sha, c.branch, c.dirty
                   FROM ingest_snapshots s
                   JOIN repos r ON r.id = s.repo_id
                   JOIN repo_commits c ON c.id = s.commit_id
                   WHERE {where_clause}
                   ORDER BY s.started_at DESC
                   LIMIT 1""",
                *params,
            )
        return dict(row) if row else None

    async def promote_snapshot(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        status: str = "attested",
        release_label: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_status = status.strip().lower()
        if normalized_status not in _VALID_SNAPSHOT_PROMOTION_STATUSES:
            raise ValueError(f"invalid snapshot promotion status: {status}")
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        promotion_id = stable_id("snapshot_promotion", snapshot["snapshot_id"], normalized_status)
        now = time.time()
        payload_metadata = metadata or {}
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO snapshot_promotions (id, snapshot_id, repo_id, status, release_label, created_at, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT (snapshot_id, status)
                   DO UPDATE SET release_label = EXCLUDED.release_label,
                                 created_at = EXCLUDED.created_at,
                                 metadata = EXCLUDED.metadata""",
                promotion_id,
                snapshot["snapshot_id"],
                snapshot["repo_id"],
                normalized_status,
                release_label,
                now,
                json.dumps(payload_metadata),
            )
            promotion = await self._snapshot_promotion(conn, snapshot["snapshot_id"], status=normalized_status)
        return {
            "tool": "promote_snapshot",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "promotion": promotion,
        }

    async def latest_promoted_snapshot(
        self,
        repo_root: str,
        *,
        status: str = "attested",
        exclude_snapshot_id: str | None = None,
    ) -> Optional[dict[str, Any]]:
        normalized_status = status.strip().lower()
        if normalized_status not in _VALID_SNAPSHOT_PROMOTION_STATUSES:
            raise ValueError(f"invalid snapshot promotion status: {status}")
        async with self._pool.acquire() as conn:
            return await self._latest_snapshot_promotion(
                conn,
                repo_root,
                status=normalized_status,
                exclude_snapshot_id=exclude_snapshot_id,
            )

    async def repo_context(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        snapshot_id = snapshot["snapshot_id"]
        async with self._pool.acquire() as conn:
            file_count = await conn.fetchval("SELECT count(*) FROM source_files WHERE snapshot_id = $1", snapshot_id)
            component_rows = await conn.fetch(
                "SELECT kind, count(*) AS count FROM components WHERE snapshot_id = $1 GROUP BY kind ORDER BY kind",
                snapshot_id,
            )
            issue_rows = await conn.fetch(
                "SELECT severity, count(*) AS count FROM ingest_issues WHERE snapshot_id = $1 GROUP BY severity ORDER BY severity",
                snapshot_id,
            )
            property_count = await conn.fetchval("SELECT count(*) FROM verified_properties WHERE snapshot_id = $1", snapshot_id)
            runtime_artifact_count = await conn.fetchval("SELECT count(*) FROM runtime_artifacts WHERE snapshot_id = $1", snapshot_id)
            execution_artifact_count = await conn.fetchval("SELECT count(*) FROM execution_artifacts WHERE snapshot_id = $1", snapshot_id)
            policy_profile_count = await conn.fetchval("SELECT count(*) FROM policy_profiles WHERE snapshot_id = $1", snapshot_id)
            workflow_profile_count = await conn.fetchval("SELECT count(*) FROM workflow_profiles WHERE snapshot_id = $1", snapshot_id)
            promotion = await self._snapshot_promotion(conn, snapshot_id)
        return {
            "tool": "repo_context",
            "repo": {
                "name": snapshot["name"],
                "root_path": snapshot["root_path"],
                "branch": snapshot["branch"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "snapshot": {
                "id": snapshot_id,
                "status": snapshot["status"],
                "started_at": snapshot["started_at"],
                "completed_at": snapshot["completed_at"],
                "metadata": _decode_json_value(snapshot["metadata"]),
                "promotion": promotion,
            },
            "counts": {
                "files": file_count,
                "verified_properties": property_count,
                "runtime_artifacts": runtime_artifact_count,
                "execution_artifacts": execution_artifact_count,
                "policy_profiles": policy_profile_count,
                "workflow_profiles": workflow_profile_count,
                "components_by_kind": {row["kind"]: row["count"] for row in component_rows},
                "issues_by_severity": {row["severity"]: row["count"] for row in issue_rows},
            },
        }

    async def _runtime_evidence_for_properties(self, conn, snapshot_id: str, property_refs: list[str]) -> list[dict[str, Any]]:
        if not property_refs:
            return []
        evidence_edges = await conn.fetch(
            """SELECT edge_type, source_ref, source_kind, target_ref, provenance_kind, confidence, metadata
               FROM graph_edges
               WHERE snapshot_id = $1
                 AND target_ref = ANY($2::text[])
                 AND source_kind = ANY($3::text[])
               ORDER BY source_kind, source_ref, target_ref""",
            snapshot_id,
            property_refs,
            ["execution_artifact", "runtime_artifact"],
        )
        execution_keys = sorted({row["source_ref"] for row in evidence_edges if row["source_kind"] == "execution_artifact"})
        runtime_keys = sorted({row["source_ref"] for row in evidence_edges if row["source_kind"] == "runtime_artifact"})

        execution_rows = {}
        runtime_rows = {}
        if execution_keys:
            rows = await conn.fetch(
                "SELECT artifact_key, execution_id, artifact_type, metadata FROM execution_artifacts WHERE snapshot_id = $1 AND artifact_key = ANY($2::text[])",
                snapshot_id,
                execution_keys,
            )
            execution_rows = {row["artifact_key"]: dict(row) for row in rows}
        if runtime_keys:
            rows = await conn.fetch(
                "SELECT artifact_key, artifact_type, metadata FROM runtime_artifacts WHERE snapshot_id = $1 AND artifact_key = ANY($2::text[])",
                snapshot_id,
                runtime_keys,
            )
            runtime_rows = {row["artifact_key"]: dict(row) for row in rows}

        evidence = []
        for row in evidence_edges:
            edge = dict(row)
            source_ref = edge["source_ref"]
            if row["source_kind"] == "execution_artifact":
                artifact = execution_rows.get(source_ref, {})
            else:
                artifact = runtime_rows.get(source_ref, {})
            evidence.append(
                {
                    "edge_type": edge["edge_type"],
                    "source_ref": source_ref,
                    "source_kind": edge["source_kind"],
                    "target_ref": edge["target_ref"],
                    "provenance_kind": edge["provenance_kind"],
                    "confidence": edge["confidence"],
                    "artifact": {
                        key: (json.loads(value) if key == "metadata" and isinstance(value, str) else value)
                        for key, value in artifact.items()
                    },
                }
            )
        return evidence

    async def component_context(
        self,
        repo_root: str,
        component_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        snapshot_id = snapshot["snapshot_id"]
        async with self._pool.acquire() as conn:
            component = await conn.fetchrow(
                """SELECT * FROM components
                   WHERE snapshot_id = $1
                     AND (name = $2 OR display_name = $2 OR source_path = $2)
                   ORDER BY kind
                   LIMIT 1""",
                snapshot_id,
                component_name,
            )
            if component is None:
                component = await conn.fetchrow(
                    """SELECT * FROM components
                       WHERE snapshot_id = $1 AND (name ILIKE $2 OR display_name ILIKE $2 OR source_path ILIKE $2)
                       ORDER BY kind
                       LIMIT 1""",
                    snapshot_id,
                    f"%{component_name}%",
                )
            if component is None:
                raise LookupError(f"component not found: {component_name}")
            declarations = await conn.fetch(
                "SELECT qualified_name, kind, source_path, line_start, line_end, metadata FROM declarations WHERE snapshot_id = $1 AND component_id = $2 ORDER BY qualified_name",
                snapshot_id,
                component["id"],
            )
            outgoing = await conn.fetch(
                "SELECT edge_type, target_ref, target_kind, provenance_kind, confidence, metadata FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 ORDER BY edge_type, target_ref",
                snapshot_id,
                component["name"],
            )
            incoming = await conn.fetch(
                "SELECT edge_type, source_ref, source_kind, provenance_kind, confidence, metadata FROM graph_edges WHERE snapshot_id = $1 AND target_ref = $2 ORDER BY edge_type, source_ref",
                snapshot_id,
                component["name"],
            )
            property_rows = await conn.fetch(
                "SELECT target_ref FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type IN ('IMPLEMENTS_PROPERTY', 'PROVES') ORDER BY target_ref",
                snapshot_id,
                component["name"],
            )
            runtime_evidence = await self._runtime_evidence_for_properties(
                conn,
                snapshot_id,
                [row["target_ref"] for row in property_rows],
            )
        return {
            "tool": "component_context",
            "component": {
                "name": component["name"],
                "display_name": component["display_name"],
                "kind": component["kind"],
                "language": component["language"],
                "source_path": component["source_path"],
                "metadata": _decode_json_value(component["metadata"]),
            },
            "declarations": [_decode_row(row) for row in declarations],
            "outgoing_edges": [_decode_row(row) for row in outgoing],
            "incoming_edges": [_decode_row(row) for row in incoming],
            "runtime_evidence": runtime_evidence,
        }

    async def bridge_alignment(
        self,
        repo_root: str,
        bridge_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        component_ctx = await self.component_context(repo_root, bridge_name, snapshot_id=snapshot_id, commit_sha=commit_sha)
        component_name = component_ctx["component"]["name"]
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        snapshot_id = snapshot["snapshot_id"]
        async with self._pool.acquire() as conn:
            mirror_rows = await conn.fetch(
                "SELECT target_ref, metadata FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'MIRRORS_MODEL' ORDER BY target_ref",
                snapshot_id,
                component_name,
            )
            property_rows = await conn.fetch(
                "SELECT target_ref, metadata FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'IMPLEMENTS_PROPERTY' ORDER BY target_ref",
                snapshot_id,
                component_name,
            )
            test_rows = await conn.fetch(
                "SELECT target_ref, metadata FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'TESTS' ORDER BY target_ref",
                snapshot_id,
                component_name,
            )
            runtime_evidence = await self._runtime_evidence_for_properties(
                conn,
                snapshot_id,
                [row["target_ref"] for row in property_rows],
            )
        return {
            "tool": "bridge_alignment",
            "bridge": component_ctx["component"],
            "mirrors": [_decode_row(row) for row in mirror_rows],
            "properties": [_decode_row(row) for row in property_rows],
            "tests": [_decode_row(row) for row in test_rows],
            "runtime_evidence": runtime_evidence,
        }

    async def workflow_lineage(
        self,
        repo_root: str,
        workflow_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        snapshot_id = snapshot["snapshot_id"]
        async with self._pool.acquire() as conn:
            workflow = await conn.fetchrow(
                """SELECT profile_key, name, metadata FROM workflow_profiles
                   WHERE snapshot_id = $1 AND (profile_key = $2 OR profile_key = $3 OR name = $2)
                   ORDER BY COALESCE((metadata->>'created_at')::double precision, 0) DESC, profile_key DESC
                   LIMIT 1""",
                snapshot_id,
                workflow_name,
                f"workflow:{workflow_name}",
            )
            if workflow is None:
                workflow = await conn.fetchrow(
                    """SELECT profile_key, name, metadata FROM workflow_profiles
                       WHERE snapshot_id = $1 AND profile_key LIKE 'workflow:%' AND name ILIKE $2
                       ORDER BY COALESCE((metadata->>'created_at')::double precision, 0) DESC, profile_key DESC
                       LIMIT 1""",
                    snapshot_id,
                    f"%{workflow_name}%",
                )
            if workflow is None:
                raise LookupError(f"workflow not found: {workflow_name}")

            stage_rows = await conn.fetch(
                """SELECT wp.profile_key, wp.name, wp.metadata
                   FROM graph_edges ge
                   JOIN workflow_profiles wp
                     ON wp.snapshot_id = ge.snapshot_id
                    AND wp.profile_key = ge.target_ref
                   WHERE ge.snapshot_id = $1
                     AND ge.edge_type = 'CONTAINS_STAGE'
                     AND ge.source_ref = $2
                   ORDER BY wp.name""",
                snapshot_id,
                workflow["profile_key"],
            )

            stages: list[dict[str, Any]] = []
            for stage in stage_rows:
                execution_edges = await conn.fetch(
                    "SELECT target_ref FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'EXECUTES' ORDER BY target_ref",
                    snapshot_id,
                    stage["profile_key"],
                )
                dependency_edges = await conn.fetch(
                    "SELECT target_ref FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'DEPENDS_ON_STAGE' ORDER BY target_ref",
                    snapshot_id,
                    stage["profile_key"],
                )
                policy_edges = await conn.fetch(
                    "SELECT target_ref FROM graph_edges WHERE snapshot_id = $1 AND source_ref = $2 AND edge_type = 'USES_POLICY' ORDER BY target_ref",
                    snapshot_id,
                    stage["profile_key"],
                )
                execution_refs = [row["target_ref"] for row in execution_edges]
                execution_rows = []
                if execution_refs:
                    rows = await conn.fetch(
                        "SELECT artifact_key, execution_id, artifact_type, metadata FROM execution_artifacts WHERE snapshot_id = $1 AND artifact_key = ANY($2::text[]) ORDER BY artifact_key",
                        snapshot_id,
                        execution_refs,
                    )
                    execution_rows = [
                        {
                            "artifact_key": row["artifact_key"],
                            "execution_id": row["execution_id"],
                            "artifact_type": row["artifact_type"],
                            "metadata": json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"],
                        }
                        for row in rows
                    ]

                stages.append(
                    {
                        "profile_key": stage["profile_key"],
                        "name": stage["name"],
                        "metadata": _decode_json_value(stage["metadata"]),
                        "depends_on_stage_refs": [row["target_ref"] for row in dependency_edges],
                        "policy_refs": [row["target_ref"] for row in policy_edges],
                        "executions": execution_rows,
                    }
                )

        return {
            "tool": "workflow_lineage",
            "workflow": {
                "profile_key": workflow["profile_key"],
                "name": workflow["name"],
                "metadata": _decode_json_value(workflow["metadata"]),
            },
            "stages": stages,
        }

    async def proof_coverage(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        component_name: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        params: list[Any] = [snapshot["snapshot_id"]]
        where = ["snapshot_id = $1"]
        if component_name:
            params.append(component_name)
            where.append(f"(component_name = ${len(params)} OR display_name = ${len(params)} OR component_source_path = ${len(params)})")
        query = f"""SELECT * FROM verification_proof_coverage
                    WHERE {' AND '.join(where)}
                    ORDER BY component_name, property_key NULLS FIRST"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        return {
            "tool": "proof_coverage",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "rows": [_decode_row(row) for row in rows],
        }

    async def stale_verification(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM verification_stale_verification WHERE snapshot_id = $1 ORDER BY severity DESC, component_name, property_key NULLS FIRST",
                snapshot["snapshot_id"],
            )
        decoded = [_decode_row(row) for row in rows]
        return {
            "tool": "stale_verification",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "rows": decoded,
            "counts": {
                "error": sum(1 for row in decoded if row["severity"] == "error"),
                "warning": sum(1 for row in decoded if row["severity"] == "warning"),
            },
        }

    async def runtime_evidence_freshness(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        property_key: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        params: list[Any] = [snapshot["snapshot_id"]]
        where = ["snapshot_id = $1"]
        if property_key:
            params.append(property_key)
            where.append(f"(property_key = ${len(params)} OR property_name = ${len(params)})")
        query = f"""SELECT * FROM verification_runtime_evidence_freshness
                    WHERE {' AND '.join(where)}
                    ORDER BY property_key, evidence_rank, evidence_ref"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        decoded = [_decode_row(row) for row in rows]
        return {
            "tool": "runtime_evidence_freshness",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "rows": decoded,
            "counts": {
                "fresh": sum(1 for row in decoded if row["freshness_state"] == "fresh"),
                "timestamp_only": sum(1 for row in decoded if row["freshness_state"] == "timestamp_only"),
                "stale": sum(1 for row in decoded if not row["is_fresh"]),
            },
        }

    async def ingest_health(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM verification_ingest_health WHERE snapshot_id = $1 ORDER BY health_state, severity DESC, component_name NULLS FIRST, code",
                snapshot["snapshot_id"],
            )
        decoded = [_decode_row(row) for row in rows]
        return {
            "tool": "ingest_health",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "rows": decoded,
            "counts": {
                "blocking": sum(1 for row in decoded if row["health_state"] == "blocking"),
                "warning": sum(1 for row in decoded if row["health_state"] == "warning"),
                "stale": sum(1 for row in decoded if row["health_state"] == "stale"),
                "unresolved_alignment": sum(1 for row in decoded if row["health_state"] == "unresolved_alignment"),
            },
        }

    async def release_attestation_readiness(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM verification_release_attestation_readiness WHERE snapshot_id = $1",
                snapshot["snapshot_id"],
            )
            promotion = await self._snapshot_promotion(conn, snapshot["snapshot_id"])
            latest_attested = await self._latest_snapshot_promotion(
                conn,
                repo_root,
                status="attested",
                exclude_snapshot_id=snapshot["snapshot_id"],
            )
        if row is None:
            raise LookupError(f"release readiness not available for snapshot {snapshot['snapshot_id']}")
        readiness = _decode_row(row)
        reasons: list[str] = []
        if readiness["dirty"]:
            reasons.append("snapshot_commit_is_dirty")
        if readiness["blocking_issue_count"] > 0:
            reasons.append("blocking_ingest_issues_present")
        if readiness["uncovered_runtime_critical_count"] > 0:
            reasons.append("runtime_critical_components_missing_property_coverage")
        if readiness["stale_error_count"] > 0:
            reasons.append("stale_verification_errors_present")
        if readiness.get("stale_runtime_evidence_count", 0) > 0:
            reasons.append("stale_runtime_evidence_present")
        if readiness["execution_artifact_count"] == 0:
            reasons.append("no_execution_evidence_bound_to_snapshot")
        return {
            "tool": "release_attestation_readiness",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "readiness": readiness,
            "promotion": promotion,
            "latest_attested_baseline": latest_attested,
            "blocking_reasons": reasons,
        }

    async def snapshot_compare(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        baseline_snapshot_id: str | None = None,
        baseline_commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        async with self._pool.acquire() as conn:
            if baseline_snapshot_id is not None or baseline_commit_sha is not None:
                baseline = await self.resolve_snapshot(repo_root, snapshot_id=baseline_snapshot_id, commit_sha=baseline_commit_sha)
            else:
                baseline = await self._latest_snapshot_promotion(
                    conn,
                    repo_root,
                    status="attested",
                    exclude_snapshot_id=snapshot["snapshot_id"],
                )
            if baseline is None:
                raise LookupError(f"no attested baseline snapshot available for {repo_root}")

            current_readiness_row = await conn.fetchrow(
                "SELECT * FROM verification_release_attestation_readiness WHERE snapshot_id = $1",
                snapshot["snapshot_id"],
            )
            baseline_readiness_row = await conn.fetchrow(
                "SELECT * FROM verification_release_attestation_readiness WHERE snapshot_id = $1",
                baseline["snapshot_id"],
            )
            current_promotion = await self._snapshot_promotion(conn, snapshot["snapshot_id"])
            baseline_promotion = await self._snapshot_promotion(conn, baseline["snapshot_id"])

            inventory = {
                "components": ("components", "name"),
                "verified_properties": ("verified_properties", "property_key"),
                "runtime_artifacts": ("runtime_artifacts", "artifact_key"),
                "execution_artifacts": ("execution_artifacts", "artifact_key"),
                "workflow_profiles": ("workflow_profiles", "profile_key"),
            }
            inventory_changes: dict[str, Any] = {}
            for label, (table_name, key_column) in inventory.items():
                current_values = set(
                    await conn.fetchval(
                        f"SELECT array_agg({key_column} ORDER BY {key_column}) FROM {table_name} WHERE snapshot_id = $1",
                        snapshot["snapshot_id"],
                    )
                    or []
                )
                baseline_values = set(
                    await conn.fetchval(
                        f"SELECT array_agg({key_column} ORDER BY {key_column}) FROM {table_name} WHERE snapshot_id = $1",
                        baseline["snapshot_id"],
                    )
                    or []
                )
                added = sorted(current_values - baseline_values)
                removed = sorted(baseline_values - current_values)
                inventory_changes[label] = {
                    "current_count": len(current_values),
                    "baseline_count": len(baseline_values),
                    "delta": len(current_values) - len(baseline_values),
                    "added": added[:25],
                    "removed": removed[:25],
                }

            stale_rows = {
                "current": [
                    _decode_row(row)
                    for row in await conn.fetch(
                        "SELECT * FROM verification_stale_verification WHERE snapshot_id = $1 ORDER BY severity DESC, component_name, property_key NULLS FIRST",
                        snapshot["snapshot_id"],
                    )
                ],
                "baseline": [
                    _decode_row(row)
                    for row in await conn.fetch(
                        "SELECT * FROM verification_stale_verification WHERE snapshot_id = $1 ORDER BY severity DESC, component_name, property_key NULLS FIRST",
                        baseline["snapshot_id"],
                    )
                ],
            }

        current_readiness = _decode_row(current_readiness_row) if current_readiness_row else {}
        baseline_readiness = _decode_row(baseline_readiness_row) if baseline_readiness_row else {}
        current_stale = {
            (row["component_name"], row.get("property_key"), row["stale_reason"], row["severity"])
            for row in stale_rows["current"]
        }
        baseline_stale = {
            (row["component_name"], row.get("property_key"), row["stale_reason"], row["severity"])
            for row in stale_rows["baseline"]
        }
        stale_added = sorted(current_stale - baseline_stale)
        stale_removed = sorted(baseline_stale - current_stale)

        return {
            "tool": "snapshot_compare",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
                "promotion": current_promotion,
            },
            "baseline": {
                "id": baseline["snapshot_id"],
                "commit_sha": baseline["commit_sha"],
                "dirty": baseline["dirty"],
                "promotion": baseline_promotion,
            },
            "readiness": {
                "current": current_readiness,
                "baseline": baseline_readiness,
                "delta": {
                    key: current_readiness.get(key, 0) - baseline_readiness.get(key, 0)
                    for key in (
                        "runtime_artifact_count",
                        "execution_artifact_count",
                        "workflow_count",
                        "blocking_issue_count",
                        "warning_issue_count",
                        "stale_error_count",
                        "stale_warning_count",
                        "uncovered_runtime_critical_count",
                        "missing_runtime_evidence_count",
                        "stale_runtime_evidence_count",
                        "health_blocking_count",
                        "health_warning_count",
                        "health_stale_count",
                        "health_unresolved_alignment_count",
                    )
                },
            },
            "inventory_changes": inventory_changes,
            "stale_verification_changes": {
                "added": [
                    {
                        "component_name": component_name,
                        "property_key": property_key,
                        "stale_reason": stale_reason,
                        "severity": severity,
                    }
                    for component_name, property_key, stale_reason, severity in stale_added[:25]
                ],
                "removed": [
                    {
                        "component_name": component_name,
                        "property_key": property_key,
                        "stale_reason": stale_reason,
                        "severity": severity,
                    }
                    for component_name, property_key, stale_reason, severity in stale_removed[:25]
                ],
            },
        }

    async def proof_runtime_trace(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        property_key: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        params: list[Any] = [snapshot["snapshot_id"]]
        where = ["snapshot_id = $1"]
        if property_key:
            params.append(property_key)
            where.append(f"(property_key = ${len(params)} OR property_name = ${len(params)})")
        query = f"""SELECT * FROM verification_proof_runtime_trace
                    WHERE {' AND '.join(where)}
                    ORDER BY property_key, execution_id NULLS LAST, evidence_ref"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        return {
            "tool": "proof_runtime_trace",
            "snapshot": {
                "id": snapshot["snapshot_id"],
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "rows": [_decode_row(row) for row in rows],
        }

    async def proof_impact(
        self,
        repo_root: str,
        subject: str,
        *,
        subject_kind: str = "auto",
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        snapshot = await self.resolve_snapshot(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        if snapshot is None:
            raise LookupError(f"no verification graph snapshot for {repo_root}")
        snapshot_key = snapshot["snapshot_id"]
        async with self._pool.acquire() as conn:
            matched_components: list[dict[str, Any]] = []
            matched_properties: list[dict[str, Any]] = []
            matched_files: list[dict[str, Any]] = []

            if subject_kind in ("auto", "component", "bridge"):
                kind_filters: list[str] = []
                if subject_kind == "bridge":
                    kind_filters.append("kind LIKE '%%bridge'")
                kind_clause = ""
                if kind_filters:
                    kind_clause = f" AND {' AND '.join(kind_filters)}"
                component_rows = await conn.fetch(
                    f"""SELECT name, display_name, kind, language, source_path, metadata
                       FROM components
                       WHERE snapshot_id = $1
                         AND (name = $2 OR display_name = $2 OR source_path = $2
                              OR name ILIKE $3 OR display_name ILIKE $3 OR source_path ILIKE $3)
                         {kind_clause}
                       ORDER BY kind, name""",
                    snapshot_key,
                    subject,
                    f"%{subject}%",
                )
                matched_components = [_decode_row(row) for row in component_rows]

            if subject_kind in ("auto", "property") and (subject_kind != "auto" or not matched_components):
                property_rows = await conn.fetch(
                    """SELECT property_key, name, proof_system, source_path, metadata
                       FROM verified_properties
                       WHERE snapshot_id = $1
                         AND (property_key = $2 OR name = $2 OR property_key ILIKE $3 OR name ILIKE $3)
                       ORDER BY property_key""",
                    snapshot_key,
                    subject,
                    f"%{subject}%",
                )
                matched_properties = [_decode_row(row) for row in property_rows]

            if subject_kind in ("auto", "file") and not matched_components and not matched_properties:
                file_rows = await conn.fetch(
                    """SELECT path, sha256, language, size_bytes, metadata
                       FROM source_files
                       WHERE snapshot_id = $1
                         AND (path = $2 OR path ILIKE $3)
                       ORDER BY path""",
                    snapshot_key,
                    subject,
                    f"%{subject}%",
                )
                matched_files = [_decode_row(row) for row in file_rows]
                if matched_files:
                    component_rows = await conn.fetch(
                        """SELECT name, display_name, kind, language, source_path, metadata
                           FROM components
                           WHERE snapshot_id = $1
                             AND source_path = ANY($2::text[])
                           ORDER BY kind, name""",
                        snapshot_key,
                        [row["path"] for row in matched_files],
                    )
                    matched_components = [_decode_row(row) for row in component_rows]

            component_names = sorted({row["name"] for row in matched_components})
            property_keys = {row["property_key"] for row in matched_properties}
            if component_names:
                property_rows = await conn.fetch(
                    """SELECT DISTINCT vp.property_key, vp.name, vp.proof_system, vp.source_path, vp.metadata
                       FROM graph_edges ge
                       JOIN verified_properties vp
                         ON vp.snapshot_id = ge.snapshot_id
                        AND vp.property_key = ge.target_ref
                       WHERE ge.snapshot_id = $1
                         AND ge.source_ref = ANY($2::text[])
                         AND ge.edge_type IN ('IMPLEMENTS_PROPERTY', 'PROVES')
                       ORDER BY vp.property_key""",
                    snapshot_key,
                    component_names,
                )
                for row in property_rows:
                    property_keys.add(row["property_key"])
                    if row["property_key"] not in {item["property_key"] for item in matched_properties}:
                        matched_properties.append(_decode_row(row))

            property_key_list = sorted(property_keys)
            runtime_rows: list[dict[str, Any]] = []
            freshness_rows: list[dict[str, Any]] = []
            if property_key_list:
                runtime_rows = [
                    _decode_row(row)
                    for row in await conn.fetch(
                        "SELECT * FROM verification_proof_runtime_trace WHERE snapshot_id = $1 AND property_key = ANY($2::text[]) ORDER BY property_key, execution_id NULLS LAST, evidence_ref",
                        snapshot_key,
                        property_key_list,
                    )
                ]
                freshness_rows = [
                    _decode_row(row)
                    for row in await conn.fetch(
                        "SELECT * FROM verification_runtime_evidence_freshness WHERE snapshot_id = $1 AND property_key = ANY($2::text[]) ORDER BY property_key, evidence_rank, evidence_ref",
                        snapshot_key,
                        property_key_list,
                    )
                ]

            stale_filters: list[str] = []
            stale_params: list[Any] = [snapshot_key]
            if component_names:
                stale_params.append(component_names)
                stale_filters.append(f"component_name = ANY(${len(stale_params)}::text[])")
            if property_key_list:
                stale_params.append(property_key_list)
                stale_filters.append(f"property_key = ANY(${len(stale_params)}::text[])")
            stale_query = "SELECT * FROM verification_stale_verification WHERE snapshot_id = $1"
            if stale_filters:
                stale_query += f" AND ({' OR '.join(stale_filters)})"
            stale_query += " ORDER BY severity DESC, component_name, property_key NULLS FIRST"
            stale_rows = [_decode_row(row) for row in await conn.fetch(stale_query, *stale_params)]

            test_rows: list[dict[str, Any]] = []
            if component_names:
                test_rows = [
                    _decode_row(row)
                    for row in await conn.fetch(
                        "SELECT source_ref AS component_name, target_ref AS test_ref, metadata FROM graph_edges WHERE snapshot_id = $1 AND edge_type = 'TESTS' AND source_ref = ANY($2::text[]) ORDER BY source_ref, target_ref",
                        snapshot_key,
                        component_names,
                    )
                ]

            readiness_row = await conn.fetchrow(
                "SELECT * FROM verification_release_attestation_readiness WHERE snapshot_id = $1",
                snapshot_key,
            )
            readiness = _decode_row(readiness_row) if readiness_row else {}

            ingest_health_rows = [
                _decode_row(row)
                for row in await conn.fetch(
                    "SELECT * FROM verification_ingest_health WHERE snapshot_id = $1 ORDER BY health_state, severity DESC, component_name NULLS FIRST, code",
                    snapshot_key,
                )
            ]

        policy_refs = sorted({row["policy_ref"] for row in runtime_rows if row.get("policy_ref")})
        workflow_refs = sorted({row["workflow_ref"] for row in runtime_rows if row.get("workflow_ref")})
        risk_flags: list[str] = []
        if not matched_properties:
            risk_flags.append("no_verified_properties_resolved")
        if matched_properties and not runtime_rows:
            risk_flags.append("no_runtime_evidence_bound")
        if any(row["severity"] == "error" for row in stale_rows):
            risk_flags.append("stale_verification_errors_present")
        if any(row["stale_reason"] == "missing_runtime_evidence" for row in stale_rows):
            risk_flags.append("runtime_evidence_gap_present")
        if any(row["stale_reason"] == "stale_runtime_evidence" for row in stale_rows):
            risk_flags.append("stale_runtime_evidence_present")
        if any(row["health_state"] == "blocking" for row in ingest_health_rows):
            risk_flags.append("blocking_ingest_health_present")
        if readiness and not readiness.get("ready_for_attestation", False):
            risk_flags.append("snapshot_not_ready_for_attestation")

        return {
            "tool": "proof_impact",
            "snapshot": {
                "id": snapshot_key,
                "commit_sha": snapshot["commit_sha"],
                "dirty": snapshot["dirty"],
            },
            "subject": {
                "input": subject,
                "subject_kind": subject_kind,
                "matched_files": matched_files,
                "matched_components": matched_components,
                "matched_properties": matched_properties,
            },
            "impacts": {
                "runtime_traces": runtime_rows,
                "runtime_evidence_freshness": freshness_rows,
                "tests": test_rows,
                "policy_refs": policy_refs,
                "workflow_refs": workflow_refs,
                "ingest_health": ingest_health_rows,
                "stale_verification": stale_rows,
                "release_attestation_readiness": readiness,
            },
            "risk_flags": risk_flags,
        }