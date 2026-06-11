from __future__ import annotations

from .store import PgVerificationGraphStore


class VerificationGraphTools:
    """Thin tool surface for the first proof-aware queries."""

    def __init__(self, dsn: str):
        self._dsn = dsn

    async def repo_context(self, repo_root: str, *, snapshot_id: str | None = None, commit_sha: str | None = None) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.repo_context(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def promote_snapshot(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        status: str = "attested",
        release_label: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.promote_snapshot(
                repo_root,
                snapshot_id=snapshot_id,
                commit_sha=commit_sha,
                status=status,
                release_label=release_label,
                metadata=metadata,
            )
        finally:
            await store.close()

    async def snapshot_compare(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        baseline_snapshot_id: str | None = None,
        baseline_commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.snapshot_compare(
                repo_root,
                snapshot_id=snapshot_id,
                commit_sha=commit_sha,
                baseline_snapshot_id=baseline_snapshot_id,
                baseline_commit_sha=baseline_commit_sha,
            )
        finally:
            await store.close()

    async def component_context(
        self,
        repo_root: str,
        component_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.component_context(repo_root, component_name, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def bridge_alignment(
        self,
        repo_root: str,
        bridge_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.bridge_alignment(repo_root, bridge_name, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def workflow_lineage(
        self,
        repo_root: str,
        workflow_name: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.workflow_lineage(repo_root, workflow_name, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def proof_coverage(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        component_name: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.proof_coverage(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha, component_name=component_name)
        finally:
            await store.close()

    async def stale_verification(self, repo_root: str, *, snapshot_id: str | None = None, commit_sha: str | None = None) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.stale_verification(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def runtime_evidence_freshness(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        property_key: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.runtime_evidence_freshness(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha, property_key=property_key)
        finally:
            await store.close()

    async def ingest_health(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.ingest_health(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def release_attestation_readiness(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.release_attestation_readiness(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha)
        finally:
            await store.close()

    async def proof_runtime_trace(
        self,
        repo_root: str,
        *,
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
        property_key: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.proof_runtime_trace(repo_root, snapshot_id=snapshot_id, commit_sha=commit_sha, property_key=property_key)
        finally:
            await store.close()

    async def proof_impact(
        self,
        repo_root: str,
        subject: str,
        *,
        subject_kind: str = "auto",
        snapshot_id: str | None = None,
        commit_sha: str | None = None,
    ) -> dict:
        store = PgVerificationGraphStore(self._dsn)
        await store.initialize()
        try:
            return await store.proof_impact(
                repo_root,
                subject,
                subject_kind=subject_kind,
                snapshot_id=snapshot_id,
                commit_sha=commit_sha,
            )
        finally:
            await store.close()