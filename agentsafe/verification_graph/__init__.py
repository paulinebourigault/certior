"""Certior verification graph package."""

__all__ = [
    "ingest_repository",
    "main_doctor",
    "main_runtime_evidence",
    "PgVerificationGraphStore",
    "VerificationGraphTools",
]


def __getattr__(name: str):
    if name == "ingest_repository":
        from .ingest import ingest_repository

        return ingest_repository
    if name == "PgVerificationGraphStore":
        from .store import PgVerificationGraphStore

        return PgVerificationGraphStore
    if name == "main_doctor":
        from .ops_cli import main_doctor

        return main_doctor
    if name == "main_runtime_evidence":
        from .ops_cli import main_runtime_evidence

        return main_runtime_evidence
    if name == "VerificationGraphTools":
        from .tools import VerificationGraphTools

        return VerificationGraphTools
    raise AttributeError(name)