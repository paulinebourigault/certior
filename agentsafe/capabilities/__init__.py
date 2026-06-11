"""Capability-based security."""
from .tokens import CapabilityToken, BudgetExhaustedError, BudgetReservation
from .capability_attenuation_verified import (
    CapabilityManager,
    VerifiedCapabilityToken,
    AttenuateResult,
    SpendResult,
    CapabilityAuditEntry,
    has_permission,
    has_all_permissions,
    permissions_subset,
    attenuate,
    spend_budget,
)

__all__ = [
    # Original (unverified) tokens
    "CapabilityToken", "BudgetExhaustedError", "BudgetReservation",
    # B1: Dafny-verified capability attenuation
    "CapabilityManager", "VerifiedCapabilityToken",
    "AttenuateResult", "SpendResult", "CapabilityAuditEntry",
    "has_permission", "has_all_permissions", "permissions_subset",
    "attenuate", "spend_budget",
]
