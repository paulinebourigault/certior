"""
Permission Resolver - enforce compliance policy ceilings on API permissions.

Closes BYPASS #1: API callers can no longer supply arbitrary permissions
that override compliance policy constraints.

Resolution semantics
────────────────────
1. Every ComplianceConfig defines two permission boundaries:
   • ``permissions``           - the default/recommended permission set
   • ``max_permissions``       - the absolute ceiling (superset of defaults)
   • ``forbidden_permissions`` - hard deny-list (always stripped)

2. When the API receives user-supplied permissions:
   a. Each requested permission is checked against the ceiling
      (``max_permissions``).  Only permissions *covered* by the ceiling
      are kept.
   b. Forbidden permissions are unconditionally removed.
   c. Role-based restrictions further narrow the effective set.

3. Resolution produces an auditable ``PermissionResolution`` that records
   exactly what was granted, what was denied, and why.

Role semantics
──────────────
• ADMIN     - may request any permission up to the policy ceiling.
• OPERATOR  - restricted to the policy's default permission set.
• VIEWER    - cannot create tasks (rejected before resolution).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)


# ─── Denial reasons ────────────────────────────────────────────────────────

class DenialReason(str, Enum):
    """Machine-readable reason a permission was denied."""
    FORBIDDEN_BY_POLICY = "forbidden_by_policy"
    EXCEEDS_POLICY_CEILING = "exceeds_policy_ceiling"
    EXCEEDS_ROLE_ALLOWANCE = "exceeds_role_allowance"
    WILDCARD_DENIED_UNDER_COMPLIANCE = "wildcard_denied_under_compliance"


@dataclass(frozen=True)
class PermissionDenial:
    """One denied permission with an explanation."""
    permission: str
    reason: DenialReason
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "permission": self.permission,
            "reason": self.reason.value,
            "detail": self.detail,
        }


# ─── Resolution result ────────────────────────────────────────────────────

@dataclass(frozen=True)
class PermissionResolution:
    """
    Complete, auditable result of permission resolution.

    Attributes
    ----------
    effective_permissions : list[str]
        The permissions that will actually be granted on the token.
    denied : list[PermissionDenial]
        Permissions that were requested but denied, with reasons.
    warnings : list[str]
        Non-fatal advisory messages (e.g. "permissions narrowed by policy").
    policy_name : str
        Name of the compliance policy applied.
    user_role : str
        Role of the requesting user.
    requested_permissions : list[str] | None
        What the user originally asked for (None = used defaults).
    used_defaults : bool
        True if no user permissions were supplied (policy defaults used).
    """
    effective_permissions: List[str]
    denied: List[PermissionDenial] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    policy_name: str = ""
    user_role: str = ""
    requested_permissions: Optional[List[str]] = None
    used_defaults: bool = False

    @property
    def has_denials(self) -> bool:
        return len(self.denied) > 0

    @property
    def is_empty(self) -> bool:
        return len(self.effective_permissions) == 0

    def to_dict(self) -> Dict:
        return {
            "effective_permissions": self.effective_permissions,
            "denied": [d.to_dict() for d in self.denied],
            "warnings": self.warnings,
            "policy_name": self.policy_name,
            "user_role": self.user_role,
            "requested_permissions": self.requested_permissions,
            "used_defaults": self.used_defaults,
        }


# ─── Resolver ──────────────────────────────────────────────────────────────

class PermissionResolver:
    """
    Resolves API-supplied permissions against a compliance policy.

    This is the single enforcement point that prevents BYPASS #1.
    All permission construction in the API layer MUST go through this
    resolver.

    Thread-safety: resolver is stateless - safe to share across requests.
    """

    # Roles that may NOT create tasks at all
    _BLOCKED_ROLES = frozenset({"viewer"})

    def resolve(
        self,
        *,
        requested_permissions: Optional[List[str]],
        policy: "ComplianceConfig",  # noqa: F821 - forward ref
        user_role: str,
        profile_ceiling: Optional[List[str]] = None,
    ) -> PermissionResolution:
        """
        Resolve effective permissions.

        Parameters
        ----------
        requested_permissions
            Permissions supplied by the API caller.  ``None`` or empty
            means "use the policy defaults".
        policy
            The ``ComplianceConfig`` selected for this task.
        user_role
            The authenticated user's role (``admin``, ``operator``,
            ``viewer``).

        Returns
        -------
        PermissionResolution
            Auditable resolution with effective permissions.

        Raises
        ------
        PermissionError
            If the user's role is not allowed to create tasks.
        """
        role_lower = user_role.lower()

        # ── Gate: blocked roles ─────────────────────────────────
        if role_lower in self._BLOCKED_ROLES:
            raise PermissionError(
                f"Role '{user_role}' is not permitted to create tasks"
            )

        # ── Determine what was requested ────────────────────────
        user_supplied = bool(
            requested_permissions is not None
            and len(requested_permissions) > 0
        )

        if not user_supplied:
            # No user override → use policy defaults directly
            effective, denied, warnings = self._apply_defaults(policy)
            if profile_ceiling and "*" not in profile_ceiling:
                if effective == ["*"]:
                    effective = list(profile_ceiling)
                else:
                    effective = [
                        perm for perm in effective
                        if self._permission_covered_by(perm, profile_ceiling)
                    ]
            return PermissionResolution(
                effective_permissions=effective,
                denied=denied,
                warnings=warnings,
                policy_name=policy.name,
                user_role=role_lower,
                requested_permissions=None,
                used_defaults=True,
            )

        # ── User supplied permissions → resolve against policy ──
        assert requested_permissions is not None  # for type-checker
        effective, denied, warnings = self._resolve_requested(
            requested=requested_permissions,
            policy=policy,
            role=role_lower,
            profile_ceiling=profile_ceiling,
        )

        return PermissionResolution(
            effective_permissions=effective,
            denied=denied,
            warnings=warnings,
            policy_name=policy.name,
            user_role=role_lower,
            requested_permissions=list(requested_permissions),
            used_defaults=False,
        )

    # ── Internal: use policy defaults ────────────────────────────

    def _apply_defaults(
        self,
        policy: "ComplianceConfig",
    ) -> Tuple[List[str], List[PermissionDenial], List[str]]:
        """Return the policy's default permissions (already compliant)."""
        # Policy defaults are trusted - but still strip forbidden just
        # in case someone misconfigured a preset.
        effective = []
        denied: List[PermissionDenial] = []
        for perm in policy.permissions:
            if not policy.permission_allowed(perm):
                denied.append(PermissionDenial(
                    permission=perm,
                    reason=DenialReason.FORBIDDEN_BY_POLICY,
                    detail=(
                        f"Permission '{perm}' is in the policy defaults "
                        f"but also in the forbidden list - stripped as a "
                        f"safety precaution"
                    ),
                ))
            else:
                effective.append(perm)
        return effective, denied, []

    # ── Internal: resolve user-supplied permissions ───────────────

    def _resolve_requested(
        self,
        *,
        requested: List[str],
        policy: "ComplianceConfig",
        role: str,
        profile_ceiling: Optional[List[str]] = None,
    ) -> Tuple[List[str], List[PermissionDenial], List[str]]:
        """Intersect user request with policy ceiling and role limits."""
        effective: List[str] = []
        denied: List[PermissionDenial] = []
        warnings: List[str] = []

        # Determine the ceiling
        ceiling = self._get_ceiling(policy)
        ceiling_is_open = ceiling is None  # None = no ceiling ("*")

        # Role restriction: operators cannot exceed policy defaults
        role_ceiling: Optional[List[str]] = None
        if role == "operator":
            role_ceiling = list(policy.permissions)

        for perm in requested:
            denial = self._check_single_permission(
                perm=perm,
                policy=policy,
                ceiling=ceiling,
                ceiling_is_open=ceiling_is_open,
                role=role,
                role_ceiling=role_ceiling,
                profile_ceiling=profile_ceiling,
            )
            if denial is not None:
                denied.append(denial)
            else:
                effective.append(perm)

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for p in effective:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        effective = deduped

        # Advisory warnings
        if denied:
            warnings.append(
                f"{len(denied)} requested permission(s) denied by "
                f"'{policy.name}' policy"
            )
        if not ceiling_is_open and any("*" in r for r in requested):
            warnings.append(
                "Wildcard permissions are restricted under "
                f"'{policy.name}' compliance policy"
            )

        log.info(
            "Permission resolution: policy=%s role=%s "
            "requested=%d granted=%d denied=%d",
            policy.name, role,
            len(requested), len(effective), len(denied),
        )

        return effective, denied, warnings

    def _check_single_permission(
        self,
        *,
        perm: str,
        policy: "ComplianceConfig",
        ceiling: Optional[List[str]],
        ceiling_is_open: bool,
        role: str,
        role_ceiling: Optional[List[str]],
        profile_ceiling: Optional[List[str]],
    ) -> Optional[PermissionDenial]:
        """
        Check one permission.  Returns a denial or None if allowed.
        """
        # 1) Forbidden list (highest priority - always enforced)
        if not policy.permission_allowed(perm):
            return PermissionDenial(
                permission=perm,
                reason=DenialReason.FORBIDDEN_BY_POLICY,
                detail=(
                    f"Permission '{perm}' is forbidden under "
                    f"'{policy.name}' compliance policy"
                ),
            )

        # 2) Wildcard under restrictive policy
        if perm == "*" and not ceiling_is_open:
            return PermissionDenial(
                permission=perm,
                reason=DenialReason.WILDCARD_DENIED_UNDER_COMPLIANCE,
                detail=(
                    f"Wildcard permission '*' is not allowed under "
                    f"'{policy.name}' compliance policy; request specific "
                    f"permissions from the allowed set"
                ),
            )

        # 3) Policy ceiling check (skip for open ceilings)
        if not ceiling_is_open:
            assert ceiling is not None
            if not self._permission_covered_by(perm, ceiling):
                return PermissionDenial(
                    permission=perm,
                    reason=DenialReason.EXCEEDS_POLICY_CEILING,
                    detail=(
                        f"Permission '{perm}' is not within the "
                        f"'{policy.name}' policy's allowed permission set"
                    ),
                )

        # 4) Role ceiling (operator cannot exceed defaults)
        if role_ceiling is not None:
            if not self._permission_covered_by(perm, role_ceiling):
                return PermissionDenial(
                    permission=perm,
                    reason=DenialReason.EXCEEDS_ROLE_ALLOWANCE,
                    detail=(
                        f"Role 'operator' cannot request permission "
                        f"'{perm}' beyond the policy default set"
                    ),
                )

        # 5) Task/stage-specific profile ceiling
        if profile_ceiling is not None and "*" not in profile_ceiling:
            if not self._permission_covered_by(perm, profile_ceiling):
                return PermissionDenial(
                    permission=perm,
                    reason=DenialReason.EXCEEDS_POLICY_CEILING,
                    detail=(
                        f"Permission '{perm}' exceeds the task verification profile ceiling"
                    ),
                )

        return None  # allowed

    # ── Internal: ceiling determination ──────────────────────────

    @staticmethod
    def _get_ceiling(policy: "ComplianceConfig") -> Optional[List[str]]:
        """
        Determine the permission ceiling for a policy.

        Returns ``None`` if the policy imposes no ceiling (open/"*").
        Otherwise returns the list of maximum allowed permissions.
        """
        # If the policy has an explicit max_permissions field, use it
        max_perms = getattr(policy, "max_permissions", None)
        if max_perms is not None and len(max_perms) > 0:
            # An explicit ["*"] in max_permissions means "no ceiling"
            if max_perms == ["*"]:
                return None
            return max_perms

        # Otherwise derive from the default permission set.
        # A policy whose only permission is "*" imposes no ceiling.
        if policy.permissions == ["*"]:
            return None

        return policy.permissions

    # ── Internal: permission matching ────────────────────────────

    @staticmethod
    def _permission_covered_by(perm: str, allowed: Sequence[str]) -> bool:
        """
        Check if ``perm`` is covered by any entry in ``allowed``.

        Supports wildcard matching:
        • ``"database:*"`` covers ``"database:read"``
        • ``"*"`` covers everything
        """
        for a in allowed:
            if a == perm:
                return True
            if a == "*":
                return True
            if a.endswith("*") and perm.startswith(a[:-1]):
                return True
            # Reverse: if the allowed perm is specific but user requested
            # a wildcard that covers it - NOT allowed (can't widen)
        return False
