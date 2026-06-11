"""
certior.adapters.openclaw - OpenClaw SDK integration.
=====================================================

Verifies OpenClaw agent executions and pipelines with Certior's
capability + content + budget + delegation gates.

This adapter addresses the threats enumerated in *Uncovering Security
Threats and Architecting Defenses in Autonomous Agents: A Case Study
of OpenClaw* (arXiv:2603.12644). See ``docs/openclaw-defenses.md`` for
the per-threat mapping.

Three integration surfaces:

1. ``GuardedAgent`` - **the enforcement primitive.** Wraps an
   ``openclaw_sdk.core.agent.Agent`` so its ``.execute()`` method
   first runs Certior's input gate, blocks on a blocked verdict, then
   runs the wrapped agent, then runs the output gate. This is the
   only surface that *actually blocks* execution.

2. ``CertiorCallbackHandler`` - **observability + accounting, NOT
   enforcement.** Drop into an ``OpenClawClient`` to debit budget,
   emit audit-trail entries, and log gate decisions on every
   ``agent.execute()`` call. The hooks fire correctly, but OpenClaw's
   ``CompositeCallbackHandler`` is documented to swallow handler
   exceptions ("so one failing handler does not block the others"),
   so a blocked verdict raised from here is logged but does not stop
   the call. Use ``GuardedAgent`` for blocking; use this for
   per-call observability and budget accounting in addition.

3. ``GuardedPipeline`` - a proxy class wrapping an OpenClaw
   ``Pipeline``. Each step's allowed capability set is checked
   against the parent guard's permissions at ``add_step`` time,
   addressing the ClawDrain tool-chain exploitation and privilege
   escalation threats. Use together with ``GuardedAgent`` for full
   runtime blocking.

Usage::

    from certior import Guard
    from certior.adapters.openclaw import (
        GuardedAgent, CertiorCallbackHandler, GuardedPipeline,
    )
    from openclaw_sdk import OpenClawClient
    from openclaw_sdk.pipeline import Pipeline

    guard = Guard(
        policy="hipaa",
        permissions=["network:http:read", "filesystem:read"],
        budget_cents=5000,
    )

    async with OpenClawClient.connect(
        callbacks=[CertiorCallbackHandler(guard)],   # accounting + audit
    ) as client:
        # Wrap for actual blocking:
        agent = GuardedAgent(client.get_agent("research-bot"), guard)
        result = await agent.execute("Summarise public AI safety research")

    # Multi-step delegation with per-step capability subsetting:
    pipeline = GuardedPipeline(
        Pipeline(client),
        guard,
        step_capabilities={
            "researcher": ["network:http:read"],
            "writer":     ["filesystem:read"],
        },
    )
    pipeline.add_step("researcher", "research-bot", "find papers")
    pipeline.add_step("writer",     "writer-bot",   "summarise findings")
    output = await pipeline.run()

Requires: ``pip install openclaw-sdk``
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence

from certior.guard import Guard, CertiorBlocked, VerifyResult


# ── OpenClaw availability ────────────────────────────────────────────

def _check_openclaw() -> bool:
    try:
        from openclaw_sdk import CallbackHandler  # noqa: F401
        return True
    except ImportError:
        return False


_HAS_OPENCLAW = _check_openclaw()


# ── Constants ────────────────────────────────────────────────────────

#: Cost charged against the guard's budget for one agent execution
#: or one pipeline step. Kept fixed in 0.5.0; expose as a parameter
#: in 0.5.1 if real users need it.
_COST_PER_CALL = 1


# ── Callback handler ─────────────────────────────────────────────────

if _HAS_OPENCLAW:
    from openclaw_sdk import CallbackHandler  # type: ignore[import-not-found]

    class CertiorCallbackHandler(CallbackHandler):  # type: ignore[misc, valid-type]
        """
        OpenClaw callback for observability, budget accounting, and audit trail.

        **This class is observability + accounting, NOT runtime
        enforcement.** OpenClaw's ``CompositeCallbackHandler`` catches
        any exception raised inside a handler (``handler.py``: *"so one
        failing handler does not block the others"*) and continues
        executing. A blocked verdict raised here is logged but does
        NOT stop the underlying ``agent.execute()``. For actual
        blocking, wrap your agent in ``GuardedAgent`` - the callback
        handler can be used alongside it for the audit trail and
        budget accounting.

        What this handler does that survives the exception-swallowing:

        - Debits ``guard.budget_remaining`` per execution
          (Resource Exhaustion / arXiv #5 - accounting still occurs).
        - Records every verdict on the guard's audit log
          (Tool Result Tampering / arXiv #7 - visibility).
        - Runs the content scanner so PII / MNPI / privileged content
          is detected and (under HIPAA) redacted on the result
          metadata, even though the call is not blocked.

        Args:
            guard: Pre-configured ``Guard`` instance. If omitted, a
                ``Guard(policy=policy)`` is constructed.
            policy: Compliance preset (``"default"``, ``"hipaa"``,
                ``"sox"``, ``"legal_privilege"``). Ignored when ``guard``
                is supplied.
            block_on_violation: If ``True`` (default), still raises
                ``CertiorBlocked`` from the hook. OpenClaw will catch
                and log it; the raise is visible in the framework's
                warning logs which is useful for triage even when it
                cannot stop the call.
        """

        def __init__(
            self,
            guard: Optional[Guard] = None,
            policy: str = "default",
            block_on_violation: bool = True,
        ) -> None:
            super().__init__()
            self.guard = guard or Guard(policy=policy)
            self.block_on_violation = block_on_violation

        async def on_execution_start(
            self,
            agent_id: str,
            prompt: str = "",
            **kwargs: Any,
        ) -> None:
            """Verify the agent's input prompt before execution."""
            verdict = self.guard.verify(
                tool=f"openclaw:{agent_id}",
                content=prompt,
                params=kwargs.get("parameters") or kwargs,
                cost_cents=_COST_PER_CALL,
            )
            if verdict.blocked and self.block_on_violation:
                raise CertiorBlocked(verdict)

        async def on_execution_end(
            self,
            agent_id: str,
            result: Any = None,
            **kwargs: Any,
        ) -> None:
            """Scan the agent's output for sensitive data leakage."""
            content = _extract_content(result)
            if not content:
                return
            verdict = self.guard.verify(
                tool=f"openclaw:{agent_id}:output",
                content=content,
                cost_cents=0,
            )
            if verdict.blocked and self.block_on_violation:
                raise CertiorBlocked(verdict)

else:

    class CertiorCallbackHandler:  # type: ignore[no-redef]
        """Install ``openclaw-sdk`` to use this adapter."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "openclaw-sdk is required for the OpenClaw adapter: "
                "pip install openclaw-sdk"
            )


# ── Agent wrapper (enforcement) ──────────────────────────────────────


class GuardedAgent:
    """
    Wrap an OpenClaw ``Agent`` so its ``.execute()`` actually blocks.

    Unlike ``CertiorCallbackHandler``, this class is **not** in
    OpenClaw's exception-swallowing callback chain. It intercepts
    ``execute`` at the application layer and raises
    ``CertiorBlocked`` from its own scope, so blocked verdicts halt
    the dispatch path - the wrapped agent's ``execute`` is never
    invoked on a blocked input, and a blocked output is surfaced as
    a raised exception instead of a returned ``ExecutionResult``.

    This is the surface to use when you need real runtime enforcement
    of the eight threats in arXiv:2603.12644.

    Args:
        agent: An ``openclaw_sdk.core.agent.Agent`` instance (or any
            object with an async ``execute(query, **kwargs)`` method
            returning an object with a ``.content`` attribute).
        guard: The ``Guard`` whose policy/permissions/budget gate
            every call.

    Use together with ``CertiorCallbackHandler`` for the audit trail
    and budget accounting, and with ``GuardedPipeline`` for per-step
    capability subsetting in multi-step delegations.
    """

    def __init__(self, agent: Any, guard: Guard) -> None:
        if not hasattr(agent, "execute"):
            raise TypeError(
                "GuardedAgent expects an object with an async .execute "
                f"method (typically openclaw_sdk Agent); got {type(agent).__name__}"
            )
        self.agent = agent
        self.guard = guard

    @property
    def agent_id(self) -> str:
        return getattr(self.agent, "agent_id", "unknown")

    async def execute(self, query: str, **kwargs: Any) -> Any:
        """Verify input → run wrapped agent → verify output. Raise on block."""
        agent_id = self.agent_id

        # 1) Input gate: capability + content + budget. A blocked
        #    verdict here halts the dispatch path - the wrapped
        #    agent's execute is never called.
        input_verdict = self.guard.verify(
            tool=f"openclaw:{agent_id}",
            content=query,
            params=kwargs.get("parameters") or {k: v for k, v in kwargs.items() if isinstance(v, str)},
            cost_cents=_COST_PER_CALL,
        )
        if input_verdict.blocked:
            raise CertiorBlocked(input_verdict)

        # 2) Run the wrapped agent.
        result = await self.agent.execute(query, **kwargs)

        # 3) Output gate: scan the result's content for sensitive
        #    data and policy violations. A blocked verdict here is
        #    raised - the result never reaches the caller.
        scannable = _extract_content(result)
        if scannable:
            output_verdict = self.guard.verify(
                tool=f"openclaw:{agent_id}:output",
                content=scannable,
                cost_cents=0,
            )
            if output_verdict.blocked:
                raise CertiorBlocked(output_verdict)

        return result


# ── Pipeline proxy ───────────────────────────────────────────────────

class GuardedPipeline:
    """
    Proxy around an OpenClaw ``Pipeline`` that enforces capability
    subsetting per step.

    ``GuardedPipeline`` does exactly one job: at ``add_step`` time, it
    verifies that the step's declared capability set is a subset of the
    parent guard's permissions. A step that asks for capabilities the
    parent does not hold is rejected with ``delegation_unsafe: …`` and
    never registered on the underlying pipeline.

    ``run()`` delegates straight to the underlying pipeline. **Per-step
    budget and content gates are handled by ``CertiorCallbackHandler``,
    not by this class.** That callback fires on every ``agent.execute()``
    call OpenClaw makes (via ``openclaw_sdk.core.agent.Agent.execute``),
    so when both ``GuardedPipeline`` and ``CertiorCallbackHandler`` are
    in use together - the supported pattern - budget is debited and
    content is scanned automatically at the right moment for every
    step. Keeping the budget gate out of this class avoids
    double-charging, which would happen if both classes debited.

    Maps to the following threats from arXiv:2603.12644:

    - ClawDrain (tool-chain exploitation)  → per-step subset check at registration
    - Privilege Escalation via Tool Chains → per-step subset check at registration

    Args:
        pipeline: An OpenClaw ``Pipeline`` instance (or any object
            with ``add_step`` and ``run``). The object is wrapped,
            not mutated - its methods remain reachable as
            ``GuardedPipeline.pipeline.add_step``.
        guard: The parent ``Guard``; its ``permissions`` form the
            upper bound for every step.
        step_capabilities: Mapping from step name to the capabilities
            that step is allowed to use. Step names not in the
            mapping fall back to the empty set (most restrictive).

    Recommended use::

        guard = Guard(permissions=[...], budget_cents=...)
        handler = CertiorCallbackHandler(guard)
        async with OpenClawClient.connect(callbacks=[handler]) as client:
            pipeline = GuardedPipeline(
                Pipeline(client),
                guard,
                step_capabilities={...},
            )
            pipeline.add_step(...)
            await pipeline.run()
    """

    def __init__(
        self,
        pipeline: Any,
        guard: Guard,
        step_capabilities: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> None:
        if not (hasattr(pipeline, "add_step") and hasattr(pipeline, "run")):
            raise TypeError(
                "GuardedPipeline expects an OpenClaw Pipeline (or any "
                "object with .add_step and .run); got "
                f"{type(pipeline).__name__}"
            )
        self.pipeline = pipeline
        self.guard = guard
        self.step_capabilities = dict(step_capabilities or {})
        self._registered: List[str] = []

    def add_step(self, name: str, *args: Any, **kwargs: Any) -> "GuardedPipeline":
        """Register a step after verifying its capability subset."""
        required = frozenset(self.step_capabilities.get(name, ()))
        parent = frozenset(self.guard.permissions)
        if "*" not in parent and (excess := required - parent):
            raise CertiorBlocked(
                _make_blocked_verdict(
                    reason=(
                        f"delegation_unsafe: step {name!r} requires "
                        f"capabilities not held by the parent guard: "
                        f"{sorted(excess)}"
                    ),
                )
            )
        self.pipeline.add_step(name, *args, **kwargs)
        self._registered.append(name)
        return self

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Delegate to the underlying pipeline.

        Per-step gates are handled by ``CertiorCallbackHandler`` via
        OpenClaw's ``on_execution_start`` / ``on_execution_end`` hooks
        that fire for every ``agent.execute()`` call. This method
        intentionally does **not** debit the parent guard's budget;
        doing so would double-charge when both ``GuardedPipeline`` and
        ``CertiorCallbackHandler`` are in use together (the supported
        pattern).
        """
        return await self.pipeline.run(*args, **kwargs)


# ── Internals ────────────────────────────────────────────────────────

def _extract_content(result: Any) -> Optional[str]:
    """Pull a scannable string out of an OpenClaw ``ExecutionResult``."""
    if result is None:
        return None
    for attr in ("content", "text", "output"):
        value = getattr(result, attr, None)
        if isinstance(value, str) and value:
            return value
    if isinstance(result, str):
        return result
    return None


def _make_blocked_verdict(reason: str) -> VerifyResult:
    """Construct a blocked ``VerifyResult`` carrying a delegation reason."""
    return VerifyResult(
        allowed=False,
        reason=reason,
        violations=[],
        pii_found=[],
        redacted_content="",
        redacted_params={},
        certificate=None,
        latency_ms=0.0,
    )


# ── SKILL.md capability loader ───────────────────────────────────────


def load_step_capabilities_from_skill(skill_md_path: Any) -> List[str]:
    """Parse an OpenClaw ``SKILL.md`` and return its declared capabilities.

    OpenClaw's ``SKILL.md`` schema (per ``docs.openclaw.ai/tools/skills``)
    has no native ``capabilities`` field - the schema covers metadata
    like name, description, ``requires.bins``, ``requires.env``, and
    install instructions. Certior reads an **opt-in extension** field
    under ``metadata.certior.capabilities`` that skill authors can
    add when their skill is integrated with Certior::

        ---
        name: image-lab
        description: Generate or edit images via a provider-backed workflow
        metadata:
          openclaw:
            requires: { env: ["GEMINI_API_KEY"] }
          certior:
            capabilities: ["network:http:read", "filesystem:write"]
        ---

    If the extension field is absent, this loader returns an empty
    list (the most restrictive set) and logs a warning. This is
    deliberate: Certior does not invent capabilities from
    ``requires.bins`` heuristics because that would create false
    security. Skill authors who want their skill to work with
    Certior must declare the capability set explicitly.

    Args:
        skill_md_path: Path to a ``SKILL.md`` file (``str``, ``Path``,
            or anything ``open()`` accepts).

    Returns:
        List of capability strings (possibly empty).

    Raises:
        FileNotFoundError: If ``skill_md_path`` does not resolve.
        ValueError: If the file has no YAML frontmatter or the
            frontmatter is malformed.
    """
    import logging
    import re

    log = logging.getLogger("certior.adapters.openclaw")

    with open(skill_md_path, "r", encoding="utf-8") as fh:
        text = fh.read()

    # Frontmatter: a leading "---\n…\n---" block. Tolerant of trailing
    # whitespace and Windows newlines.
    match = re.match(
        r"\A---\r?\n(.*?)\r?\n---\r?\n", text, flags=re.DOTALL,
    )
    if not match:
        raise ValueError(
            f"{skill_md_path}: no YAML frontmatter (--- delimited block at top)"
        )

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "PyYAML is required to parse SKILL.md frontmatter "
            "(pip install PyYAML)"
        ) from exc

    try:
        data = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError as exc:
        raise ValueError(
            f"{skill_md_path}: malformed YAML frontmatter: {exc}"
        ) from exc

    metadata = data.get("metadata") if isinstance(data, dict) else None
    # OpenClaw's docs note that ``metadata`` is sometimes JSON-as-string;
    # accept either dict-shape or a single-line JSON object.
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{skill_md_path}: metadata field is a string but not valid JSON: {exc}"
            ) from exc

    certior_ext = (metadata or {}).get("certior") if isinstance(metadata, dict) else None
    caps = (certior_ext or {}).get("capabilities") if isinstance(certior_ext, dict) else None

    if caps is None:
        log.warning(
            "skill %s declares no metadata.certior.capabilities; "
            "treating as empty (most restrictive) set",
            skill_md_path,
        )
        return []

    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise ValueError(
            f"{skill_md_path}: metadata.certior.capabilities must be a list of strings"
        )

    return list(caps)


def load_step_capabilities_from_skills_dir(
    skills_dir: Any,
    step_name_from: str = "name",
) -> "dict[str, List[str]]":
    """Walk a skills directory and build a ``step_capabilities`` mapping.

    Looks for ``*/SKILL.md`` one level deep (matching OpenClaw's
    ``~/.openclaw/workspace/skills/<skill>/SKILL.md`` layout). For each
    one calls :func:`load_step_capabilities_from_skill` and keys the
    result by either the skill's ``name`` field (default) or the
    containing directory's name (``step_name_from="dirname"``).

    Args:
        skills_dir: Path to a directory containing one subdirectory
            per skill, each with a ``SKILL.md`` at its top.
        step_name_from: ``"name"`` (read the frontmatter ``name``
            field, default) or ``"dirname"`` (use the subdirectory
            name).

    Returns:
        Mapping suitable for passing as ``GuardedPipeline(step_capabilities=...)``.
    """
    from pathlib import Path

    root = Path(skills_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"{skills_dir} is not a directory")

    out: "dict[str, List[str]]" = {}
    for skill_md in sorted(root.glob("*/SKILL.md")):
        caps = load_step_capabilities_from_skill(skill_md)
        if step_name_from == "dirname":
            key = skill_md.parent.name
        else:
            # Re-parse just to get the name; cheap and avoids duplicating
            # the parsing logic.
            with open(skill_md, "r", encoding="utf-8") as fh:
                import re
                m = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", fh.read(), flags=re.DOTALL)
            if m:
                import yaml  # type: ignore[import-untyped]
                fm = yaml.safe_load(m.group(1)) or {}
                key = (fm.get("name") if isinstance(fm, dict) else None) or skill_md.parent.name
            else:
                key = skill_md.parent.name
        out[key] = caps
    return out


__all__ = [
    "CertiorCallbackHandler",
    "GuardedAgent",
    "GuardedPipeline",
    "audit_skill",
    "audit_skills_dir",
    "load_step_capabilities_from_skill",
    "load_step_capabilities_from_skills_dir",
    "skill_fingerprint",
    "SkillAuditResult",
]


# Re-export the static skill auditor so callers can write
# ``from certior.adapters.openclaw import audit_skill`` alongside the
# runtime gates. The audit module is kept as a separate file because
# (a) it has zero runtime dependencies on ``openclaw_sdk`` and (b) it
# powers the ``certior-skill-audit`` CLI.
from certior.adapters.openclaw_skill_audit import (  # noqa: E402
    SkillAuditResult,
    audit_skill,
    audit_skills_dir,
    skill_fingerprint,
)
