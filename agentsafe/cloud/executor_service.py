"""
ExecutorService - async task execution with automatic mode selection.

When an LLM config and tool registry are available, routes through the
reactive AgenticOrchestrator (LLM decides each tool call dynamically).
Otherwise falls back to the plan-based VerifiedOrchestrator pipeline.

Status updates flow:
  AgenticExecutor → AgenticOrchestrator → ExecutorService → EventBus → WebSocket
"""
from __future__ import annotations

import logging
import os
import time
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Optional
from unittest.mock import Mock

from agentsafe.capabilities.tokens import CapabilityToken
from agentsafe.compliance.exporter import ComplianceExporter
from agentsafe.compliance.presets import CompliancePresets
from agentsafe.safety.scanner import ContentSafetyPolicy
from agentsafe.skills.loader import VerifiedSkillLoader
from .state_store import StateStore, Execution, ExecutionStatus
from .event_bus import EventBus, Event
from .webhook import WebhookManager

log = logging.getLogger(__name__)


class ExecutorService:
    """
    Async execution service with automatic mode selection.

    Modes:
      agentic  - LLM reactive loop (AgenticOrchestrator)
      legacy   - plan→execute→verify pipeline (VerifiedOrchestrator)

    The mode is determined at runtime based on whether llm_config is set.

    Persistence:
      By default uses in-memory stores.  Call ``ExecutorService.create()``
      with a ``data_dir`` to get SQLite-backed persistence that survives
      process restarts.
    """

    def __init__(
        self,
        state_store: Optional[StateStore] = None,
        event_bus: Optional[EventBus] = None,
        webhook_manager: Optional[WebhookManager] = None,
        # Legacy pipeline kwargs
        tools: Optional[Dict[str, Any]] = None,
        skill_loader: Optional[VerifiedSkillLoader] = None,
        content_policy: Optional[ContentSafetyPolicy] = None,
        llm_client: Any = None,
        # Agentic pipeline kwargs
        llm_config: Any = None,
        tool_registry: Any = None,
        system_prompt: Optional[str] = None,
        runtime_llm_credentials: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        self.state = state_store or StateStore()
        self.events = event_bus or EventBus()
        self.webhooks = webhook_manager or WebhookManager()

        # Legacy
        self.tools = tools or {}
        self.skill_loader = skill_loader
        self.content_policy = content_policy
        self.llm_client = llm_client

        # Agentic
        self.llm_config = llm_config
        self.tool_registry = tool_registry
        self.system_prompt = system_prompt
        self.runtime_llm_credentials = runtime_llm_credentials if runtime_llm_credentials is not None else {}

    @classmethod
    async def create(
        cls,
        data_dir: str = "certior_data",
        **kwargs: Any,
    ) -> "ExecutorService":
        """
        Create an ExecutorService with SQLite-backed persistence.

        All execution state, tasks, and events survive process restarts.

        Args:
            data_dir: Directory for SQLite database files.
            **kwargs: Forwarded to ``__init__`` (llm_config, tools, etc.)
        """
        from .sqlite_backend import create_backend

        store, queue, bus = await create_backend(data_dir)
        return cls(state_store=store, event_bus=bus, **kwargs)

    @property
    def mode(self) -> str:
        """Return 'agentic' if LLM config is available, else 'legacy'."""
        if self.llm_config is not None:
            try:
                from agentsafe.llm.config import LLMConfig
                if isinstance(self.llm_config, LLMConfig) and self.llm_config.is_configured:
                    return "agentic"
            except ImportError:
                pass
        return "legacy"

    # ------------------------------------------------------------------
    # Task lifecycle
    # ------------------------------------------------------------------

    async def submit(
        self,
        task: str,
        user_id: str,
        token: CapabilityToken,
        webhook_url: str = "",
        llm_provider: str = None,
        llm_model: str = None,
        llm_api_key: str = None,
        verification_profile: Optional[Dict[str, Any]] = None,
    ) -> Execution:
        """Create a new execution record."""
        execution = Execution(
            user_id=user_id,
            task=task,
            token_id=token.id,
            webhook_url=webhook_url,
            llm_provider=llm_provider,
            llm_model=llm_model,
            token_data={
                "id": token.id,
                "agent_id": token.agent_id,
                "permissions": list(token.permissions),
                "budget_cents": token.budget_cents,
                "budget_remaining_cents": getattr(token, "budget_remaining_cents", token.budget_cents),
                "metadata": dict(getattr(token, "metadata", {}) or {}),
                "verification_profile": verification_profile,
            },
        )
        if llm_api_key:
            self.runtime_llm_credentials[execution.id] = {
                "provider": llm_provider or "",
                "model": llm_model or "",
                "api_key": llm_api_key,
            }
        await self.state.create(execution)
        await self.events.emit(Event(
            type="execution.created",
            execution_id=execution.id,
            data={"task": task, "mode": self.mode},
        ))
        return execution

    async def execute(
        self,
        execution_id: str,
        token: Any = None,
    ) -> Execution:
        """
        Execute a submitted task.

        Automatically selects the agentic or legacy pipeline.

        *token* may be a CapabilityToken, a dict (from JSON round-trip),
        a string (from SQLite ``default=str`` serialisation), or ``None``
        (in which case a default token is constructed from execution data).
        """
        execution = await self.state.get(execution_id)
        if not execution:
            raise ValueError(f"Execution not found: {execution_id}")

        # ── Reconstruct CapabilityToken if needed ───────────────────
        token = self._ensure_token(token, execution)

        execution.status = ExecutionStatus.PLANNING
        await self.state.update(execution)
        await self._emit(execution, "planning")

        try:
            release_binding = await self._validate_temporal_requirements(execution)
            if release_binding is not None:
                token = self._bind_release_artifacts(execution, token, release_binding)
                await self.state.update(execution)

            if self.mode == "agentic":
                result = await self._execute_agentic(execution, token)
            else:
                result = await self._execute_legacy(execution, token)

            # Apply result to execution
            if result.success:
                execution.status = ExecutionStatus.COMPLETED
                execution.results = self._build_execution_results(result)
                execution.certificates = result.certificates
                execution.cost_cents = result.cost_cents
                execution.completed_at = time.time()
            else:
                execution.status = ExecutionStatus.FAILED
                execution.error = result.error

            await self.state.update(execution)
            await self._emit(execution, execution.status.value, data={
                "cost_cents": execution.cost_cents,
                "certificate_count": len(execution.certificates),
            })

            # Webhook
            if execution.webhook_url:
                await self.webhooks.deliver(
                    execution.webhook_url,
                    execution.to_dict(),
                )

            return execution

        except Exception as exc:
            log.exception("Execution %s failed", execution_id)
            execution.status = ExecutionStatus.FAILED
            # Sanitize error: don't leak stack traces or internal paths
            error_msg = str(exc)
            if any(s in error_msg for s in ("/home/", "Traceback", "File \"")):
                error_msg = f"Internal error: {type(exc).__name__}"

            # Detect billing/quota errors and add provider context
            error_lower = error_msg.lower()
            is_billing = any(kw in error_lower for kw in (
                "credit balance", "billing", "quota", "rate_limit",
                "insufficient_quota", "exceeded", "payment",
            ))
            if is_billing:
                # Identify which provider failed
                failed_provider = (
                    execution.llm_provider
                    or (self.llm_config.provider if self.llm_config else "unknown")
                )
                alt_providers = {"anthropic": "openai", "openai": "anthropic"}
                alt = alt_providers.get(failed_provider, "")
                alt_key = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}.get(alt, "")

                hint = f" [Provider: {failed_provider}]"
                if alt and os.environ.get(alt_key):
                    hint += (
                        f" - Tip: {alt} is also configured. "
                        f"Resubmit with provider='{alt}' or switch in Settings."
                    )
                elif alt:
                    hint += (
                        f" - Set {alt_key} to enable {alt} as a fallback provider."
                    )
                error_msg += hint

            execution.error = error_msg
            await self.state.update(execution)
            await self._emit(execution, "failed", data={"error": error_msg})
            return execution

    # ------------------------------------------------------------------
    # Agentic pipeline
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Token reconstruction
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_token(token: Any, execution: Execution) -> CapabilityToken:
        """
        Guarantee we have a proper CapabilityToken.

        The SQLite task queue serialises args with ``json.dumps(default=str)``
        which turns the token into its ``__repr__`` string.  This method
        reconstructs it from whatever we received.
        """
        if isinstance(token, CapabilityToken):
            return token

        # Dict from JSON round-trip
        if isinstance(token, dict):
            return CapabilityToken(
                id=token.get("id", execution.token_id or token.get("token_id", "")),
                agent_id=token.get("agent_id", execution.user_id),
                permissions=token.get("permissions", ["*"]),
                budget_cents=token.get("budget_cents", 10000),
                budget_remaining_cents=token.get("budget_remaining_cents", 10000),
                expires_at=token.get("expires_at"),
                metadata=token.get("metadata", {}),
            )

        # Stored during submit()
        td = getattr(execution, "token_data", None)
        if isinstance(td, dict):
            return CapabilityToken(
                id=td.get("id", execution.token_id or ""),
                agent_id=td.get("agent_id", execution.user_id),
                permissions=td.get("permissions", ["*"]),
                budget_cents=td.get("budget_cents", 10000),
                budget_remaining_cents=td.get("budget_remaining_cents", 10000),
                metadata=td.get("metadata", {}),
            )

        # Fallback: create a default token from execution metadata
        return CapabilityToken(
            id=execution.token_id or "",
            agent_id=execution.user_id,
            permissions=["*"],
            budget_cents=10000,
            budget_remaining_cents=10000,
        )

    def _build_content_policy_for_execution(self, execution: Execution) -> ContentSafetyPolicy:
        policy_name = self._extract_compliance_policy_name(execution)
        try:
            config = CompliancePresets.get(policy_name)
        except ValueError:
            return self.content_policy or ContentSafetyPolicy.default()

        profile = self._extract_verification_profile(execution) or {}
        if profile.get("task_class") == "public_safe_summary" and policy_name.lower() == "hipaa":
            adjusted = deepcopy(config.content_safety)
            adjusted.blocked_keywords = [
                keyword for keyword in adjusted.blocked_keywords
                if keyword.lower() not in {"diagnosis", "treatment plan", "prescription"}
            ]
            return adjusted

        return config.content_safety

    async def _execute_agentic(self, execution: Execution, token: CapabilityToken):
        """Route through AgenticOrchestrator (reactive LLM loop)."""
        from agentsafe.agents.agentic_orchestrator import AgenticOrchestrator

        execution.status = ExecutionStatus.EXECUTING
        await self.state.update(execution)
        await self._emit(execution, "executing", data={"mode": "agentic"})

        # Per-task LLM config override
        task_llm_config = self.llm_config
        if execution.llm_provider or execution.llm_model:
            from agentsafe.llm.config import LLMConfig
            import os
            override_provider = execution.llm_provider or self.llm_config.provider
            override_model = execution.llm_model or ""
            # Resolve API key for the target provider
            key_env = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
            }
            runtime_credentials = self.runtime_llm_credentials.get(execution.id) or {}
            api_key = runtime_credentials.get("api_key") or os.environ.get(key_env.get(override_provider, ""), "")
            if api_key:
                task_llm_config = LLMConfig(
                    provider=override_provider,
                    model=override_model,
                    api_key=api_key,
                )
                log.info(
                    "Task %s using provider override: %s/%s",
                    execution.id[:8], override_provider, task_llm_config.model,
                )
            self.runtime_llm_credentials.pop(execution.id, None)

        orchestrator = AgenticOrchestrator(
            capability_token=token,
            llm_config=task_llm_config,
            tool_registry=self._build_tool_registry_for_execution(execution),
            content_policy=self._build_content_policy_for_execution(execution),
            system_prompt=self.system_prompt,
            on_status=self._make_agentic_status_handler(execution),
        )

        return await orchestrator.execute(execution.task)

    def _make_agentic_status_handler(self, execution: Execution):
        """
        Create a status callback that translates agentic status events
        into rich execution events for the WebSocket stream.
        """
        step_counter = {"n": 0}

        async def _handler(status: str, task: str):
            data: Dict[str, Any] = {"mode": "agentic"}

            if status == "executing_tool":
                step_counter["n"] += 1
                execution.current_step = step_counter["n"]
                await self.state.update(execution)
                data["step"] = step_counter["n"]

            elif status == "verifying":
                execution.status = ExecutionStatus.VERIFYING
                await self.state.update(execution)
                data["step"] = step_counter["n"]

            await self._emit(execution, status, data=data)

        return _handler

    # ------------------------------------------------------------------
    # Legacy pipeline
    # ------------------------------------------------------------------

    async def _execute_legacy(self, execution: Execution, token: CapabilityToken):
        """Route through plan-based VerifiedOrchestrator."""
        from agentsafe.agents.orchestrator import VerifiedOrchestrator

        execution.status = ExecutionStatus.EXECUTING
        await self.state.update(execution)
        await self._emit(execution, "executing", data={"mode": "legacy"})

        orchestrator = VerifiedOrchestrator(
            capability_token=token,
            llm_client=self.llm_client,
            tools=self.tools,
            skill_loader=self.skill_loader,
            content_policy=self._build_content_policy_for_execution(execution),
            on_status=lambda status, task: self._on_legacy_status(execution, status),
        )

        return await orchestrator.execute(execution.task)

    async def _on_legacy_status(self, execution: Execution, status: str):
        """Forward legacy orchestrator status updates."""
        if status == "verifying":
            execution.status = ExecutionStatus.VERIFYING
            await self.state.update(execution)
        await self._emit(execution, status, data={"mode": "legacy"})

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    async def get_status(self, execution_id: str) -> Optional[Execution]:
        return await self.state.get(execution_id)

    async def cancel(self, execution_id: str) -> bool:
        execution = await self.state.get(execution_id)
        if execution and execution.status in (
            ExecutionStatus.QUEUED,
            ExecutionStatus.PLANNING,
        ):
            execution.status = ExecutionStatus.CANCELLED
            await self.state.update(execution)
            await self._emit(execution, "cancelled")
            return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _emit(
        self,
        execution: Execution,
        status: str,
        *,
        data: Optional[Dict[str, Any]] = None,
    ):
        """Emit an event to the bus."""
        payload = {"status": status, "task": execution.task}
        if data:
            payload.update(data)
        await self.events.emit(Event(
            type=f"execution.{status}",
            execution_id=execution.id,
            data=payload,
        ))

    @staticmethod
    def _serialise_result_value(value: Any) -> Any:
        """Convert rich result objects into JSON-safe structures."""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mock):
            return str(value)
        if isinstance(value, list):
            return [ExecutorService._serialise_result_value(item) for item in value]
        if isinstance(value, tuple):
            return [ExecutorService._serialise_result_value(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): ExecutorService._serialise_result_value(item)
                for key, item in value.items()
            }
        if hasattr(value, "to_dict"):
            return ExecutorService._serialise_result_value(value.to_dict())
        if is_dataclass(value):
            return ExecutorService._serialise_result_value(asdict(value))
        return str(value)

    @classmethod
    def _build_execution_results(cls, result: Any) -> Dict[str, Any]:
        """Persist the execution result with enough detail for audit export."""
        payload: Dict[str, Any] = {
            "output": str(result.output) if getattr(result, "output", None) else None,
            "cost_cents": getattr(result, "cost_cents", 0),
            "duration_ms": getattr(result, "duration_ms", 0.0),
            "steps": cls._serialise_result_value(getattr(result, "steps", [])),
            "total_input_tokens": getattr(result, "total_input_tokens", 0),
            "total_output_tokens": getattr(result, "total_output_tokens", 0),
        }

        optional_fields = {
            "audit_trail": getattr(result, "audit_trail", None),
            "step_scans": getattr(result, "step_scans", None),
            "ifc_summary": getattr(result, "ifc_summary", None),
            "approval_summary": getattr(result, "approval_summary", None),
            "lean_verification_summary": getattr(result, "lean_summary", None),
            "safety_scan": getattr(result, "safety_scan", None),
            "lean_certificates": getattr(result, "lean_certificates", None),
            "verification_profile": getattr(result, "verification_profile", None),
            "approved_artifact": getattr(result, "approved_artifact", None),
            "release_binding_summary": getattr(result, "release_binding_summary", None),
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = cls._serialise_result_value(value)

        if hasattr(result, "to_dict"):
            result_dict = cls._serialise_result_value(result.to_dict())
            for key in (
                "content_safety_summary",
                "ifc_summary",
                "approval_summary",
                "lean_verification_summary",
            ):
                if key in result_dict and key not in payload:
                    payload[key] = result_dict[key]

        return payload

    def _build_tool_registry_for_execution(self, execution: Execution):
        registry = self.tool_registry
        if registry is not None and not getattr(registry, "_profile_aware_factory", False):
            return registry

        try:
            from agentsafe.tools import create_default_registry
        except ImportError:
            return registry

        token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
        metadata = token_data.get("metadata") if isinstance(token_data.get("metadata"), dict) else {}
        verification_profile = self._extract_verification_profile(execution)
        compliance_policy = str(metadata.get("compliance_policy") or "default")
        workspace = os.getenv("CERTIOR_WORKSPACE", "/tmp/certior-workspace")
        skills_dir = os.getenv("CERTIOR_SKILLS_DIR")
        return create_default_registry(
            workspace=workspace,
            skills_dir=skills_dir,
            compliance_policy=compliance_policy,
            verification_profile=verification_profile,
        )

    def _extract_verification_profile(self, execution: Execution) -> Optional[Dict[str, Any]]:
        token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
        profile = token_data.get("verification_profile")
        if isinstance(profile, dict):
            return profile
        metadata = token_data.get("metadata")
        if isinstance(metadata, dict):
            profile = metadata.get("verification_profile")
            if isinstance(profile, dict):
                return profile
        if isinstance(execution.results, dict):
            profile = execution.results.get("verification_profile")
            if isinstance(profile, dict):
                return profile
        return None

    def _extract_compliance_policy_name(self, execution: Execution) -> str:
        token_data = execution.token_data if isinstance(execution.token_data, dict) else {}
        metadata = token_data.get("metadata")
        if isinstance(metadata, dict):
            policy_name = metadata.get("compliance_policy")
            if isinstance(policy_name, str) and policy_name:
                return policy_name
        return "default"

    def _bind_release_artifacts(
        self,
        execution: Execution,
        token: CapabilityToken,
        release_binding: Dict[str, Any],
    ) -> CapabilityToken:
        token_data = dict(execution.token_data or {})
        metadata = dict(token_data.get("metadata") or {})
        profile = self._extract_verification_profile(execution) or {}
        profile = dict(profile)
        profile_metadata = dict(profile.get("metadata") or {})
        profile_metadata["release_binding"] = release_binding
        profile["metadata"] = profile_metadata
        metadata["verification_profile"] = profile
        token_data["metadata"] = metadata
        token_data["verification_profile"] = profile
        execution.token_data = token_data

        return CapabilityToken(
            id=token.id,
            agent_id=token.agent_id,
            permissions=list(token.permissions),
            budget_cents=token.budget_cents,
            budget_remaining_cents=token.budget_remaining_cents,
            expires_at=token.expires_at,
            metadata=metadata,
        )

    @staticmethod
    def _extract_approved_artifact(execution: Execution) -> Optional[Dict[str, Any]]:
        results = execution.results if isinstance(execution.results, dict) else {}
        artifact = results.get("approved_artifact")
        if not isinstance(artifact, dict):
            return None
        if not artifact.get("approved_for_release"):
            return None
        artifact_hash = artifact.get("sha256")
        artifact_text = artifact.get("text")
        if not artifact_hash or not artifact_text:
            return None
        return {
            "execution_id": execution.id,
            "sha256": str(artifact_hash),
            "text": str(artifact_text),
            "stage_role": artifact.get("stage_role", "reviewer"),
            "task_class": artifact.get("task_class", "privacy_review"),
        }

    async def _validate_temporal_requirements(self, execution: Execution) -> Optional[Dict[str, Any]]:
        profile = self._extract_verification_profile(execution) or {}
        if profile.get("stage_role") != "release":
            return None

        upstream_ids = profile.get("upstream_execution_ids")
        if not isinstance(upstream_ids, list) or not upstream_ids:
            raise ValueError(
                "Release-stage execution is missing upstream reviewer executions"
            )

        failures = []
        approved_artifacts = []
        for upstream_id in upstream_ids:
            upstream = await self.state.get(str(upstream_id))
            if upstream is None:
                failures.append(f"missing:{upstream_id}")
                continue
            if upstream.status != ExecutionStatus.COMPLETED:
                failures.append(f"not_completed:{upstream_id}")
                continue

            upstream_profile = self._extract_verification_profile(upstream) or {}
            if upstream_profile.get("stage_role") != "reviewer":
                failures.append(f"not_reviewer:{upstream_id}")
                continue

            policy_name = self._extract_compliance_policy_name(upstream)
            config = CompliancePresets.get(policy_name)
            attestation = ComplianceExporter(config).export(upstream).attestation
            if not attestation.get("compliant"):
                failures.append(f"non_compliant:{upstream_id}")
                continue

            approved_artifact = self._extract_approved_artifact(upstream)
            if approved_artifact is None:
                failures.append(f"missing_approved_artifact:{upstream_id}")
                continue
            approved_artifacts.append(approved_artifact)

        if failures:
            raise ValueError(
                "Release-stage temporal validation failed: " + ", ".join(failures)
            )

        return {
            "approved_artifacts": approved_artifacts,
            "bound_at": time.time(),
        }
