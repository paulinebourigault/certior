"""
Agent execution state management.

Tracks the internal lifecycle of an agent run - phase transitions,
per-step status, timing, error history, and checkpoint/rollback -
independently of the cloud-level ``StateStore`` (which handles
persistence and cross-service coordination).

Key types:

  ``AgentPhase``
      Fine-grained enum of phases an agent can be in.

  ``StepState``
      The status of a single plan step (pending → running → done/failed/skipped).

  ``AgentExecutionState``
      Full mutable snapshot of an agent's progress through a plan.

  ``AgentStateManager``
      Owns one or more ``AgentExecutionState`` objects and provides
      checkpoint / rollback, observer notification, and query helpers.
"""
from __future__ import annotations

import copy
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, ClassVar, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AgentPhase(str, Enum):
    """High-level phase of an agent run."""
    IDLE = "idle"
    INITIALISING = "initialising"
    PLANNING = "planning"
    VERIFYING_PLAN = "verifying_plan"
    EXECUTING = "executing"
    VERIFYING_OUTPUT = "verifying_output"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepStatus(str, Enum):
    """Status of an individual step within a plan."""
    PENDING = "pending"
    RUNNING = "running"
    VERIFYING = "verifying"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Step-level state
# ---------------------------------------------------------------------------

@dataclass
class StepState:
    """Tracks one step in a verified plan execution."""
    step_id: str = ""
    tool: str = ""
    index: int = 0
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    cost_cents: int = 0
    certificate_id: str = ""
    output: Any = None
    error: str = ""
    attempts: int = 0
    verified: bool = False

    # -- lifecycle helpers --

    def start(self) -> None:
        self.status = StepStatus.RUNNING
        self.started_at = time.time()
        self.attempts += 1

    def mark_verifying(self) -> None:
        self.status = StepStatus.VERIFYING

    def complete(
        self, *, output: Any = None, cost_cents: int = 0, certificate_id: str = "",
    ) -> None:
        self.status = StepStatus.DONE
        self.completed_at = time.time()
        self.output = output
        self.cost_cents = cost_cents
        self.certificate_id = certificate_id
        self.verified = True

    def fail(self, error: str) -> None:
        self.status = StepStatus.FAILED
        self.completed_at = time.time()
        self.error = error

    def skip(self, reason: str = "") -> None:
        self.status = StepStatus.SKIPPED
        self.completed_at = time.time()
        self.error = reason

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.completed_at or time.time()
        return (end - self.started_at) * 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool": self.tool,
            "index": self.index,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "cost_cents": self.cost_cents,
            "certificate_id": self.certificate_id,
            "error": self.error,
            "attempts": self.attempts,
            "verified": self.verified,
        }


# ---------------------------------------------------------------------------
# Agent-level execution state
# ---------------------------------------------------------------------------

@dataclass
class AgentExecutionState:
    """
    Full mutable snapshot of an agent's progress.

    Create one per orchestrator run.  The orchestrator (or individual
    agents) call ``transition`` / ``set_current_step`` / ``record_error``
    as the run progresses.  A ``AgentStateManager`` can checkpoint and
    rollback these states.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    task: str = ""
    phase: AgentPhase = AgentPhase.IDLE
    steps: List[StepState] = field(default_factory=list)
    current_step_index: int = -1
    total_budget_cents: int = 0
    consumed_cents: int = 0
    plan_hash: str = ""
    plan_certificate_id: str = ""
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_history: List[Dict[str, Any]] = field(default_factory=list)

    # -- phase transitions --

    _ALLOWED_TRANSITIONS: ClassVar[Dict[AgentPhase, List[AgentPhase]]] = {
        AgentPhase.IDLE: [AgentPhase.INITIALISING],
        AgentPhase.INITIALISING: [AgentPhase.PLANNING, AgentPhase.FAILED],
        AgentPhase.PLANNING: [AgentPhase.VERIFYING_PLAN, AgentPhase.FAILED],
        AgentPhase.VERIFYING_PLAN: [AgentPhase.EXECUTING, AgentPhase.FAILED],
        AgentPhase.EXECUTING: [
            AgentPhase.VERIFYING_OUTPUT, AgentPhase.FAILED, AgentPhase.ROLLED_BACK,
        ],
        AgentPhase.VERIFYING_OUTPUT: [AgentPhase.COMPLETED, AgentPhase.FAILED],
        AgentPhase.FAILED: [AgentPhase.ROLLED_BACK, AgentPhase.IDLE],
        AgentPhase.COMPLETED: [],
        AgentPhase.ROLLED_BACK: [AgentPhase.IDLE],
    }

    def transition(self, new_phase: AgentPhase) -> None:
        """
        Move to *new_phase*.

        Raises ``InvalidTransition`` if the move is not allowed by the
        state machine.
        """
        allowed = self._ALLOWED_TRANSITIONS.get(self.phase, [])
        if new_phase not in allowed:
            raise InvalidTransition(
                f"Cannot transition from {self.phase.value} to {new_phase.value}"
            )
        self.phase = new_phase
        if new_phase == AgentPhase.INITIALISING:
            self.started_at = time.time()
        if new_phase in (AgentPhase.COMPLETED, AgentPhase.FAILED, AgentPhase.ROLLED_BACK):
            self.completed_at = time.time()

    # -- step management --

    def init_steps(self, steps: List[Dict[str, Any]]) -> None:
        """Populate step states from a plan's step list."""
        self.steps = [
            StepState(
                step_id=s.get("id", str(uuid.uuid4())),
                tool=s.get("tool", ""),
                index=i,
            )
            for i, s in enumerate(steps)
        ]
        self.current_step_index = -1

    def advance_step(self) -> Optional[StepState]:
        """Move to the next pending step and mark it running.  Returns ``None`` when done."""
        next_idx = self.current_step_index + 1
        if next_idx >= len(self.steps):
            return None
        self.current_step_index = next_idx
        step = self.steps[next_idx]
        step.start()
        return step

    @property
    def current_step(self) -> Optional[StepState]:
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    # -- budget tracking --

    def consume_budget(self, cents: int) -> None:
        self.consumed_cents += cents

    @property
    def budget_remaining_cents(self) -> int:
        return max(0, self.total_budget_cents - self.consumed_cents)

    @property
    def budget_exhausted(self) -> bool:
        return self.consumed_cents >= self.total_budget_cents and self.total_budget_cents > 0

    # -- error history --

    def record_error(self, error: str, *, phase: Optional[str] = None) -> None:
        self.error_history.append({
            "error": error,
            "phase": phase or self.phase.value,
            "step_index": self.current_step_index,
            "timestamp": time.time(),
        })

    # -- query helpers --

    @property
    def is_terminal(self) -> bool:
        return self.phase in (AgentPhase.COMPLETED, AgentPhase.FAILED, AgentPhase.ROLLED_BACK)

    @property
    def duration_ms(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.completed_at or time.time()
        return (end - self.started_at) * 1000

    @property
    def completed_steps(self) -> List[StepState]:
        return [s for s in self.steps if s.status == StepStatus.DONE]

    @property
    def failed_steps(self) -> List[StepState]:
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    @property
    def progress(self) -> float:
        """Return a 0.0-1.0 progress fraction."""
        if not self.steps:
            return 0.0
        done = sum(1 for s in self.steps if s.status in (StepStatus.DONE, StepStatus.SKIPPED))
        return done / len(self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "task": self.task,
            "phase": self.phase.value,
            "current_step_index": self.current_step_index,
            "progress": round(self.progress, 4),
            "total_budget_cents": self.total_budget_cents,
            "consumed_cents": self.consumed_cents,
            "budget_remaining_cents": self.budget_remaining_cents,
            "duration_ms": self.duration_ms,
            "steps": [s.to_dict() for s in self.steps],
            "error_history": self.error_history,
            "is_terminal": self.is_terminal,
        }


# ---------------------------------------------------------------------------
# State manager
# ---------------------------------------------------------------------------

class AgentStateManager:
    """
    Manages ``AgentExecutionState`` instances and provides checkpoint /
    rollback, observer notification, and lookup.

    Typical usage::

        mgr = AgentStateManager()
        state = mgr.create(agent_id="planner", task="Analyse report", budget=10000)
        state.transition(AgentPhase.INITIALISING)

        # ... later, before a risky step ...
        cp = mgr.checkpoint(state.id)

        # ... if the step fails ...
        mgr.rollback(state.id, cp)
    """

    def __init__(self) -> None:
        self._states: Dict[str, AgentExecutionState] = {}
        self._checkpoints: Dict[str, Dict[str, AgentExecutionState]] = {}  # state_id → {cp_id → snapshot}
        self._observers: List[Callable[[AgentExecutionState, str], Any]] = []

    # -- creation --

    def create(
        self,
        agent_id: str,
        task: str = "",
        budget_cents: int = 0,
    ) -> AgentExecutionState:
        """Create and register a new execution state."""
        state = AgentExecutionState(
            agent_id=agent_id,
            task=task,
            total_budget_cents=budget_cents,
        )
        self._states[state.id] = state
        self._checkpoints[state.id] = {}
        self._notify(state, "created")
        return state

    # -- lookup --

    def get(self, state_id: str) -> Optional[AgentExecutionState]:
        return self._states.get(state_id)

    def list_active(self) -> List[AgentExecutionState]:
        return [s for s in self._states.values() if not s.is_terminal]

    def list_all(self) -> List[AgentExecutionState]:
        return list(self._states.values())

    # -- checkpoint / rollback --

    def checkpoint(self, state_id: str) -> str:
        """
        Snapshot the current state.  Returns a checkpoint id that can
        be passed to ``rollback``.
        """
        state = self._states.get(state_id)
        if state is None:
            raise KeyError(f"Unknown state: {state_id}")
        cp_id = str(uuid.uuid4())
        self._checkpoints[state_id][cp_id] = copy.deepcopy(state)
        self._notify(state, "checkpoint")
        return cp_id

    def rollback(self, state_id: str, checkpoint_id: str) -> AgentExecutionState:
        """
        Restore state to a previous checkpoint.

        The current state is replaced in-place so that all references
        to the ``AgentExecutionState`` see the restored values.
        """
        cps = self._checkpoints.get(state_id, {})
        snapshot = cps.get(checkpoint_id)
        if snapshot is None:
            raise KeyError(f"Checkpoint {checkpoint_id} not found for state {state_id}")

        restored = copy.deepcopy(snapshot)
        # Preserve the original id so references stay valid
        restored.id = state_id
        self._states[state_id] = restored
        self._notify(restored, "rollback")
        return restored

    def list_checkpoints(self, state_id: str) -> List[str]:
        """Return checkpoint ids for a given state, oldest first."""
        return list(self._checkpoints.get(state_id, {}).keys())

    def discard_checkpoints(self, state_id: str) -> int:
        """Remove all checkpoints for a state.  Returns count removed."""
        cps = self._checkpoints.pop(state_id, {})
        return len(cps)

    # -- observer pattern --

    def add_observer(self, callback: Callable[[AgentExecutionState, str], Any]) -> None:
        """Register a callback invoked as ``callback(state, event_name)``."""
        self._observers.append(callback)

    def remove_observer(self, callback: Callable) -> None:
        self._observers = [o for o in self._observers if o is not callback]

    def _notify(self, state: AgentExecutionState, event: str) -> None:
        for obs in self._observers:
            try:
                obs(state, event)
            except Exception:
                pass  # observer errors must not break the state machine

    # -- cleanup --

    def remove(self, state_id: str) -> bool:
        removed = self._states.pop(state_id, None) is not None
        self._checkpoints.pop(state_id, None)
        return removed


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidTransition(Exception):
    """Raised when an illegal phase transition is attempted."""
    pass
