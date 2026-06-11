"""
Comprehensive tests for agentsafe.agents.state.

Covers:
  - StepState lifecycle (start → verifying → complete / fail / skip)
  - AgentExecutionState phase transitions (state machine validation)
  - AgentExecutionState step management, budget tracking, error history
  - AgentStateManager: create, checkpoint, rollback, observers, cleanup
  - Serialisation via to_dict()
  - Edge cases: illegal transitions, empty plans, double advance
"""
import time
import pytest

from agentsafe.agents.state import (
    AgentPhase,
    StepStatus,
    StepState,
    AgentExecutionState,
    AgentStateManager,
    InvalidTransition,
)


# ═══════════════════════════════════════════════════════════════════════════
# StepState
# ═══════════════════════════════════════════════════════════════════════════


class TestStepState:
    def test_initial_state(self):
        s = StepState(step_id="s1", tool="web_browsing", index=0)
        assert s.status == StepStatus.PENDING
        assert s.started_at is None
        assert s.completed_at is None
        assert s.attempts == 0
        assert s.verified is False
        assert s.duration_ms is None

    def test_start(self):
        s = StepState(step_id="s1")
        s.start()
        assert s.status == StepStatus.RUNNING
        assert s.started_at is not None
        assert s.attempts == 1

    def test_start_increments_attempts(self):
        s = StepState()
        s.start()
        s.start()
        assert s.attempts == 2

    def test_mark_verifying(self):
        s = StepState()
        s.start()
        s.mark_verifying()
        assert s.status == StepStatus.VERIFYING

    def test_complete(self):
        s = StepState()
        s.start()
        s.complete(output={"rows": 10}, cost_cents=50, certificate_id="cert-1")
        assert s.status == StepStatus.DONE
        assert s.completed_at is not None
        assert s.output == {"rows": 10}
        assert s.cost_cents == 50
        assert s.certificate_id == "cert-1"
        assert s.verified is True

    def test_fail(self):
        s = StepState()
        s.start()
        s.fail("timeout")
        assert s.status == StepStatus.FAILED
        assert s.error == "timeout"
        assert s.completed_at is not None

    def test_skip(self):
        s = StepState()
        s.skip("not needed")
        assert s.status == StepStatus.SKIPPED
        assert s.error == "not needed"

    def test_duration_ms_while_running(self):
        s = StepState()
        s.start()
        dur = s.duration_ms
        assert dur is not None
        assert dur >= 0

    def test_duration_ms_after_completion(self):
        s = StepState()
        s.start()
        s.complete()
        dur = s.duration_ms
        assert dur is not None
        assert dur >= 0

    def test_to_dict(self):
        s = StepState(step_id="s1", tool="db_query", index=2)
        s.start()
        s.complete(cost_cents=10, certificate_id="c1")
        d = s.to_dict()
        assert d["step_id"] == "s1"
        assert d["tool"] == "db_query"
        assert d["index"] == 2
        assert d["status"] == "done"
        assert d["cost_cents"] == 10
        assert d["certificate_id"] == "c1"
        assert d["verified"] is True
        assert d["attempts"] == 1
        assert isinstance(d["duration_ms"], float)


# ═══════════════════════════════════════════════════════════════════════════
# AgentExecutionState - Phase transitions
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentExecutionStateTransitions:
    """Validate the state machine enforces legal transitions."""

    def _make(self) -> AgentExecutionState:
        return AgentExecutionState(agent_id="test", task="t")

    def test_happy_path(self):
        s = self._make()
        s.transition(AgentPhase.INITIALISING)
        assert s.started_at is not None
        s.transition(AgentPhase.PLANNING)
        s.transition(AgentPhase.VERIFYING_PLAN)
        s.transition(AgentPhase.EXECUTING)
        s.transition(AgentPhase.VERIFYING_OUTPUT)
        s.transition(AgentPhase.COMPLETED)
        assert s.phase == AgentPhase.COMPLETED
        assert s.completed_at is not None

    def test_fail_from_planning(self):
        s = self._make()
        s.transition(AgentPhase.INITIALISING)
        s.transition(AgentPhase.PLANNING)
        s.transition(AgentPhase.FAILED)
        assert s.phase == AgentPhase.FAILED

    def test_fail_then_rollback(self):
        s = self._make()
        s.transition(AgentPhase.INITIALISING)
        s.transition(AgentPhase.PLANNING)
        s.transition(AgentPhase.FAILED)
        s.transition(AgentPhase.ROLLED_BACK)
        assert s.phase == AgentPhase.ROLLED_BACK

    def test_rollback_then_restart(self):
        s = self._make()
        s.transition(AgentPhase.INITIALISING)
        s.transition(AgentPhase.PLANNING)
        s.transition(AgentPhase.FAILED)
        s.transition(AgentPhase.ROLLED_BACK)
        s.transition(AgentPhase.IDLE)
        assert s.phase == AgentPhase.IDLE

    def test_illegal_transition_raises(self):
        s = self._make()
        with pytest.raises(InvalidTransition):
            s.transition(AgentPhase.EXECUTING)  # IDLE → EXECUTING not allowed

    def test_completed_is_terminal(self):
        s = self._make()
        s.transition(AgentPhase.INITIALISING)
        s.transition(AgentPhase.PLANNING)
        s.transition(AgentPhase.VERIFYING_PLAN)
        s.transition(AgentPhase.EXECUTING)
        s.transition(AgentPhase.VERIFYING_OUTPUT)
        s.transition(AgentPhase.COMPLETED)
        with pytest.raises(InvalidTransition):
            s.transition(AgentPhase.IDLE)

    def test_fail_from_every_non_terminal_phase(self):
        """FAILED should be reachable from every working phase."""
        for start_phase in [
            AgentPhase.INITIALISING,
            AgentPhase.PLANNING,
            AgentPhase.VERIFYING_PLAN,
            AgentPhase.EXECUTING,
            AgentPhase.VERIFYING_OUTPUT,
        ]:
            s = self._make()
            # Walk to start_phase
            path = {
                AgentPhase.INITIALISING: [AgentPhase.INITIALISING],
                AgentPhase.PLANNING: [AgentPhase.INITIALISING, AgentPhase.PLANNING],
                AgentPhase.VERIFYING_PLAN: [
                    AgentPhase.INITIALISING, AgentPhase.PLANNING,
                    AgentPhase.VERIFYING_PLAN,
                ],
                AgentPhase.EXECUTING: [
                    AgentPhase.INITIALISING, AgentPhase.PLANNING,
                    AgentPhase.VERIFYING_PLAN, AgentPhase.EXECUTING,
                ],
                AgentPhase.VERIFYING_OUTPUT: [
                    AgentPhase.INITIALISING, AgentPhase.PLANNING,
                    AgentPhase.VERIFYING_PLAN, AgentPhase.EXECUTING,
                    AgentPhase.VERIFYING_OUTPUT,
                ],
            }[start_phase]
            for p in path:
                s.transition(p)
            s.transition(AgentPhase.FAILED)
            assert s.phase == AgentPhase.FAILED


# ═══════════════════════════════════════════════════════════════════════════
# AgentExecutionState - Step management
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentExecutionStateSteps:
    def _make_with_steps(self, n=3):
        s = AgentExecutionState(agent_id="e", task="t")
        steps = [{"id": f"step-{i}", "tool": f"tool_{i}"} for i in range(n)]
        s.init_steps(steps)
        return s

    def test_init_steps(self):
        s = self._make_with_steps(3)
        assert len(s.steps) == 3
        assert s.current_step_index == -1
        assert s.steps[0].tool == "tool_0"
        assert s.steps[2].index == 2

    def test_advance_step(self):
        s = self._make_with_steps(2)
        step = s.advance_step()
        assert step is not None
        assert step.step_id == "step-0"
        assert step.status == StepStatus.RUNNING
        assert s.current_step_index == 0

    def test_advance_through_all_steps(self):
        s = self._make_with_steps(3)
        for i in range(3):
            step = s.advance_step()
            assert step.index == i
        # No more steps
        assert s.advance_step() is None

    def test_current_step(self):
        s = self._make_with_steps(2)
        assert s.current_step is None  # before first advance
        s.advance_step()
        assert s.current_step is not None
        assert s.current_step.step_id == "step-0"

    def test_progress_tracking(self):
        s = self._make_with_steps(4)
        assert s.progress == 0.0
        s.advance_step()
        s.current_step.complete()
        assert s.progress == 0.25
        s.advance_step()
        s.current_step.complete()
        assert s.progress == 0.5

    def test_completed_and_failed_steps(self):
        s = self._make_with_steps(3)
        s.advance_step()
        s.current_step.complete()
        s.advance_step()
        s.current_step.fail("err")
        s.advance_step()
        s.current_step.skip()
        assert len(s.completed_steps) == 1
        assert len(s.failed_steps) == 1
        assert s.progress == pytest.approx(2 / 3, abs=0.01)

    def test_init_steps_with_missing_ids(self):
        s = AgentExecutionState()
        s.init_steps([{"tool": "x"}, {"tool": "y"}])
        assert len(s.steps) == 2
        assert s.steps[0].step_id  # auto-generated UUID
        assert s.steps[1].step_id


# ═══════════════════════════════════════════════════════════════════════════
# AgentExecutionState - Budget
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentExecutionStateBudget:
    def test_consume_budget(self):
        s = AgentExecutionState(total_budget_cents=1000)
        s.consume_budget(300)
        assert s.budget_remaining_cents == 700
        assert s.consumed_cents == 300
        assert s.budget_exhausted is False

    def test_budget_exhausted(self):
        s = AgentExecutionState(total_budget_cents=100)
        s.consume_budget(100)
        assert s.budget_exhausted is True

    def test_budget_remaining_never_negative(self):
        s = AgentExecutionState(total_budget_cents=50)
        s.consume_budget(200)
        assert s.budget_remaining_cents == 0

    def test_zero_budget_not_exhausted(self):
        s = AgentExecutionState(total_budget_cents=0)
        assert s.budget_exhausted is False  # 0 means unlimited


# ═══════════════════════════════════════════════════════════════════════════
# AgentExecutionState - Errors & serialisation
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentExecutionStateErrorsAndDict:
    def test_record_error(self):
        s = AgentExecutionState(agent_id="a")
        s.transition(AgentPhase.INITIALISING)
        s.record_error("something broke")
        assert len(s.error_history) == 1
        assert s.error_history[0]["error"] == "something broke"
        assert s.error_history[0]["phase"] == "initialising"
        assert "timestamp" in s.error_history[0]

    def test_record_error_custom_phase(self):
        s = AgentExecutionState()
        s.record_error("oops", phase="custom_phase")
        assert s.error_history[0]["phase"] == "custom_phase"

    def test_is_terminal(self):
        for phase in [AgentPhase.COMPLETED, AgentPhase.FAILED, AgentPhase.ROLLED_BACK]:
            s = AgentExecutionState(phase=phase)
            assert s.is_terminal is True
        for phase in [AgentPhase.IDLE, AgentPhase.EXECUTING]:
            s = AgentExecutionState(phase=phase)
            assert s.is_terminal is False

    def test_duration_ms(self):
        s = AgentExecutionState()
        assert s.duration_ms is None
        s.transition(AgentPhase.INITIALISING)
        dur = s.duration_ms
        assert dur is not None
        assert dur >= 0

    def test_to_dict_keys(self):
        s = AgentExecutionState(agent_id="a", task="do stuff",
                                total_budget_cents=5000)
        s.init_steps([{"id": "s1", "tool": "t1"}])
        d = s.to_dict()
        expected_keys = {
            "id", "agent_id", "task", "phase", "current_step_index",
            "progress", "total_budget_cents", "consumed_cents",
            "budget_remaining_cents", "duration_ms", "steps",
            "error_history", "is_terminal",
        }
        assert set(d.keys()) == expected_keys
        assert len(d["steps"]) == 1
        assert d["phase"] == "idle"
        assert d["progress"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# AgentStateManager
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentStateManager:
    def test_create_and_get(self):
        mgr = AgentStateManager()
        state = mgr.create("agent-1", task="analyse", budget_cents=2000)
        assert state.agent_id == "agent-1"
        assert state.task == "analyse"
        assert state.total_budget_cents == 2000
        assert mgr.get(state.id) is state

    def test_get_nonexistent(self):
        mgr = AgentStateManager()
        assert mgr.get("nope") is None

    def test_list_all(self):
        mgr = AgentStateManager()
        mgr.create("a1")
        mgr.create("a2")
        assert len(mgr.list_all()) == 2

    def test_list_active(self):
        mgr = AgentStateManager()
        s1 = mgr.create("a1")
        s2 = mgr.create("a2")
        s2.phase = AgentPhase.COMPLETED  # force terminal
        active = mgr.list_active()
        assert len(active) == 1
        assert active[0].id == s1.id

    def test_remove(self):
        mgr = AgentStateManager()
        s = mgr.create("a1")
        assert mgr.remove(s.id) is True
        assert mgr.get(s.id) is None
        assert mgr.remove(s.id) is False


class TestAgentStateManagerCheckpoint:
    def test_checkpoint_and_rollback(self):
        mgr = AgentStateManager()
        state = mgr.create("a1", task="t", budget_cents=1000)
        state.transition(AgentPhase.INITIALISING)
        state.transition(AgentPhase.PLANNING)

        # Checkpoint at PLANNING
        cp = mgr.checkpoint(state.id)

        # Advance further
        state.transition(AgentPhase.VERIFYING_PLAN)
        state.transition(AgentPhase.EXECUTING)
        state.consume_budget(500)
        assert state.phase == AgentPhase.EXECUTING
        assert state.consumed_cents == 500

        # Rollback
        restored = mgr.rollback(state.id, cp)
        assert restored.phase == AgentPhase.PLANNING
        assert restored.consumed_cents == 0

        # The manager's get() also returns the restored state
        assert mgr.get(state.id).phase == AgentPhase.PLANNING

    def test_rollback_preserves_id(self):
        mgr = AgentStateManager()
        state = mgr.create("a1")
        cp = mgr.checkpoint(state.id)
        state.phase = AgentPhase.COMPLETED
        restored = mgr.rollback(state.id, cp)
        assert restored.id == state.id

    def test_multiple_checkpoints(self):
        mgr = AgentStateManager()
        state = mgr.create("a1")
        state.transition(AgentPhase.INITIALISING)
        cp1 = mgr.checkpoint(state.id)

        state.transition(AgentPhase.PLANNING)
        cp2 = mgr.checkpoint(state.id)

        state.transition(AgentPhase.VERIFYING_PLAN)

        # Rollback to cp1 (earlier)
        restored = mgr.rollback(state.id, cp1)
        assert restored.phase == AgentPhase.INITIALISING

    def test_list_checkpoints(self):
        mgr = AgentStateManager()
        state = mgr.create("a1")
        cp1 = mgr.checkpoint(state.id)
        cp2 = mgr.checkpoint(state.id)
        cps = mgr.list_checkpoints(state.id)
        assert cp1 in cps
        assert cp2 in cps

    def test_discard_checkpoints(self):
        mgr = AgentStateManager()
        state = mgr.create("a1")
        mgr.checkpoint(state.id)
        mgr.checkpoint(state.id)
        count = mgr.discard_checkpoints(state.id)
        assert count == 2
        assert mgr.list_checkpoints(state.id) == []

    def test_checkpoint_nonexistent_state_raises(self):
        mgr = AgentStateManager()
        with pytest.raises(KeyError):
            mgr.checkpoint("missing")

    def test_rollback_bad_checkpoint_raises(self):
        mgr = AgentStateManager()
        state = mgr.create("a1")
        with pytest.raises(KeyError):
            mgr.rollback(state.id, "fake-cp")

    def test_checkpoint_is_deep_copy(self):
        """Mutating state after checkpoint must not affect the snapshot."""
        mgr = AgentStateManager()
        state = mgr.create("a1", budget_cents=1000)
        state.init_steps([{"id": "s1", "tool": "t"}])
        cp = mgr.checkpoint(state.id)

        # Mutate
        state.consume_budget(999)
        state.advance_step()
        state.current_step.complete(output="done")

        # Rollback: snapshot should be pristine
        restored = mgr.rollback(state.id, cp)
        assert restored.consumed_cents == 0
        assert restored.steps[0].status == StepStatus.PENDING


class TestAgentStateManagerObserver:
    def test_observer_called_on_create(self):
        events = []
        mgr = AgentStateManager()
        mgr.add_observer(lambda s, e: events.append(e))
        mgr.create("a1")
        assert "created" in events

    def test_observer_called_on_checkpoint_and_rollback(self):
        events = []
        mgr = AgentStateManager()
        mgr.add_observer(lambda s, e: events.append(e))
        state = mgr.create("a1")
        cp = mgr.checkpoint(state.id)
        mgr.rollback(state.id, cp)
        assert events == ["created", "checkpoint", "rollback"]

    def test_remove_observer(self):
        events = []
        cb = lambda s, e: events.append(e)
        mgr = AgentStateManager()
        mgr.add_observer(cb)
        mgr.create("a1")
        mgr.remove_observer(cb)
        mgr.create("a2")
        assert len(events) == 1  # only first create

    def test_observer_exception_does_not_propagate(self):
        """A failing observer must not break the state machine."""
        def bad_observer(s, e):
            raise RuntimeError("boom")

        mgr = AgentStateManager()
        mgr.add_observer(bad_observer)
        # Should not raise
        state = mgr.create("a1")
        assert state.agent_id == "a1"
