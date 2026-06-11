import { useCallback } from "react";
import { usePolling } from "@/lib/hooks";
import * as api from "@/lib/api";
import type { Workflow } from "@/lib/types";

interface Props {
  workflowId: string;
  onClose: () => void;
  onOpenExecution?: (executionId: string) => void;
}

const WORKFLOW_TONES: Record<string, string> = {
  queued: "bg-base-700/50 text-gray-300 border-base-600/30",
  running: "bg-accent-bg text-accent border-accent/20",
  completed: "bg-verified-bg text-verified border-verified/20",
  failed: "bg-blocked-bg text-blocked border-blocked/20",
  cancelled: "bg-base-700/50 text-gray-400 border-base-600/30",
};

const STAGE_DOTS: Record<string, string> = {
  pending: "bg-gray-500",
  running: "bg-accent animate-pulse",
  completed: "bg-verified",
  failed: "bg-blocked",
  blocked: "bg-warn",
  cancelled: "bg-gray-600",
};

export default function WorkflowViewer({ workflowId, onClose, onOpenExecution }: Props) {
  const fetchWorkflow = useCallback(() => api.getWorkflow(workflowId), [workflowId]);
  const { data: workflow, loading } = usePolling<Workflow>(fetchWorkflow, 4000, !!workflowId);

  if (loading && !workflow) {
    return <div className="card p-6 text-sm text-gray-500">Loading workflow…</div>;
  }
  if (!workflow) return null;

  return (
    <div className="card p-6 space-y-5 animate-fade-in">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-gray-500 font-medium">Workflow</p>
          <h3 className="text-lg font-display text-gray-100 mt-1">{workflow.name}</h3>
          <p className="text-xs text-gray-500 mt-1">{workflow.description || "Sequential verified workflow"}</p>
        </div>
        <button onClick={onClose} className="btn-ghost text-xs px-3 py-2">Close</button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`badge border ${WORKFLOW_TONES[workflow.status] ?? WORKFLOW_TONES.queued}`}>{workflow.status}</span>
        <span className="text-gray-500">{workflow.completed_stage_count}/{workflow.stage_count} stages complete</span>
        <span className="mono text-gray-600">{workflow.id.slice(0, 8)}</span>
      </div>

      <div className="space-y-3">
        {workflow.stages.map((stage, index) => (
          <div key={stage.id} className="rounded-xl border border-base-700/40 bg-base-900/50 p-4 space-y-2">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${STAGE_DOTS[stage.status] ?? STAGE_DOTS.pending}`} />
                <p className="text-sm font-medium text-gray-200">{index + 1}. {stage.name}</p>
              </div>
              <span className="text-xs text-gray-500">{stage.stage_role}</span>
            </div>
            <p className="text-xs text-gray-500 leading-relaxed">{stage.task}</p>
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-gray-500">
              <span className="badge bg-base-700/40 text-gray-300 border border-base-600/30">{stage.compliance_policy}</span>
              <span>${(stage.budget_cents / 100).toFixed(0)}</span>
              {stage.execution_id && (
                <button
                  onClick={() => onOpenExecution?.(stage.execution_id as string)}
                  className="mono text-accent hover:text-accent-glow transition-colors"
                >
                  {stage.execution_id.slice(0, 8)}
                </button>
              )}
            </div>
            {stage.output_summary && <p className="text-xs text-gray-400">{stage.output_summary}</p>}
            {stage.error && <p className="text-xs text-blocked">{stage.error}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}