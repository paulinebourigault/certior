/* ──────────────────────────────────────────────────────────────
   ExecutionViewer - real-time execution tracker.
   Connects via WebSocket, shows step progress, verification
   status, and provides cancel / compliance-export actions.
   ────────────────────────────────────────────────────────────── */

import { useCallback, useState } from "react";
import type { Execution, ExecutionStatus } from "@/lib/types";
import { useExecution } from "@/lib/hooks";
import * as api from "@/lib/api";
import VerificationBadge from "./VerificationBadge";
import RealTimeLog from "./RealTimeLog";
import { useToast } from "./Toast";

interface Props {
  executionId: string;
  onClose?: () => void;
}

/* ── Status styling ── */

const STATUS_META: Record<ExecutionStatus, { label: string; color: string; icon: string }> = {
  queued:    { label: "Queued",     color: "text-gray-400",    icon: "◻" },
  planning:  { label: "Planning",   color: "text-accent",      icon: "◈" },
  executing: { label: "Executing",  color: "text-accent-glow", icon: "▸" },
  verifying: { label: "Verifying",  color: "text-verified",    icon: "⊢" },
  completed: { label: "Completed",  color: "text-verified",    icon: "✓" },
  failed:    { label: "Failed",     color: "text-blocked",     icon: "✗" },
  cancelled: { label: "Cancelled",  color: "text-gray-500",    icon: "⊘" },
};

function StatusPill({ status }: { status: ExecutionStatus }) {
  const meta = STATUS_META[status] ?? STATUS_META.queued;
  return (
    <span className={`badge border border-current/20 ${meta.color}`} role="status">
      <span className="text-[11px]" aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}

/* ── Progress bar ── */

function ProgressBar({ execution }: { execution: Execution }) {
  const isTerminal = ["completed", "failed", "cancelled"].includes(execution.status);
  const progress = isTerminal
    ? 100
    : execution.status === "queued"
      ? 0
      : Math.max(5, Math.min(95, (execution.current_step + 1) * 20));

  const barColor =
    execution.status === "failed" || execution.status === "cancelled"
      ? "bg-blocked"
      : execution.status === "completed"
        ? "bg-verified"
        : "bg-accent";

  return (
    <div className="h-1 w-full rounded-full bg-base-700 overflow-hidden" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
      <div
        className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
        style={{ width: `${progress}%` }}
      />
    </div>
  );
}

/* ── Elapsed time formatting - timestamps are epoch seconds ── */

function formatElapsed(execution: Execution): string | null {
  const now = Date.now() / 1000; // current time in epoch seconds
  const start = execution.created_at;
  if (!start) return null;

  const end = execution.completed_at ?? now;
  const elapsedSec = Math.max(0, end - start);

  if (elapsedSec < 0.1) return null;
  if (elapsedSec < 1) return `${Math.round(elapsedSec * 1000)}ms`;
  if (elapsedSec < 60) return `${elapsedSec.toFixed(1)}s`;
  if (elapsedSec < 3600) return `${Math.floor(elapsedSec / 60)}m ${Math.floor(elapsedSec % 60)}s`;
  return `${Math.floor(elapsedSec / 3600)}h ${Math.floor((elapsedSec % 3600) / 60)}m`;
}

/* ── Main component ── */

export default function ExecutionViewer({ executionId, onClose }: Props) {
  const { execution, events, connected } = useExecution(executionId);
  const [cancelling, setCancelling] = useState(false);
  const { toast } = useToast();

  const handleCancel = useCallback(async () => {
    setCancelling(true);
    try {
      await api.cancelExecution(executionId);
      toast("info", "Execution cancelled");
    } catch (e) {
      toast("error", e instanceof api.ApiError ? e.message : "Cancel failed");
    } finally {
      setCancelling(false);
    }
  }, [executionId, toast]);

  if (!execution) {
    return (
      <div className="card p-8 flex items-center justify-center" role="status" aria-label="Loading execution">
        <div className="flex items-center gap-3 text-slate-500 text-sm">
          <svg className="h-5 w-5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <circle cx="12" cy="12" r="10" strokeDasharray="60" strokeDashoffset="20" />
          </svg>
          Loading execution…
        </div>
      </div>
    );
  }

  const isTerminal = ["completed", "failed", "cancelled"].includes(execution.status);
  const elapsed = formatElapsed(execution);

  return (
    <div className="card overflow-hidden animate-fade-in">
      {/* Header */}
      <div className="border-b border-base-700/60 p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2.5 mb-1.5">
              <StatusPill status={execution.status} />
              {connected && !isTerminal && (
                <span className="flex items-center gap-1 text-[10px] text-verified/60">
                  <span className="h-1.5 w-1.5 rounded-full bg-verified animate-pulse" aria-hidden="true" />
                  Live
                </span>
              )}
            </div>
            <p className="text-sm text-slate-800 leading-snug truncate">
              {execution.task}
            </p>
            <p className="mono text-slate-500 mt-1">
              {executionId.slice(0, 8)}
              {elapsed && <>, {elapsed}</>}
              {execution.cost_cents > 0 && <>, ${(execution.cost_cents / 100).toFixed(2)}</>}
            </p>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            {!isTerminal && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="btn-ghost text-xs text-blocked/80 hover:text-blocked"
                aria-label="Cancel execution"
              >
                {cancelling ? "Cancelling…" : "Cancel"}
              </button>
            )}
            {onClose && (
              <button onClick={onClose} className="btn-ghost text-xs" aria-label="Close execution viewer">
                ✕
              </button>
            )}
          </div>
        </div>

        <div className="mt-3">
          <ProgressBar execution={execution} />
        </div>
      </div>

      {/* Verification status */}
      {(execution.status === "completed" || execution.certificate_count > 0) && (
        <div className="border-b border-base-700/60 p-4">
          <VerificationBadge
            certificateCount={execution.certificate_count}
            status={execution.status === "completed" ? "verified" : "pending"}
            proofProperties={execution.proof_properties ?? []}
          />
        </div>
      )}

      {/* Agent output */}
      {execution.output && (
        <div className="border-b border-base-700/60 p-5">
          <p className="text-[11px] uppercase tracking-widest text-slate-500 font-medium mb-2">Output</p>
          <div className="rounded-lg bg-white/85 border border-base-700/40 p-4">
            <p className="text-sm text-slate-700 leading-relaxed whitespace-pre-wrap">{execution.output}</p>
          </div>
          {execution.verification_summary && (
            <div className="flex gap-3 mt-2 text-[11px] text-slate-500">
              <span>{execution.verification_summary.steps} verified steps</span>
              {execution.verification_summary.duration_ms && (
                <span>· {(execution.verification_summary.duration_ms / 1000).toFixed(1)}s</span>
              )}
              <span>· {execution.verification_summary.total_input_tokens + execution.verification_summary.total_output_tokens} tokens</span>
            </div>
          )}
        </div>
      )}

      {/* Real-time event log */}
      <div className="max-h-64 overflow-y-auto">
        <RealTimeLog events={events} status={execution.status} />
      </div>

      {/* Footer with error */}
      {execution.error && (
        <div className="border-t border-blocked/20 bg-blocked-bg p-4" role="alert">
          <p className="text-xs font-medium text-blocked mb-1">Error</p>
          <p className="mono text-slate-700">{execution.error}</p>
        </div>
      )}
    </div>
  );
}
