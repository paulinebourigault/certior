/* ──────────────────────────────────────────────────────────────
   Executions - browse, filter, and inspect executions.
   Two-panel layout on desktop; bottom-sheet detail on mobile.
   ────────────────────────────────────────────────────────────── */

import Head from "next/head";
import { useCallback, useState } from "react";
import type { Execution, ExecutionStatus } from "@/lib/types";
import { usePolling } from "@/lib/hooks";
import * as api from "@/lib/api";
import ExecutionViewer from "@/components/ExecutionViewer";
import ComplianceDashboard from "@/components/ComplianceDashboard";
import ErrorBoundary from "@/components/ErrorBoundary";

/* ── Filter chip ── */

const FILTERS: { value: ExecutionStatus | "all"; label: string }[] = [
  { value: "all",       label: "All" },
  { value: "queued",    label: "Queued" },
  { value: "executing", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed",    label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

const STATUS_COLOR: Record<ExecutionStatus, string> = {
  queued:    "text-gray-400",
  planning:  "text-accent",
  executing: "text-accent-glow",
  verifying: "text-verified",
  completed: "text-verified",
  failed:    "text-blocked",
  cancelled: "text-gray-500",
};

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleString("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
  });
}

export default function TasksPage() {
  const [filter, setFilter] = useState<ExecutionStatus | "all">("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [showCompliance, setShowCompliance] = useState(false);

  const fetchExecs = useCallback(
    () => api.listExecutions(filter === "all" ? undefined : filter, 50),
    [filter],
  );
  const { data: executions, loading } = usePolling<Execution[]>(fetchExecs, 5000);

  return (
    <>
      <Head>
        <title>Certior Studio - Executions</title>
      </Head>

      <div className="flex h-full flex-col lg:flex-row p-6 lg:p-8 gap-6">
        <div className={`w-full lg:w-[420px] flex-shrink-0 panel-warm rounded-[28px] flex flex-col ${selected ? "hidden lg:flex" : "flex"}`}>
          <div className="p-5 border-b border-base-700/40 space-y-3">
            <div className="space-y-2">
              <p className="label">Execution log</p>
              <h1 className="text-2xl font-semibold font-display text-slate-900">Executions</h1>
              <p className="text-sm leading-6 text-slate-600">Filter runs, inspect output, and switch into the compliance export view when a run completes.</p>
            </div>
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter executions by status">
              {FILTERS.map((f) => (
                <button
                  key={f.value}
                  onClick={() => { setFilter(f.value); setSelected(null); }}
                  className={`badge cursor-pointer transition-colors ${
                    filter === f.value
                      ? "bg-accent-bg text-accent border border-accent/20"
                      : "bg-white/70 text-slate-600 border border-base-600/30 hover:text-slate-800"
                  }`}
                  aria-pressed={filter === f.value}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {loading && !executions && (
              <div className="p-8 text-center text-sm text-slate-500" role="status">Loading…</div>
            )}

            {executions && executions.length === 0 && (
              <div className="p-8 text-center text-sm text-slate-500">
                No executions match the filter.
              </div>
            )}

            {executions?.map((ex) => (
              <button
                key={ex.id}
                onClick={() => { setSelected(ex.id); setShowCompliance(false); }}
                className={`w-full text-left p-4 border-b border-base-700/30 transition-colors ${
                  selected === ex.id
                    ? "bg-accent-bg border-l-2 border-l-accent"
                    : "hover:bg-white/68 border-l-2 border-l-transparent"
                }`}
                aria-current={selected === ex.id ? "true" : undefined}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm text-slate-800 truncate flex-1">{ex.task}</p>
                  <span className={`text-[11px] font-medium ${STATUS_COLOR[ex.status]}`}>
                    {ex.status}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="mono text-slate-500">{ex.id.slice(0, 8)}</span>
                  <span className="text-slate-400">·</span>
                  <span className="text-xs text-slate-500">{formatDate(ex.created_at)}</span>
                  {ex.certificate_count > 0 && (
                    <>
                      <span className="text-slate-400">·</span>
                      <span className="text-xs text-verified/70">
                        {ex.certificate_count} cert{ex.certificate_count !== 1 ? "s" : ""}
                      </span>
                    </>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className={`flex-1 panel-warm rounded-[28px] flex flex-col overflow-y-auto ${selected ? "flex" : "hidden lg:flex"}`}>
          {!selected && (
            <div className="flex-1 flex items-center justify-center text-sm text-slate-500">
              <div className="text-center space-y-2">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} className="h-12 w-12 mx-auto text-slate-400" aria-hidden="true">
                  <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
                  <rect x="9" y="3" width="6" height="4" rx="1" />
                </svg>
                <p>Select an execution to view details</p>
              </div>
            </div>
          )}

          {selected && (
            <div className="p-4 lg:p-6 space-y-6">
              <button
                onClick={() => setSelected(null)}
                className="lg:hidden btn-ghost text-xs mb-2"
                aria-label="Back to execution list"
              >
                ← Back to list
              </button>

              <div className="flex rounded-lg bg-base-800 p-0.5 w-fit" role="tablist" aria-label="View mode">
                <button
                  role="tab"
                  aria-selected={!showCompliance}
                  onClick={() => setShowCompliance(false)}
                  className={`rounded-md px-4 py-1.5 text-xs font-medium transition-colors ${
                    !showCompliance ? "bg-white text-slate-800" : "text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Execution
                </button>
                <button
                  role="tab"
                  aria-selected={showCompliance}
                  onClick={() => setShowCompliance(true)}
                  className={`rounded-md px-4 py-1.5 text-xs font-medium transition-colors ${
                    showCompliance ? "bg-white text-slate-800" : "text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Compliance
                </button>
              </div>

              <ErrorBoundary>
                {showCompliance ? (
                  <ComplianceDashboard executionId={selected} />
                ) : (
                  <ExecutionViewer executionId={selected} />
                )}
              </ErrorBoundary>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
