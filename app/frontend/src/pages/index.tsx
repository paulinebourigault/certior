/* ──────────────────────────────────────────────────────────────
  Dashboard - task submission and recent execution activity.
  ────────────────────────────────────────────────────────────── */

import Head from "next/head";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import type { Execution, ExecutionStatus, Workflow } from "@/lib/types";
import { usePolling, useRuntimeLLMSetup } from "@/lib/hooks";
import * as api from "@/lib/api";
import TaskInput from "@/components/TaskInput";
import WorkflowInput from "@/components/WorkflowInput";
import ExecutionViewer from "@/components/ExecutionViewer";
import WorkflowViewer from "@/components/WorkflowViewer";
import VerificationBadge from "@/components/VerificationBadge";
import ErrorBoundary from "@/components/ErrorBoundary";
import LLMSetupDialog from "@/components/LLMSetupDialog";
import BrandMark from "@/components/BrandMark";

/* ── Status helpers ── */

const STATUS_DOTS: Record<ExecutionStatus, string> = {
  queued:    "bg-gray-500",
  planning:  "bg-accent",
  executing: "bg-accent-glow animate-pulse",
  verifying: "bg-verified animate-pulse",
  completed: "bg-verified",
  failed:    "bg-blocked",
  cancelled: "bg-gray-600",
};

function timeAgo(ts: number): string {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60)   return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function DashboardPage() {
  const router = useRouter();
  const { setup, save, clear } = useRuntimeLLMSetup();
  const [runMode, setRunMode] = useState<"single" | "workflow">("single");
  const [activeExecution, setActiveExecution] = useState<string | null>(null);
  const [activeWorkflow, setActiveWorkflow] = useState<string | null>(null);
  const [setupOpen, setSetupOpen] = useState(false);
  const [setupSavedAt, setSetupSavedAt] = useState<number | null>(setup?.validatedAt ?? null);

  const fetchRecent = useCallback(() => api.listExecutions(undefined, 15), []);
  const fetchWorkflows = useCallback(() => api.listWorkflows(undefined, 10), []);
  const { data: executions, loading } = usePolling<Execution[]>(fetchRecent, 5000);
  const { data: workflows } = usePolling<Workflow[]>(fetchWorkflows, 5000);

  const handleSubmitted = (executionId: string) => {
    setRunMode("single");
    setActiveExecution(executionId);
  };

  const handleWorkflowSubmitted = (workflowId: string) => {
    setRunMode("workflow");
    setActiveWorkflow(workflowId);
  };

  useEffect(() => {
    if (router.query.mode === "workflow") {
      setRunMode("workflow");
    } else if (router.query.mode === "single") {
      setRunMode("single");
    }
  }, [router.query.mode]);

  useEffect(() => {
    if (!setup?.valid || !setup.apiKey) {
      setSetupOpen(true);
    }
  }, [setup]);

  // Quick stats
  const stats = executions
    ? {
        total: executions.length,
        completed: executions.filter((e) => e.status === "completed").length,
        active: executions.filter((e) => ["queued", "planning", "executing", "verifying"].includes(e.status)).length,
        failed: executions.filter((e) => e.status === "failed").length,
      }
    : null;

  return (
    <>
      <Head>
        <title>Certior Studio - Dashboard</title>
      </Head>

      <LLMSetupDialog
        open={setupOpen}
        initialSetup={setup}
        onClose={setup?.valid ? () => setSetupOpen(false) : undefined}
        onSaved={(next) => {
          save(next);
          setSetupSavedAt(Date.now());
          setSetupOpen(false);
        }}
      />

      <div className="p-6 lg:p-8 max-w-6xl mx-auto space-y-8">
        <div className="hero-band rounded-[34px] border border-base-700/60 px-6 py-6 shadow-sm lg:px-8 lg:py-8">
          <div className="grid gap-6 lg:grid-cols-[1.2fr_0.78fr] lg:items-start">
            <div className="space-y-5">
              <BrandMark size={60} variant="editorial" subtitle="verified agentic operations" />
              <div className="space-y-3">
                <h1 className="max-w-2xl text-4xl font-semibold font-display leading-tight text-slate-900 lg:text-[3.2rem]">
                  CERTIOR studio for verified agentic operations.
                </h1>
                <p className="max-w-2xl text-base leading-7 text-slate-600">
                  Start runs, stage workflows, inspect evidence, and export verified output from one place.
                </p>
              </div>

              <div className="flex flex-wrap gap-3">
                <button onClick={() => setRunMode("single")} className="btn-primary px-5 py-3 text-sm">
                  Start single run
                </button>
                <button onClick={() => setRunMode("workflow")} className="btn-ghost border border-base-700/60 px-5 py-3 text-sm">
                  Build workflow
                </button>
                <Link href="/examples" className="btn-ghost border border-base-700/60 px-5 py-3 text-sm">
                  Open examples
                </Link>
              </div>
            </div>

            <div className="panel-warm rounded-[28px] p-5 lg:p-6 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="label mb-2">Model</p>
                  <p className="text-lg font-display text-slate-900">{setup?.valid ? `${setup.provider}, ${setup.model}` : "Setup required"}</p>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    {setup?.valid ? "Validated in this browser session." : "Choose a provider, model, and key before submitting runs."}
                  </p>
                </div>
                <span className={`badge border px-2.5 py-1 ${setup?.valid ? "border-verified/20 bg-verified-bg text-verified" : "border-warn/20 bg-warn-bg text-warn"}`}>
                  {setup?.valid ? "Ready" : "Pending"}
                </span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <button onClick={() => setSetupOpen(true)} className="btn-primary w-full px-4 py-3 text-sm">
                  {setup?.valid ? "Change setup" : "Set up model"}
                </button>
                {setup?.valid ? (
                  <button onClick={() => { clear(); setSetupOpen(true); }} className="btn-ghost w-full border border-base-700/60 px-4 py-3 text-sm text-blocked hover:text-blocked">
                    Clear setup
                  </button>
                ) : (
                  <Link href="/settings" className="btn-ghost w-full border border-base-700/60 px-4 py-3 text-sm">
                    Open settings
                  </Link>
                )}
              </div>

              {setup?.valid && setupSavedAt && (
                <div className="rounded-2xl border border-verified/20 bg-verified-bg px-4 py-3 text-sm text-verified">
                  <p className="font-medium">Model setup saved</p>
                  <p className="mt-1 text-xs">Ready for new runs in this browser session.</p>
                </div>
              )}

              <div className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-4">
                <p className="label mb-2">What you can do here</p>
                <p className="text-sm leading-6 text-slate-600">Submit one-off tasks, assemble staged handoffs, inspect live execution output, and export compliance evidence after completion.</p>
              </div>
            </div>
          </div>
        </div>

        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Total", value: stats.total, color: "text-slate-700", note: "All recorded runs" },
              { label: "Verified", value: stats.completed, color: "text-verified", note: "Completed with evidence" },
              { label: "Active", value: stats.active, color: "text-accent", note: "Still running or checking" },
              { label: "Failed", value: stats.failed, color: "text-blocked", note: "Needs another pass" },
            ].map((s) => (
              <div key={s.label} className="panel-warm rounded-[24px] p-4">
                <p className="text-xs text-slate-500 uppercase tracking-wider">{s.label}</p>
                <p className={`text-2xl font-semibold font-display mt-1 ${s.color}`}>{s.value}</p>
                <p className="mt-2 text-xs leading-5 text-slate-500">{s.note}</p>
              </div>
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Left: Task input + active viewer */}
          <div className="lg:col-span-2 space-y-6">
            <div className="inline-flex rounded-2xl border border-base-700/60 bg-white/78 p-1 shadow-sm">
              {[
                { id: "single", label: "Single Run" },
                { id: "workflow", label: "Workflow Run" },
              ].map((mode) => (
                <button
                  key={mode.id}
                  onClick={() => setRunMode(mode.id as "single" | "workflow")}
                  className={`rounded-lg px-4 py-2 text-sm transition-colors ${
                    runMode === mode.id
                      ? "bg-accent-bg text-slate-800"
                      : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {mode.label}
                </button>
              ))}
            </div>

            {runMode === "single" ? (
              <TaskInput onSubmitted={handleSubmitted} runtimeSetup={setup} />
            ) : (
              <WorkflowInput onSubmitted={handleWorkflowSubmitted} runtimeSetup={setup} />
            )}

            {activeWorkflow && (
              <ErrorBoundary>
                <WorkflowViewer
                  workflowId={activeWorkflow}
                  onClose={() => setActiveWorkflow(null)}
                  onOpenExecution={(executionId) => setActiveExecution(executionId)}
                />
              </ErrorBoundary>
            )}

            {activeExecution && (
              <ErrorBoundary>
                <ExecutionViewer
                  executionId={activeExecution}
                  onClose={() => setActiveExecution(null)}
                />
              </ErrorBoundary>
            )}
          </div>

          {/* Right: Recent executions */}
          <div className="lg:col-span-3 space-y-3">
            {workflows && workflows.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-medium text-slate-700">Recent Workflows</h2>
                  <span className="text-xs text-slate-500">Sequential</span>
                </div>
                <div className="space-y-2">
                  {workflows.map((workflow) => (
                    <button
                      key={workflow.id}
                      onClick={() => {
                        setRunMode("workflow");
                        setActiveWorkflow(workflow.id);
                      }}
                      className={`panel-warm rounded-[24px] w-full text-left p-4 transition-colors ${
                        activeWorkflow === workflow.id ? "border-accent/40 bg-accent-bg" : ""
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm text-slate-800 truncate">{workflow.name}</p>
                          <p className="text-xs text-slate-500 mt-1">
                            {workflow.completed_stage_count}/{workflow.stage_count} stages complete, {timeAgo(workflow.created_at)}
                          </p>
                        </div>
                        <span className="badge bg-white/70 text-slate-600 border border-base-600/40 capitalize">
                          {workflow.status}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {workflows && workflows.length === 0 && (
              <div className="panel-warm rounded-[24px] p-6 text-sm text-slate-600">
                <p className="font-medium text-slate-900">No workflows yet</p>
                <p className="mt-2 leading-6">Use workflow mode when the task needs drafting, review, and release as separate verified stages.</p>
              </div>
            )}

            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-700">Recent Executions</h2>
              <Link href="/tasks" className="text-xs text-accent-dim hover:text-accent transition-colors">
                View all →
              </Link>
            </div>

            {loading && !executions && (
              <div className="panel-warm rounded-[24px] p-8 text-center text-sm text-slate-500">Loading…</div>
            )}

            {executions && executions.length === 0 && (
              <div className="panel-warm rounded-[24px] p-8 text-center text-sm text-slate-500 space-y-3">
                <p className="text-base font-display text-slate-900">No executions yet</p>
                <p>Start with a single run for one-off work, or switch to workflow mode for staged handoffs.</p>
                <div className="flex flex-wrap items-center justify-center gap-3">
                  <button onClick={() => setRunMode("single")} className="btn-primary px-4 py-2 text-sm">
                    Start single run
                  </button>
                  <button onClick={() => setRunMode("workflow")} className="btn-ghost border border-base-700/60 px-4 py-2 text-sm">
                    Build workflow
                  </button>
                </div>
              </div>
            )}

            {executions && executions.length > 0 && (
              <div className="space-y-2">
                {executions.map((ex) => (
                  <button
                    key={ex.id}
                    onClick={() => setActiveExecution(ex.id)}
                    className={`panel-warm rounded-[24px] w-full text-left p-4 transition-colors ${
                      activeExecution === ex.id ? "border-accent/40 bg-accent-bg" : ""
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className={`h-2 w-2 rounded-full flex-shrink-0 ${STATUS_DOTS[ex.status]}`} />

                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-slate-800 truncate">{ex.task}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="mono text-slate-500">{ex.id.slice(0, 8)}</span>
                          <span className="text-slate-400">·</span>
                          <span className="text-xs text-slate-500">{timeAgo(ex.created_at)}</span>
                          {ex.cost_cents > 0 && (
                            <>
                              <span className="text-slate-400">·</span>
                              <span className="text-xs text-slate-500">${(ex.cost_cents / 100).toFixed(2)}</span>
                            </>
                          )}
                        </div>
                      </div>

                      {ex.status === "completed" && ex.certificate_count > 0 && (
                        <VerificationBadge
                          certificateCount={ex.certificate_count}
                          status="verified"
                          compact
                        />
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
