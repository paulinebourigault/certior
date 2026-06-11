import Head from "next/head";
import { useCallback, useState } from "react";
import * as api from "@/lib/api";
import type { Workflow } from "@/lib/types";
import { usePolling } from "@/lib/hooks";
import ExecutionViewer from "@/components/ExecutionViewer";
import WorkflowViewer from "@/components/WorkflowViewer";
import { useToast } from "@/components/Toast";

function timeAgo(ts: number): string {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function latestExecutionId(workflow: Workflow): string | null {
  for (let index = workflow.stages.length - 1; index >= 0; index -= 1) {
    const executionId = workflow.stages[index]?.execution_id;
    if (executionId) return executionId;
  }
  return null;
}

export default function WorkflowsPage() {
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const { toast } = useToast();
  const fetchWorkflows = useCallback(() => api.listWorkflows(undefined, 25), []);
  const { data: workflows, loading } = usePolling<Workflow[]>(fetchWorkflows, 4000);

  const selectedWorkflow = workflows?.find((workflow) => workflow.id === selectedWorkflowId) ?? workflows?.[0] ?? null;

  const handleCancel = useCallback(async () => {
    if (!selectedWorkflow) return;
    setWorking(true);
    try {
      await api.cancelWorkflow(selectedWorkflow.id);
      toast("info", "Workflow cancelled");
    } catch (error) {
      toast("error", error instanceof api.ApiError ? error.message : "Workflow cancel failed");
    } finally {
      setWorking(false);
    }
  }, [selectedWorkflow, toast]);

  const handleExport = useCallback(async () => {
    if (!selectedWorkflow) return;
    setWorking(true);
    try {
      await api.downloadWorkflowExport(selectedWorkflow.id);
      toast("success", "Workflow export downloaded");
    } catch (error) {
      toast("error", error instanceof api.ApiError ? error.message : "Workflow export failed");
    } finally {
      setWorking(false);
    }
  }, [selectedWorkflow, toast]);

  return (
    <>
      <Head>
        <title>Certior Studio - Workflows</title>
      </Head>

      <div className="p-6 lg:p-8 max-w-6xl mx-auto space-y-8">
        <div className="hero-band rounded-[30px] border border-base-700/60 px-6 py-6 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="label mb-2">Staged runs</p>
              <h1 className="text-3xl font-semibold font-display text-slate-900">Workflows</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Track stage progress, inspect the latest execution in a chain, cancel active work, and export the combined evidence package.</p>
            </div>
            <div className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-3 text-sm text-slate-600">
              <p className="font-medium text-slate-900">Sequential orchestration</p>
              <p className="mt-1 text-xs">Each stage reuses the same verified execution path.</p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-slate-700">Workflow Queue</h2>
              <span className="text-xs text-slate-500">Recent runs</span>
            </div>

            {loading && !workflows && (
              <div className="panel-warm rounded-[24px] p-8 text-center text-sm text-slate-500">Loading workflows…</div>
            )}

            {workflows && workflows.length === 0 && (
              <div className="panel-warm rounded-[24px] p-8 text-center text-sm text-slate-500">No workflows yet. Start one from the dashboard.</div>
            )}

            {workflows?.map((workflow) => (
              <div
                key={workflow.id}
                className={`panel-warm rounded-[24px] p-4 transition-colors ${selectedWorkflow?.id === workflow.id ? "border-accent/40 bg-accent-bg" : ""}`}
              >
                <button
                  onClick={() => {
                    setSelectedWorkflowId(workflow.id);
                    setSelectedExecutionId(null);
                  }}
                  className="w-full text-left"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm text-slate-800 truncate">{workflow.name}</p>
                      <p className="text-xs text-slate-500 mt-1">{workflow.completed_stage_count}/{workflow.stage_count} stages complete, {timeAgo(workflow.created_at)}</p>
                    </div>
                    <span className="badge bg-white/70 text-slate-600 border border-base-600/30 capitalize">{workflow.status}</span>
                  </div>
                </button>
                {latestExecutionId(workflow) && (
                  <div className="mt-3 flex items-center justify-between gap-3 border-t border-base-700/40 pt-3">
                    <span className="text-[11px] text-slate-500">Latest execution</span>
                    <button
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedWorkflowId(workflow.id);
                        setSelectedExecutionId(latestExecutionId(workflow));
                      }}
                      className="mono text-xs text-accent hover:text-accent-glow transition-colors"
                    >
                      Open {latestExecutionId(workflow)?.slice(0, 8)}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="lg:col-span-3 space-y-4">
            {selectedWorkflow ? (
              <>
                <div className="flex flex-wrap gap-3 justify-end">
                  <button onClick={handleExport} disabled={working} className="btn-ghost border border-base-700/60 text-xs px-3 py-2">
                    {working ? "Working…" : "Export Workflow JSON"}
                  </button>
                  {selectedWorkflow.status === "queued" || selectedWorkflow.status === "running" ? (
                    <button onClick={handleCancel} disabled={working} className="btn-danger text-xs px-3 py-2">
                      {working ? "Working…" : "Cancel Workflow"}
                    </button>
                  ) : null}
                </div>
                <WorkflowViewer
                  workflowId={selectedWorkflow.id}
                  onClose={() => {
                    setSelectedWorkflowId(null);
                    setSelectedExecutionId(null);
                  }}
                  onOpenExecution={(executionId) => setSelectedExecutionId(executionId)}
                />
                {selectedExecutionId && (
                  <ExecutionViewer
                    executionId={selectedExecutionId}
                    onClose={() => setSelectedExecutionId(null)}
                  />
                )}
              </>
            ) : (
              <div className="panel-warm rounded-[24px] p-8 text-center text-sm text-slate-500">Select a workflow to inspect its stages and evidence.</div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}