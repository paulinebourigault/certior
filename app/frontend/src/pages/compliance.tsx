/* ──────────────────────────────────────────────────────────────
   Compliance - browse presets, select executions, export packages.
   ────────────────────────────────────────────────────────────── */

import Head from "next/head";
import { useEffect, useState } from "react";
import type { CompliancePreset, Execution } from "@/lib/types";
import * as api from "@/lib/api";
import ComplianceDashboard from "@/components/ComplianceDashboard";
import ErrorBoundary from "@/components/ErrorBoundary";

/* ── Preset card colors ── */

const PRESET_STYLE: Record<string, { border: string; bg: string; text: string; icon: string }> = {
  hipaa: {
    border: "border-blocked/20",
    bg: "bg-blocked-bg",
    text: "text-blocked",
    icon: "🏥",
  },
  sox: {
    border: "border-warn/20",
    bg: "bg-warn-bg",
    text: "text-warn",
    icon: "📊",
  },
  legal: {
    border: "border-accent/20",
    bg: "bg-accent-bg",
    text: "text-accent",
    icon: "⚖️",
  },
  default: {
    border: "border-base-600",
    bg: "bg-base-700/30",
    text: "text-gray-400",
    icon: "🛡️",
  },
};

function getPresetStyle(key: string) {
  if (key.includes("hipaa")) return PRESET_STYLE.hipaa;
  if (key.includes("sox")) return PRESET_STYLE.sox;
  if (key.includes("legal")) return PRESET_STYLE.legal;
  return PRESET_STYLE.default;
}

export default function CompliancePage() {
  const [presets, setPresets] = useState<CompliancePreset[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [selectedExec, setSelectedExec] = useState<string | null>(null);
  const [loadingPresets, setLoadingPresets] = useState(true);

  const selectedExecution = executions.find((execution) => execution.id === selectedExec) ?? null;

  useEffect(() => {
    Promise.all([
      api.getCompliancePresets(),
      api.listExecutions("completed", 20),
    ]).then(([p, e]) => {
      setPresets(p);
      setExecutions(e);
      setLoadingPresets(false);
    }).catch(() => setLoadingPresets(false));
  }, []);

  return (
    <>
      <Head>
        <title>Certior Studio - Compliance</title>
      </Head>

      <div className="p-6 lg:p-8 max-w-6xl mx-auto space-y-8">
        <div className="hero-band rounded-[30px] border border-base-700/60 px-6 py-6 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="label mb-2">Evidence and export</p>
              <h1 className="text-3xl font-semibold font-display text-slate-900">Compliance</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Review the preset requirements, pick a completed execution, and generate the package needed for audit or release review.</p>
            </div>
            <div className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-3 text-sm text-slate-600">
              <p className="font-medium text-slate-900">Export after completion</p>
              <p className="mt-1 text-xs">JSON and PDF are generated from the recorded evidence.</p>
            </div>
          </div>
        </div>

        {/* Presets grid */}
        <div>
          <h2 className="text-sm font-medium text-slate-700 mb-3">Presets</h2>
          {loadingPresets ? (
            <div className="text-sm text-slate-500">Loading…</div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {presets.map((p) => {
                const style = getPresetStyle(p.key);
                return (
                  <div key={p.key} className={`panel-warm rounded-[24px] p-4 ${style.border} space-y-3`}>
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{style.icon}</span>
                      <h3 className={`text-sm font-semibold ${style.text}`}>{p.name}</h3>
                    </div>
                    <div className="space-y-1">
                      <p className="text-[11px] text-slate-500">
                        {p.required_proofs.length} required proof{p.required_proofs.length !== 1 ? "s" : ""}
                      </p>
                      {p.human_approvals.length > 0 && (
                        <p className="text-[11px] text-warn/70">
                          {p.human_approvals.length} approval workflow{p.human_approvals.length !== 1 ? "s" : ""}
                        </p>
                      )}
                      <p className="text-[11px] text-slate-500">
                        {Math.round(p.retention_days / 365)}y retention
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-1 pt-1">
                      {p.required_proofs.slice(0, 3).map((proof) => (
                        <span key={proof} className={`badge ${style.bg} ${style.text} border ${style.border} text-[9px]`}>
                          ⊢ {proof}
                        </span>
                      ))}
                      {p.required_proofs.length > 3 && (
                        <span className="badge bg-white/70 text-slate-500 border border-base-600/30 text-[9px]">
                          +{p.required_proofs.length - 3}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Execution selector + compliance dashboard */}
        <div className="space-y-4">
          <div className="panel-warm rounded-[24px] px-4 py-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-sm font-medium text-slate-800">Choose a completed run</h2>
                <p className="mt-1 text-xs text-slate-500">Open one finished execution to review its recorded evidence and export files.</p>
              </div>
            <select
              value={selectedExec ?? ""}
              onChange={(e) => setSelectedExec(e.target.value || null)}
              className="input-field py-1.5 px-3 text-xs w-auto min-w-[280px]"
              aria-label="Select execution for compliance export"
            >
              <option value="">Select a completed execution…</option>
              {executions.map((ex) => (
                <option key={ex.id} value={ex.id}>
                  {ex.id.slice(0, 8)} - {ex.task.slice(0, 50)}
                </option>
              ))}
            </select>
            </div>
          </div>

          {selectedExec ? (
            <ErrorBoundary>
              <ComplianceDashboard
                executionId={selectedExec}
                defaultPreset={selectedExecution?.compliance_policy ?? undefined}
              />
            </ErrorBoundary>
          ) : (
            <div className="panel-warm rounded-[28px] p-12 text-center text-sm text-slate-500">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} className="h-12 w-12 mx-auto text-slate-400 mb-3">
                <path d="M12 2l7 3.5v5c0 5.25-3 9.5-7 11-4-1.5-7-5.75-7-11v-5L12 2z" />
                <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <p>Select a completed execution above to view and export its compliance package.</p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
