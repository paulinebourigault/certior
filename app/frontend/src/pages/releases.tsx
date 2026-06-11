
import { useState } from "react";
import { getReleaseDecision, getReleaseHealth, getPromotionHistory, promoteRelease } from "@/lib/api";
import type { ReleaseDecisionResponse, HealthStatusResponse, PromotionRecord } from "@/lib/types";

export default function ReleaseTrustPage() {
  const [repoRoot, setRepoRoot] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [data, setData] = useState<ReleaseDecisionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"verdict" | "attestation" | "baseline" | "health" | "history">("verdict");

  // Health Data
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);

  // Promotion states
  const [promoteReason, setPromoteReason] = useState("");
  const [promoteLoading, setPromoteLoading] = useState(false);
  const [promoteStatus, setPromoteStatus] = useState<"attested" | "rejected" | "revoked">("attested");
  const [promoteSuccess, setPromoteSuccess] = useState(false);
  const [promotions, setPromotions] = useState<PromotionRecord[]>([]);

  const fetchPromotions = async (repo: string) => {
    try {
      const h = await getPromotionHistory(repo);
      setPromotions(h.promotions || []);
    } catch(e) { console.error(e); }
  };

  const handlePromote = async () => {
    if (!repoRoot || !data) return;
    setPromoteLoading(true);
    setPromoteSuccess(false);
    try {
      await promoteRelease({
        repo_root: repoRoot,
        operator_identity: "operator@certior.local",
        reason: promoteReason || "Promoted via Studio",
        bound_artifact_digest: data.release_artifact_digest || "unknown",
        commit_sha: data.commit_sha || null,
        status: promoteStatus
      });
      const res = { ok: true };
      if (res.ok) {
        setPromoteSuccess(true);
        setPromoteReason("");
        await fetchPromotions(repoRoot);
      } else {
        alert("Failed to promote: " + JSON.stringify(res));
      }
    } catch(err) {
      alert("Error promoting");
    } finally {
      setPromoteLoading(false);
    }
  };


  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoRoot) return;
    setLoading(true);
    setError(null);
    setData(null);
    setActiveTab("verdict");

    try {
      const result = await getReleaseDecision({ repo_root: repoRoot, commit_sha: commitSha || undefined });
      setData(result);

      // Fetch health
      try {
        const healthData = await getReleaseHealth(repoRoot);
        setHealth(healthData);
      } catch (e) { console.error("Health fetch error", e); }

      // Fetch promotions
      await fetchPromotions(repoRoot);
    } catch (err: any) {
      setError(err?.message || "Failed to fetch release decision");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="p-6 lg:p-8 max-w-6xl mx-auto space-y-8">
        <div className="hero-band rounded-[30px] border border-base-700/60 px-6 py-6 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="label mb-2">Release Pipeline</p>
              <h1 className="text-3xl font-semibold font-display text-slate-900 mb-2">Release Trust</h1>
              <p className="max-w-2xl text-sm leading-6 text-slate-600">Evaluate release readiness, review component provenance, and compare with stable baselines.</p>
            </div>
          </div>
        </div>

        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-4 p-4 panel-warm rounded-[24px] border border-base-700/60 shadow-sm">
          <input
            type="text"
            className="flex-1 bg-white border border-base-700/50 text-slate-900 rounded-xl px-4 py-2 focus:ring-2 focus:ring-accent-500 focus:outline-none text-sm placeholder:text-slate-400"
            placeholder="Repository root (e.g. /tmp/my-repo)"
            value={repoRoot}
            onChange={(e) => setRepoRoot(e.target.value)}
            required
          />
          <input
            type="text"
            className="w-full sm:w-48 bg-white border border-base-700/50 text-slate-900 rounded-xl px-4 py-2 focus:ring-2 focus:ring-accent-500 focus:outline-none text-sm placeholder:text-slate-400"
            placeholder="Commit SHA (optional)"
            value={commitSha}
            onChange={(e) => setCommitSha(e.target.value)}
          />
          <button type="submit" className="btn-primary px-6 rounded-xl text-sm font-medium items-center justify-center flex" disabled={loading}>
            {loading ? "Checking..." : "Inspect Decision"}
          </button>
        </form>

        {error && (
          <div className="p-4 bg-rose-50 border border-rose-200 rounded-md text-rose-800 text-sm">
            {error}
          </div>
        )}

        {data && (
          <div className="space-y-6">
            {/* High-level status bar */}
            <div className={`p-6 border rounded-lg flex items-center justify-between shadow-lg ${data.decision === "SHIP" ? "bg-emerald-50 border-emerald-200/60 text-emerald-800" : "bg-rose-50 border-rose-200/60 text-rose-800"}`}>
              <div className="flex items-center gap-4">
                <div className={`text-4xl font-extrabold tracking-tight ${data.decision === "SHIP" ? "text-emerald-700" : "text-rose-700"}`}>
                  {data.decision === "SHIP" ? "READY TO SHIP" : "DO NOT SHIP"}
                </div>
                {data.decision === "NO_SHIP" && (
                  <span className="px-3 py-1 bg-rose-100 border border-rose-200 text-rose-800 text-sm font-semibold rounded-full uppercase tracking-wider">
                    {data.blockers.length} Blockers Found
                  </span>
                )}
              </div>
              <div className="text-right hidden sm:block">
                <div className="text-sm text-slate-500 uppercase tracking-widest font-semibold mb-1">Target Commit</div>
                <div className="text-slate-700 font-mono text-sm">{data.commit_sha || "Latest"}</div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="border-b border-base-700/50">
              <nav className="flex space-x-8">
                <button
                  onClick={() => setActiveTab("verdict")}
                  className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === "verdict" ? "border-accent-500 text-accent-700" : "border-transparent text-slate-500 hover:text-slate-700 hover:border-base-700/80"
                  }`}
                >
                  Release Verdict
                </button>
                <button
                  onClick={() => setActiveTab("attestation")}
                  className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === "attestation" ? "border-accent-500 text-accent-700" : "border-transparent text-slate-500 hover:text-slate-700 hover:border-base-700/80"
                  }`}
                >
                  Attestation Scope
                </button>
                <button
                  onClick={() => setActiveTab("baseline")}
                  className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === "baseline" ? "border-accent-500 text-accent-700" : "border-transparent text-slate-500 hover:text-slate-700 hover:border-base-700/80"
                  }`}
                >
                  Baseline Comparison
                </button>
              </nav>
            </div>

            {/* Tab content */}
            <div className="pt-2">
              {activeTab === "verdict" && (
                <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  {/* Promotion Box */}
                  <section className="panel-warm border border-base-700/50 rounded-lg p-5">
                    <h3 className="text-lg font-semibold text-slate-700 mb-4 border-b border-base-700/50 pb-2">Audit-Grade Promotion</h3>
                    {promoteSuccess && (
                       <div className="mb-4 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-md text-sm">
                         Release successfully actioned. Audit log updated.
                       </div>
                    )}
                    <div className="flex flex-col md:flex-row gap-4">
                      <div className="flex-1">
                        <label className="block text-xs uppercase tracking-wider text-slate-500 mb-1">Reason for {promoteStatus}</label>
                        <input type="text"
                          className="w-full panel-warm border border-base-700/50 rounded px-3 py-2 text-sm text-slate-700 focus:outline-none focus:border-accent-500"
                          placeholder="e.g. Cleared by manual security review ticket #1234"
                          value={promoteReason}
                          onChange={(e) => setPromoteReason(e.target.value)}
                        />
                      </div>
                      <div className="flex items-end gap-2">
                        <select 
                           className="panel-warm border border-base-700/50 rounded px-3 py-2 text-sm text-slate-700 focus:outline-none focus:border-accent-500"
                           value={promoteStatus}
                           onChange={(e: any) => setPromoteStatus(e.target.value)}
                        >
                          <option value="attested">Approve (Attested)</option>
                          <option value="rejected">Reject (Halt)</option>
                          <option value="revoked">Revoke (Rollback)</option>
                        </select>
                        <button 
                          onClick={handlePromote}
                          disabled={promoteLoading}
                          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-slate-900 px-4 py-2 rounded text-sm font-medium transition-colors whitespace-nowrap"
                        >
                          {promoteLoading ? "Submitting..." : "Submit Action"}
                        </button>
                      </div>
                    </div>
                  </section>

                  {data.blockers.length > 0 ? (
                    <section className="space-y-4">
                      <h2 className="text-xl font-semibold text-slate-900 flex items-center gap-2">
                        <span className="w-2 h-6 bg-red-500 rounded-sm"></span> Blockers & Remediation
                      </h2>
                      <div className="grid gap-4">
                        {data.blockers.map((b, i) => (
                          <div key={i} className="p-5 panel-warm rounded-lg border border-base-700/50 shadow-sm relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-1 h-full bg-red-500/50"></div>
                            <div className="font-bold text-rose-700 mb-2 font-mono text-sm tracking-wide bg-red-500/10 inline-block px-2 py-0.5 rounded">{b.component}</div>
                            <p className="text-slate-700 mb-4 text-lg">{b.reason}</p>
                            {b.remediation_suggestion && (
                              <div className="text-sm bg-white/50 p-4 rounded-md border border-base-700/50 text-slate-700 flex items-start gap-3">
                                <span className="font-bold text-emerald-400 uppercase tracking-widest text-xs mt-0.5">Fix</span> 
                                <span className="font-mono">{b.remediation_suggestion}</span>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </section>
                  ) : (
                    <div className="p-8 text-center border border-base-700/50 rounded-lg panel-warm space-y-3">
                      <div className="text-4xl">🎉</div>
                      <h3 className="text-xl font-medium text-slate-900">All clear!</h3>
                      <p className="text-slate-500">No blockers found. This snapshot is fully attested and ready for release.</p>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "attestation" && (
                <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  
                  <section>
                    <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
                      <span className="w-2 h-6 bg-blue-500 rounded-sm"></span> Policy Requirements
                    </h2>
                    <div className="panel-warm rounded-lg border border-base-700/50 overflow-hidden">
                      <table className="w-full text-left text-sm whitespace-nowrap">
                        <thead className="bg-[#0a0a0a] border-b border-base-700/50 uppercase tracking-wider text-xs font-semibold text-slate-500">
                          <tr>
                            <th className="px-6 py-4">Status</th>
                            <th className="px-6 py-4">Policy Code</th>
                            <th className="px-6 py-4">Requirement</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                          {data.explanation.map((ex, i) => (
                            <tr key={i} className="hover:bg-white/5 transition-colors">
                              <td className="px-6 py-4">
                                {ex.satisfied ? (
                                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Passed
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-rose-700 border border-red-500/20">
                                    <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span> Failed
                                  </span>
                                )}
                              </td>
                              <td className="px-6 py-4 font-mono text-slate-700">{ex.policy}</td>
                              <td className="px-6 py-4 text-slate-500 truncate max-w-md" title={ex.requirement}>{ex.requirement}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>

                  <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div>
                      <h2 className="text-lg font-medium text-slate-900 mb-3">Components Provenance</h2>
                      <div className="panel-warm rounded-lg border border-base-700/50 p-1">
                        {data.provenance?.components && data.provenance.components.length > 0 ? (
                          <ul className="divide-y divide-gray-800">
                            {data.provenance.components.map((c, i) => (
                              <li key={i} className="p-3 flex justify-between items-center hover:bg-white/5 rounded">
                                <div>
                                  <div className="font-semibold text-slate-700">{c.name}</div>
                                  <div className="text-xs text-slate-500 font-mono mt-1">Ref: {c.source_commit.substring(0, 8)}...</div>
                                </div>
                                <span className="px-2 py-1 bg-base-700/50 rounded text-xs font-mono text-slate-700">v{c.version}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <div className="p-6 text-center text-slate-500 text-sm">No component data.</div>
                        )}
                      </div>
                    </div>
                    <div>
                      <h2 className="text-lg font-medium text-slate-900 mb-3">CI Status</h2>
                      <div className="panel-warm rounded-lg border border-base-700/50 p-1">
                        {data.provenance?.checks && data.provenance.checks.length > 0 ? (
                          <ul className="divide-y divide-gray-800">
                            {data.provenance.checks.map((c, i) => (
                              <li key={i} className="p-3 flex justify-between items-center hover:bg-white/5 rounded">
                                <div className="truncate pr-4">
                                  <div className="font-semibold text-slate-700 truncate">{c.check_run_name}</div>
                                  <div className="text-xs text-slate-500 mt-1">{c.workflow}</div>
                                </div>
                                <span className={`shrink-0 px-2 py-1 rounded text-xs font-semibold uppercase ${
                                  c.conclusion === 'success' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-rose-700'
                                }`}>
                                  {c.conclusion || 'unknown'}
                                </span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <div className="p-6 text-center text-slate-500 text-sm">No CI checks found.</div>
                        )}
                      </div>
                    </div>
                  </section>
                </div>
              )}

              {activeTab === "health" && (
                <div className="space-y-6">
                  {health ? (
                    <>
                      <div className="bg-base-700/50 border border-base-700/50 p-4 rounded-lg">
                        <h4 className="text-lg font-semibold text-slate-700 mb-2">Ingest Status</h4>
                        <div className="flex items-center space-x-2 mb-4">
                            <span className={`px-2 py-1 text-xs font-semibold rounded ${
                              health.ingest_status === "healthy" ? "bg-green-100 text-green-800" :
                              health.ingest_status === "degraded" ? "bg-yellow-100 text-yellow-800" : "bg-red-100 text-red-800"
                            }`}>
                              {health.ingest_status.toUpperCase()}
                            </span>
                        </div>
                        {health.ingest_issues && health.ingest_issues.length > 0 ? (
                          <div className="space-y-2">
                            {health.ingest_issues.map((issue: any, idx: number) => (
                              <div key={idx} className="flex items-start panel-warm border border-base-700/50 p-3 rounded">
                                <div className="flex-1">
                                  <div className="flex items-center space-x-2">
                                    <span className="text-xs font-semibold uppercase text-yellow-400 bg-yellow-400/10 px-2 py-0.5 rounded">
                                      {issue.severity}
                                    </span>
                                    <span className="text-slate-700 font-medium">{issue.code}</span>
                                  </div>
                                  <p className="text-slate-500 text-sm mt-1">{issue.detail}</p>
                                  {(issue.component_name || issue.property_key) && (
                                    <div className="mt-2 flex space-x-4 text-xs text-slate-500">
                                      {issue.component_name && <span>Component: {issue.component_name}</span>}
                                      {issue.property_key && <span>Property: {issue.property_key}</span>}
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-slate-500 text-sm">No ingest issues detected. The verification graph is stable.</p>
                        )}
                      </div>

                      <div className="bg-base-700/50 border border-base-700/50 p-4 rounded-lg">
                        <h4 className="text-lg font-semibold text-slate-700 mb-2">Runtime Evidence Freshness</h4>
                        <div className="grid grid-cols-3 gap-4">
                          <div className="panel-warm p-4 rounded border border-base-700/50 flex flex-col items-center">
                            <span className="text-2xl font-bold text-emerald-700">{health.freshness_summary?.fresh || 0}</span>
                            <span className="text-sm text-slate-500">Fresh</span>
                          </div>
                          <div className="panel-warm p-4 rounded border border-base-700/50 flex flex-col items-center">
                            <span className="text-2xl font-bold text-yellow-400">{health.freshness_summary?.stale || 0}</span>
                            <span className="text-sm text-slate-500">Stale</span>
                          </div>
                          <div className="panel-warm p-4 rounded border border-base-700/50 flex flex-col items-center">
                            <span className="text-2xl font-bold text-accent-700">{health.freshness_summary?.timestamp_only || 0}</span>
                            <span className="text-sm text-slate-500">Timestamp Only</span>
                          </div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="text-slate-500 p-4 bg-base-700/50 rounded border border-base-700/50">
                      No health data available. Ensure the release decision endpoint is reachable.
                    </div>
                  )}
                </div>
              )}
              
              {activeTab === "baseline" && (
                <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                  {!data.baseline || !data.baseline.has_baseline ? (
                    <div className="p-8 panel-warm border border-base-700/50 rounded-lg text-center">
                      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-500/10 text-accent-700 mb-4">
                        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <h3 className="text-lg font-medium text-slate-900 mb-2">No Attested Baseline Found</h3>
                      <p className="text-slate-500 max-w-md mx-auto text-sm">
                        There is no previously attested release for this repository to compare against. This might be the first release snapshot being processed.
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between p-4 bg-blue-900/10 border border-accent-500/20 rounded-lg">
                        <div>
                          <div className="text-sm font-semibold tracking-wider text-accent-700 uppercase mb-1">Last Attested Baseline</div>
                          <div className="font-mono text-slate-700 flex items-center gap-2">
                            {data.baseline.baseline_commit_sha}
                            <span className="px-2 py-0.5 bg-blue-500/20 text-blue-300 rounded text-xs">APPROVED</span>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-3xl font-light text-slate-500">&rarr;</div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-semibold tracking-wider text-purple-400 uppercase mb-1">Current Evaluation</div>
                          <div className="font-mono text-slate-700">
                            {data.commit_sha || "Latest candidate"}
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Components Diff */}
                        <div className="panel-warm rounded-lg border border-base-700/50 overflow-hidden">
                          <div className="p-4 border-b border-base-700/50 bg-[#0a0a0a] flex items-center justify-between">
                            <h3 className="font-semibold text-slate-900">Components</h3>
                            {data.baseline.components && (
                              <span className="text-xs font-mono text-slate-500">Δ {data.baseline.components.delta > 0 ? "+" : ""}{data.baseline.components.delta}</span>
                            )}
                          </div>
                          <div className="p-4">
                            {data.baseline.components ? (
                              <div className="space-y-4">
                                {data.baseline.components.added.length > 0 && (
                                  <div>
                                    <div className="text-xs font-semibold text-emerald-400 uppercase mb-2">Added ({data.baseline.components.added.length})</div>
                                    <ul className="space-y-1">
                                      {data.baseline.components.added.map(c => (
                                        <li key={`add-${c}`} className="text-sm font-mono text-slate-700 bg-emerald-500/10 px-2 py-1 rounded">+ {c}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {data.baseline.components.removed.length > 0 && (
                                  <div>
                                    <div className="text-xs font-semibold text-rose-700 uppercase mb-2">Removed ({data.baseline.components.removed.length})</div>
                                    <ul className="space-y-1">
                                      {data.baseline.components.removed.map(c => (
                                        <li key={`rem-${c}`} className="text-sm font-mono text-slate-500 bg-red-500/10 px-2 py-1 rounded line-through">- {c}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {data.baseline.components.added.length === 0 && data.baseline.components.removed.length === 0 && (
                                  <div className="text-sm text-slate-500 italic">No component changes detected.</div>
                                )}
                              </div>
                            ) : (
                              <div className="text-sm text-slate-500">Inventory comparison unavailable.</div>
                            )}
                          </div>
                        </div>

                        {/* Verified Properties Diff */}
                        <div className="panel-warm rounded-lg border border-base-700/50 overflow-hidden">
                          <div className="p-4 border-b border-base-700/50 bg-[#0a0a0a] flex items-center justify-between">
                            <h3 className="font-semibold text-slate-900">Verified Properties</h3>
                            {data.baseline.verified_properties && (
                              <span className="text-xs font-mono text-slate-500">Δ {data.baseline.verified_properties.delta > 0 ? "+" : ""}{data.baseline.verified_properties.delta}</span>
                            )}
                          </div>
                          <div className="p-4">
                            {data.baseline.verified_properties ? (
                              <div className="space-y-4">
                                {data.baseline.verified_properties.added.length > 0 && (
                                  <div>
                                    <div className="text-xs font-semibold text-emerald-400 uppercase mb-2">Newly Covered ({data.baseline.verified_properties.added.length})</div>
                                    <ul className="space-y-1">
                                      {data.baseline.verified_properties.added.map(p => (
                                        <li key={`add-p-${p}`} className="text-sm font-mono text-slate-700 bg-emerald-500/10 px-2 py-1 rounded truncate" title={p}>+ {p.split(':').pop() || p}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {data.baseline.verified_properties.removed.length > 0 && (
                                  <div>
                                    <div className="text-xs font-semibold text-rose-700 uppercase mb-2">Coverage Lost ({data.baseline.verified_properties.removed.length})</div>
                                    <ul className="space-y-1">
                                      {data.baseline.verified_properties.removed.map(p => (
                                        <li key={`rem-p-${p}`} className="text-sm font-mono text-slate-500 bg-red-500/10 px-2 py-1 rounded truncate line-through" title={p}>- {p.split(':').pop() || p}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {data.baseline.verified_properties.added.length === 0 && data.baseline.verified_properties.removed.length === 0 && (
                                  <div className="text-sm text-slate-500 italic">No scope changes detected.</div>
                                )}
                              </div>
                            ) : (
                              <div className="text-sm text-slate-500">Coverage comparison unavailable.</div>
                            )}
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
