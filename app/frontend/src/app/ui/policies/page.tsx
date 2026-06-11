"use client";

import { useEffect, useMemo, useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Ban, CheckCircle2, PlayCircle, RefreshCcw, ShieldIcon, X } from "lucide-react";

type GraphEdge = {
  source: string;
  target: string;
  permissions?: string[];
  status?: string;
  reason?: string;
  proofSignature?: string;
};

type PolicyRow = {
  repo: string;
  package: string;
  language: string;
  status: "enforcing" | "blocking";
  outcome: "pass" | "block";
  scope: string;
  permissions: string[];
  evidenceMode?: "blocked" | "verified";
};

const policyRows: PolicyRow[] = [
  {
    repo: "Clinical release assistant",
    package: "HIPAA Reviewed Release",
    language: "Lean 4",
    status: "enforcing",
    outcome: "pass",
    scope: "Reviewer artifact must exist before public release.",
    permissions: ["review_phi", "approve_public_release"],
  },
  {
    repo: "Untrusted child publisher",
    package: "Capability Escalation Guard",
    language: "Lean 4",
    status: "blocking",
    outcome: "block",
    scope: "Child cannot receive permissions or budget outside parent token.",
    permissions: ["publish_public_artifact", "export_raw_phi"],
    evidenceMode: "blocked",
  },
  {
    repo: "Finance reporting agent",
    package: "SOX Audit Boundary",
    language: "Lean 4",
    status: "enforcing",
    outcome: "pass",
    scope: "Material financial changes require signed review evidence.",
    permissions: ["write_audit_graph"],
  },
  {
    repo: "Legal research assistant",
    package: "Privilege Boundary",
    language: "Lean 4",
    status: "enforcing",
    outcome: "pass",
    scope: "Privileged material cannot flow into public summaries.",
    permissions: ["redact_phi", "check_policy_bounds"],
  },
  {
    repo: "PHI detector escalation attempt",
    package: "Raw PHI Export Guard",
    language: "Lean 4",
    status: "blocking",
    outcome: "block",
    scope: "A detection-only child cannot delegate raw PHI export or public publishing permissions.",
    permissions: ["export_raw_phi"],
    evidenceMode: "blocked",
  },
  {
    repo: "Public content release agent",
    package: "Artifact Hash Binding",
    language: "Lean 4",
    status: "enforcing",
    outcome: "pass",
    scope: "Released text must match the reviewed artifact hash.",
    permissions: ["publish_public_artifact"],
  },
];

const GRAPH_RETRY_DELAYS_MS = [0, 500, 1200];

function edgeMatches(row: PolicyRow, edge: GraphEdge) {
  const permissions = edge.permissions || [];
  const permissionMatch = row.permissions.some((permission) => permissions.includes(permission));
  if (!permissionMatch) return false;
  if (row.evidenceMode === "blocked") return edge.status === "blocked";
  if (row.evidenceMode === "verified") return edge.status !== "blocked";
  return true;
}

export default function PoliciesPage() {
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function loadGraphEvidence() {
      setLoading(true);
      try {
        let graph: { edges?: GraphEdge[] } | null = null;
        for (const delay of GRAPH_RETRY_DELAYS_MS) {
          if (cancelled) return;
          if (delay > 0) await new Promise((resolve) => window.setTimeout(resolve, delay));
          try {
            const response = await fetch("/api/v1/agents/delegation-graph", { cache: "no-store" });
            if (!response.ok) throw new Error("Graph unavailable");
            graph = await response.json();
            break;
          } catch {
            graph = null;
          }
        }
        if (!cancelled) setEdges(graph?.edges || []);
      } catch {
        if (!cancelled) setEdges([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    loadGraphEvidence();
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  const selectedEvidence = useMemo(() => {
    if (!selectedPolicy) return [];
    return edges.filter((edge) => edgeMatches(selectedPolicy, edge));
  }, [edges, selectedPolicy]);
  const selectedHasLiveEvidence = selectedEvidence.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-blue-700">
            <ShieldIcon className="h-4 w-4" />
            Boundary library
          </div>
          <h2 className="font-display text-2xl font-semibold text-slate-900">Policy Bound Configuration</h2>
        </div>
        <div className="flex flex-wrap gap-2 text-sm font-semibold">
          <span className="rounded-md border border-slate-200 bg-white px-3 py-2 text-slate-700">{policyRows.length} policies</span>
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-700">{edges.length} graph events</span>
          <button
            type="button"
            onClick={() => setRefreshKey((value) => value + 1)}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-2 text-slate-700 hover:bg-slate-50"
          >
            <RefreshCcw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh evidence
          </button>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Boundary Target</TableHead>
                <TableHead>Certior Package</TableHead>
                <TableHead>Engine</TableHead>
                <TableHead>Boundary</TableHead>
                <TableHead>Evidence Link</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policyRows.map((row) => {
                const matches = edges.filter((edge) => edgeMatches(row, edge));
                const hasLiveEvidence = matches.length > 0;
                const blocked = hasLiveEvidence ? matches.some((edge) => edge.status === "blocked") : false;
                const selected = selectedPolicy?.package === row.package;
                return (
                  <TableRow key={row.package} className={selected ? "bg-blue-50/60" : undefined}>
                    <TableCell className="font-medium text-slate-700">{row.repo}</TableCell>
                    <TableCell className="font-medium text-[#867059]">{row.package}</TableCell>
                    <TableCell>
                      <span className="badge border border-slate-200 bg-slate-100 text-slate-600">{row.language}</span>
                    </TableCell>
                    <TableCell className="max-w-[360px] text-sm text-slate-600">{row.scope}</TableCell>
                    <TableCell>
                      <span className={`badge border ${blocked ? "border-red-200 bg-red-50 text-red-700" : hasLiveEvidence ? "border-green-200 bg-green-50 text-green-700" : "border-amber-200 bg-amber-50 text-amber-700"}`}>
                        {blocked ? <Ban className="mr-1 h-3 w-3" /> : <CheckCircle2 className="mr-1 h-3 w-3" />}
                        {hasLiveEvidence ? `${matches.length} event${matches.length === 1 ? "" : "s"}` : "No live event"}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedPolicy(row)}
                        aria-pressed={selected}
                        className={`ml-auto inline-flex items-center justify-end gap-1 rounded-md border px-2.5 py-1.5 text-sm font-semibold ${
                          selected
                            ? "border-blue-300 bg-blue-100 text-blue-800"
                            : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                        }`}
                      >
                        <PlayCircle className="h-4 w-4" />
                        Validations
                      </button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          {selectedPolicy ? (
            <>
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-xs font-bold uppercase text-slate-500">Validation detail</div>
              <h3 className="mt-1 font-display text-lg font-semibold text-slate-900">{selectedPolicy.package}</h3>
              <p className="mt-1 text-sm text-slate-600">{selectedPolicy.scope}</p>
            </div>
            <button
              type="button"
              onClick={() => setSelectedPolicy(null)}
              className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-200 text-slate-500 hover:bg-slate-50"
              aria-label="Close validation detail"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="mt-4 grid gap-3">
            {selectedHasLiveEvidence ? selectedEvidence.map((edge, index) => (
              <div key={`${edge.source}-${edge.target}-${index}`} className="rounded-md border border-slate-200 bg-slate-50 p-3">
                <div className="text-sm font-semibold text-slate-900">{edge.source} -&gt; {edge.target}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {(edge.permissions || []).map((permission) => (
                    <span key={permission} className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-xs font-semibold text-blue-800">{permission}</span>
                  ))}
                </div>
                <div className={`mt-2 rounded-md border px-2 py-1 text-xs font-semibold ${edge.status === "blocked" ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"}`}>
                  {edge.reason || (edge.status === "blocked" ? "Blocked by boundary" : "Verified by runtime boundary")}
                </div>
              </div>
            )) : (
              <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                <div className="font-semibold">No live graph event for this policy yet.</div>
                <p className="mt-1">Run or replay the matching scenario before using this row as evidence.</p>
              </div>
            )}
          </div>
            </>
          ) : (
            <div className="flex min-h-[260px] flex-col items-center justify-center rounded-md border border-dashed border-slate-200 bg-slate-50 px-4 text-center">
              <PlayCircle className="h-8 w-8 text-slate-400" />
              <div className="mt-3 text-sm font-semibold text-slate-700">Select a validation</div>
              <p className="mt-1 max-w-xs text-sm text-slate-500">Open a policy row to inspect the live graph evidence Certior used for that boundary.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
