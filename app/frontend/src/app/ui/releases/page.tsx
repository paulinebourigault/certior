"use client";

import { useEffect, useMemo, useState } from "react";
import type { PromotionRecord } from "@/lib/types";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AlertTriangle, CheckCircle2, Clock, Database, RefreshCcw, ShieldCheck, XCircle } from "lucide-react";

const REPO_ROOT = "certior-oss/agents";
const LIVE_HISTORY_TIMEOUT_MS = 10000;

type PromotionHistoryPayload = {
  promotions: PromotionRecord[];
  source?: string;
  repo_root?: string;
};

function statusTone(status: string) {
  if (status === "attested") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "rejected" || status === "blocked") return "border-red-200 bg-red-50 text-red-700";
  return "border-slate-200 bg-slate-50 text-slate-700";
}

function displayLabel(row: PromotionRecord) {
  return row.release_label || row.snapshot_id;
}

function shortId(value?: string | null, size = 12) {
  if (!value) return "current";
  return value.length > size ? value.slice(0, size) : value;
}

function formatStoredAt(value: number) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value * 1000));
}

function isDemoSource(value: string) {
  return /^example\s+\d+/i.test(value) || /approved path/i.test(value);
}

function normalizeReason(row: PromotionRecord) {
  const reason = typeof row.metadata?.reason === "string" ? row.metadata.reason : "";
  const source = typeof row.metadata?.source === "string" ? row.metadata.source : "";
  if (reason && !isDemoSource(reason)) return reason;
  if (source && !isDemoSource(source)) return source;
  if (row.status === "attested") return "Attestation persisted with artifact binding and operator metadata.";
  if (row.status === "revoked") return "Promotion was revoked in the verification graph.";
  return "Release promotion was rejected by the verification graph.";
}

function evidenceDetails(row: PromotionRecord) {
  const digest = typeof row.metadata?.bound_artifact_digest === "string" ? row.metadata.bound_artifact_digest : null;
  const operator = typeof row.metadata?.operator_identity === "string" ? row.metadata.operator_identity : null;
  return {
    summary: normalizeReason(row),
    record: `DB record ${shortId(row.id)} | stored ${formatStoredAt(row.created_at)}`,
    digest: digest ? `artifact ${shortId(digest, 24)}` : "artifact binding recorded",
    operator: operator || "operator attestation recorded",
  };
}

function issueCount(row: PromotionRecord) {
  const explicitIssues = Number(row.metadata?.issues);
  if (Number.isFinite(explicitIssues)) return explicitIssues;
  return row.status === "attested" ? 0 : 1;
}

function uniqueLatestRows(rows: PromotionRecord[]) {
  const seen = new Set<string>();
  return [...rows]
    .sort((left, right) => (right.created_at || 0) - (left.created_at || 0))
    .filter((row) => {
    const key = [row.status, row.release_label || row.snapshot_id, row.commit_sha || "current"].join("::");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function getStudioPromotionHistory(repoRoot: string): Promise<PromotionHistoryPayload> {
  const response = await fetch(`/api/studio/release-promotions?repo_root=${encodeURIComponent(repoRoot)}`, { cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(body.detail || "Release history unavailable");
  }
  return response.json();
}

export default function ReleasesPage() {
  const [releases, setReleases] = useState<PromotionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiNote, setApiNote] = useState<string | null>(null);
  const [historySource, setHistorySource] = useState("live");
  const [lastLoadedAt, setLastLoadedAt] = useState<number | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      setLoading(true);
      setApiNote(null);

      let timeoutId: number | undefined;
      try {
        const data = await Promise.race([
          getStudioPromotionHistory(REPO_ROOT),
          new Promise<never>((_, reject) => {
            timeoutId = window.setTimeout(() => reject(new Error("Live promotion history timed out")), LIVE_HISTORY_TIMEOUT_MS);
          }),
        ]);
        if (!cancelled) {
          setReleases(data.promotions || []);
          setHistorySource(data.source || "live");
          setLastLoadedAt(Date.now());
        }
      } catch (error) {
        if (!cancelled) {
          setApiNote("Live release history unavailable. Start the API and PostgreSQL verification graph, then refresh.");
          setReleases([]);
          setLastLoadedAt(null);
        }
      } finally {
        if (timeoutId) window.clearTimeout(timeoutId);
        if (!cancelled) setLoading(false);
      }
    }

    fetchData();
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  const rows = useMemo(() => uniqueLatestRows(releases).slice(0, 8), [releases]);
  const isLive = historySource === "live" && lastLoadedAt !== null;
  const attestedCount = rows.filter((row) => row.status === "attested").length;
  const blockedCount = rows.filter((row) => row.status !== "attested").length;

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-emerald-700">
            <ShieldCheck className="h-4 w-4" />
            Release control plane
          </div>
          <h2 className="font-display text-2xl font-semibold text-slate-900">Release Attestations</h2>
          <p className="mt-1 text-sm text-slate-600">Latest promotion records loaded from PostgreSQL for {REPO_ROOT}.</p>
        </div>
        <div className="flex flex-wrap gap-2 text-sm font-semibold">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-blue-700">
            <Database className="h-4 w-4" />
            {isLive ? "Live DB records" : "Waiting for DB records"}
          </span>
          <span className="rounded-md border border-slate-200 bg-white px-3 py-2 text-slate-700">{rows.length} latest records</span>
          {lastLoadedAt && <span className="rounded-md border border-slate-200 bg-white px-3 py-2 text-slate-700">Synced {formatStoredAt(lastLoadedAt / 1000)}</span>}
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-emerald-700">{attestedCount} attested</span>
          <span className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-red-700">{blockedCount} blocked</span>
          <button
            type="button"
            onClick={() => setRefreshKey((value) => value + 1)}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-2 text-slate-700 hover:bg-slate-50"
          >
            <RefreshCcw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {apiNote && (
        <div className="flex items-center gap-2 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm font-semibold text-blue-800">
          <AlertTriangle className="h-4 w-4" />
          {apiNote}
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Attestation</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Commit</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Evidence</TableHead>
              <TableHead className="text-right">Graph Signal</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-slate-500">
                  <div className="flex items-center justify-center gap-2">
                    <Clock className="h-4 w-4 animate-spin" />
                    <span>Loading release attestations...</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-10 text-center text-slate-500">
                  No live promotion records returned for {REPO_ROOT}. Promote or reject a release, then refresh this view.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => {
                const issues = issueCount(row);
                const isAttested = row.status === "attested";
                const evidence = evidenceDetails(row);
                return (
                  <TableRow key={row.id}>
                    <TableCell>
                      <div className="font-semibold text-slate-900">{displayLabel(row)}</div>
                      <div className="mt-1 font-mono text-xs text-slate-500">snapshot {shortId(row.snapshot_id, 18)}</div>
                      <div className="mt-1 font-mono text-xs text-slate-400">record {shortId(row.id, 18)}</div>
                    </TableCell>
                    <TableCell className="font-medium text-slate-700">{REPO_ROOT}</TableCell>
                    <TableCell>
                      <span className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-xs text-slate-600">
                        {row.commit_sha || "current"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-bold ${statusTone(row.status)}`}>
                        {isAttested ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                        {isAttested ? "Attested" : "Blocked"}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-xl text-sm text-slate-600">
                      <div className="font-medium text-slate-800">{evidence.summary}</div>
                      <div className="mt-1 font-mono text-xs text-slate-500">{evidence.record}</div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        <span className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-semibold text-slate-600">{evidence.digest}</span>
                        <span className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-semibold text-slate-600">{evidence.operator}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-bold">
                      {issues > 0 ? <span className="text-red-600">{issues} issue{issues === 1 ? "" : "s"}</span> : <span className="text-emerald-700">clear</span>}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}