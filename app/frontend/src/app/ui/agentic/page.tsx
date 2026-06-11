"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import useSWR from "swr";
import {
  Activity,
  AlertTriangle,
  Ban,
  Box,
  CheckCircle2,
  Clock3,
  Layers3,
  Save,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  Background,
  Controls,
  Edge,
  MarkerType,
  Node,
  ReactFlow,
  ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import { listGlassBoxRecords, saveGlassBoxRecord } from "@/lib/api";
import { GLASS_BOX_ORCHESTRATIONS } from "@/lib/glassBoxOrchestrations";
import type { GlassBoxRecord } from "@/lib/types";
import "@xyflow/react/dist/style.css";

type GraphNode = {
  id: string;
  label?: string;
  type?: "parent" | "child" | string;
};

type GraphEdge = {
  id?: string;
  source: string;
  target: string;
  label?: string;
  permissions?: string[];
  budget?: number;
  timestamp?: number;
  status?: "verified" | "blocked" | string;
  severity?: "normal" | "critical" | string;
  proofSignature?: string;
  reason?: string;
};

type GraphData = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

type OrchestrationRun = {
  id: string;
  title: string;
  subtitle: string;
  colorClass: string;
  match: (edge: GraphEdge) => boolean;
};

type SelectedProof = {
  source: string;
  target: string;
  permissions: string[];
  budget: number;
  status?: string;
  severity?: string;
  proofSignature?: string;
  reason?: string;
  step: number;
};

async function loadGraphData(url = "/api/v1/agents/delegation-graph") {
  const delays = [0, 500, 1200];
  let lastError: unknown;
  for (const delay of delays) {
    if (delay > 0) await new Promise((resolve) => window.setTimeout(resolve, delay));
    try {
      const response = await fetch(url, { cache: "no-store" });
      if (!response.ok) throw new Error(`Graph request failed: ${response.status}`);
      return response.json() as Promise<GraphData>;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Graph request failed");
}

const fetcher = (url: string) => loadGraphData(url);

const NODE_WIDTH = 220;
const COLUMN_WIDTH = 320;
const ROW_HEIGHT = 124;
const LOCAL_RECORDS_KEY = "certior_glass_box_records";
const ORCHESTRATION_MATCHERS: Record<string, (edge: GraphEdge) => boolean> = {
  all: () => true,
  "privacy-review": (edge) => edge.source.includes("Privacy") || edge.target.includes("Privacy") || edge.target.includes("Redaction") || edge.target.includes("Policy"),
  "release-gate": (edge) => edge.status !== "blocked" && (edge.source.includes("Release") || edge.target.includes("Release") || edge.permissions?.includes("publish_public_artifact") === true),
  "security-blocks": (edge) => edge.status === "blocked" || edge.permissions?.includes("export_raw_phi") === true,
  "audit-evidence": (edge) => edge.permissions?.includes("write_audit_graph") === true || edge.target.includes("Audit"),
};

const ORCHESTRATIONS: OrchestrationRun[] = GLASS_BOX_ORCHESTRATIONS.map((run) => ({
  ...run,
  match: ORCHESTRATION_MATCHERS[run.id] || ORCHESTRATION_MATCHERS.all,
}));

function currentRunFromLocation() {
  if (typeof window === "undefined") return "all";
  const runId = new URLSearchParams(window.location.search).get("run") || "all";
  return ORCHESTRATION_MATCHERS[runId] ? runId : "all";
}

function localRecordId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `local_${crypto.randomUUID().slice(0, 12)}`;
  }
  return `local_${Date.now()}`;
}

function shortPermissions(permissions: string[] = []) {
  if (permissions.length === 0) return "verified delegation";
  const labels = permissions.map(formatPermissionLabel);
  if (labels.length <= 2) return labels.join(" + ");
  return `${labels[0]} +${labels.length - 1}`;
}

function formatPermissionLabel(permission: string) {
  return permission
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatBudget(value?: number) {
  if (!Number.isFinite(value)) return "Budget not set";
  return `Budget: ${new Intl.NumberFormat("en-US").format(value || 0)}`;
}

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function inferPhase(edge?: GraphEdge) {
  if (!edge) return "Awaiting agent handoff";
  if (edge.status === "blocked") return "Blocked privilege escalation";
  if (edge.source.includes("Release Gate") || edge.target.includes("Release")) return "Approved release fan-out";
  if (edge.source.includes("Privacy") || edge.target.includes("Redaction") || edge.target.includes("Policy")) return "Reviewer fan-out";
  if (edge.target.includes("Classifier") || edge.target.includes("Detector") || edge.target.includes("Budget")) return "Bootstrap triage";
  return "Verified delegation";
}

function edgeTone(edge: GraphEdge, isActive: boolean) {
  if (edge.status === "blocked") {
    return {
      stroke: "#dc2626",
      label: "#991b1b",
      labelBg: "#fef2f2",
      width: isActive ? 4 : 3,
    };
  }
  if (edge.source.includes("Release Gate") || edge.target.includes("Release")) {
    return {
      stroke: isActive ? "#d97706" : "#b45309",
      label: "#92400e",
      labelBg: "#fffbeb",
      width: isActive ? 3 : 2,
    };
  }
  if (edge.source.includes("Privacy") || edge.target.includes("Redaction") || edge.target.includes("Policy")) {
    return {
      stroke: isActive ? "#059669" : "#047857",
      label: "#065f46",
      labelBg: "#ecfdf5",
      width: isActive ? 3 : 2,
    };
  }
  return {
    stroke: isActive ? "#2563eb" : "#475569",
    label: "#0f172a",
    labelBg: "#ffffff",
    width: isActive ? 3 : 2,
  };
}

function nodeTone(node: GraphNode, isActive: boolean, isBlocked: boolean) {
  if (isBlocked) {
    return {
      border: "2px solid #dc2626",
      background: "#fef2f2",
      shadow: "0 16px 34px rgba(220, 38, 38, 0.18)",
    };
  }
  if (isActive) {
    return {
      border: "2px solid #2563eb",
      background: "#eff6ff",
      shadow: "0 16px 34px rgba(37, 99, 235, 0.20)",
    };
  }
  if (node.id.includes("Release")) {
    return {
      border: "1px solid #f59e0b",
      background: "#fffbeb",
      shadow: "0 8px 22px rgba(146, 64, 14, 0.10)",
    };
  }
  if (node.id.includes("Privacy") || node.id.includes("Redaction") || node.id.includes("Policy")) {
    return {
      border: "1px solid #10b981",
      background: "#ecfdf5",
      shadow: "0 8px 22px rgba(6, 95, 70, 0.10)",
    };
  }
  return {
    border: node.type === "parent" ? "1px solid #64748b" : "1px solid #cbd5e1",
    background: node.type === "parent" ? "#f8fafc" : "#ffffff",
    shadow: "0 8px 22px rgba(15, 23, 42, 0.08)",
  };
}

function buildLayout(nodes: GraphNode[], edges: GraphEdge[]) {
  const incoming = new Map<string, number>();
  const outgoing = new Map<string, string[]>();

  nodes.forEach((node) => {
    incoming.set(node.id, 0);
    outgoing.set(node.id, []);
  });

  edges.forEach((edge) => {
    incoming.set(edge.target, (incoming.get(edge.target) || 0) + 1);
    outgoing.set(edge.source, [...(outgoing.get(edge.source) || []), edge.target]);
  });

  const levels = new Map<string, number>();
  const queue = nodes.filter((node) => (incoming.get(node.id) || 0) === 0).map((node) => node.id);
  queue.forEach((id) => levels.set(id, 0));

  while (queue.length > 0) {
    const current = queue.shift() as string;
    const nextLevel = (levels.get(current) || 0) + 1;
    for (const child of outgoing.get(current) || []) {
      if (!levels.has(child) || nextLevel > (levels.get(child) || 0)) {
        levels.set(child, nextLevel);
        queue.push(child);
      }
    }
  }

  nodes.forEach((node) => {
    if (!levels.has(node.id)) levels.set(node.id, 0);
  });

  const rowsByLevel = new Map<number, string[]>();
  nodes.forEach((node) => {
    const level = levels.get(node.id) || 0;
    rowsByLevel.set(level, [...(rowsByLevel.get(level) || []), node.id]);
  });

  return { levels, rowsByLevel };
}

export default function AgenticFlowPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [flowInstance, setFlowInstance] = useState<ReactFlowInstance | null>(null);
  const [selectedProof, setSelectedProof] = useState<SelectedProof | null>(null);
  const [replayMode, setReplayMode] = useState(true);
  const [isPlaying, setIsPlaying] = useState(true);
  const [visibleEdgeCount, setVisibleEdgeCount] = useState(1);
  const [boundaryView, setBoundaryView] = useState(false);
  const [savingRecord, setSavingRecord] = useState(false);
  const [savedRecord, setSavedRecord] = useState<GlassBoxRecord | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [recentRecords, setRecentRecords] = useState<GlassBoxRecord[]>([]);
  const [showSnapshotTrail, setShowSnapshotTrail] = useState(false);
  const [activeRunId, setActiveRunId] = useState("all");

  useEffect(() => {
    const syncFromLocation = () => setActiveRunId(currentRunFromLocation());
    const selectFromSidebar = (event: Event) => {
      const runId = (event as CustomEvent<string>).detail;
      setActiveRunId(ORCHESTRATION_MATCHERS[runId] ? runId : "all");
    };
    syncFromLocation();
    window.addEventListener("popstate", syncFromLocation);
    window.addEventListener("certior:glass-box-run", selectFromSidebar);
    return () => {
      window.removeEventListener("popstate", syncFromLocation);
      window.removeEventListener("certior:glass-box-run", selectFromSidebar);
    };
  }, []);

  const { data, error, isLoading } = useSWR<GraphData>("/api/v1/agents/delegation-graph", fetcher, {
    refreshInterval: 3000,
    revalidateOnFocus: true,
  });

  const allOrderedEdges = useMemo(() => {
    return [...(data?.edges || [])].sort((left, right) => (left.timestamp || 0) - (right.timestamp || 0));
  }, [data?.edges]);

  const activeRun = useMemo(() => ORCHESTRATIONS.find((run) => run.id === activeRunId) || ORCHESTRATIONS[0], [activeRunId]);

  const runOrderedEdges = useMemo(() => {
    return allOrderedEdges.filter((edge) => activeRun.match(edge));
  }, [activeRun, allOrderedEdges]);

  const orderedEdges = useMemo(() => {
    if (!boundaryView) return runOrderedEdges;
    return runOrderedEdges.filter((edge) => {
      const permissions = edge.permissions || [];
      return edge.status === "blocked" || permissions.some((permission) =>
        ["approve_public_release", "publish_public_artifact", "export_raw_phi", "check_policy_bounds"].includes(permission),
      );
    });
  }, [boundaryView, runOrderedEdges]);

  const visibleEdges = useMemo(() => {
    if (!replayMode) return orderedEdges;
    return orderedEdges.slice(0, Math.max(1, Math.min(visibleEdgeCount, orderedEdges.length)));
  }, [orderedEdges, replayMode, visibleEdgeCount]);

  const visibleNodeIds = useMemo(() => {
    if (!data?.nodes) return new Set<string>();
    const ids = new Set<string>();
    const nodeEdges = replayMode ? visibleEdges : orderedEdges;
    nodeEdges.forEach((edge) => {
      ids.add(edge.source);
      ids.add(edge.target);
    });
    if (ids.size === 0 && activeRunId === "all") return new Set(data.nodes.map((node) => node.id));
    return ids;
  }, [activeRunId, data?.nodes, orderedEdges, replayMode, visibleEdges]);

  const visibleNodes = useMemo(() => {
    return (data?.nodes || []).filter((node) => visibleNodeIds.has(node.id));
  }, [data?.nodes, visibleNodeIds]);

  const activeEdge = visibleEdges[visibleEdges.length - 1];
  const activePhase = inferPhase(activeEdge);
  const blockedCount = runOrderedEdges.filter((edge) => edge.status === "blocked").length;
  const boundaryEventCount = useMemo(() => {
    return runOrderedEdges.filter((edge) => {
      const permissions = edge.permissions || [];
      return edge.status === "blocked" || permissions.some((permission) =>
        ["approve_public_release", "publish_public_artifact", "export_raw_phi", "check_policy_bounds"].includes(permission),
      );
    }).length;
  }, [runOrderedEdges]);

  const visibleSnapshotRecords = useMemo(() => {
    return recentRecords.filter((record) => record.use_cases?.includes(activeRun.title)).slice(0, 3);
  }, [activeRun.title, recentRecords]);

  useEffect(() => {
    if (!replayMode || !isPlaying || orderedEdges.length === 0) return;
    if (visibleEdgeCount >= orderedEdges.length) return;
    const timer = window.setTimeout(() => setVisibleEdgeCount((count) => count + 1), 1200);
    return () => window.clearTimeout(timer);
  }, [isPlaying, orderedEdges.length, replayMode, visibleEdgeCount]);

  useEffect(() => {
    if (orderedEdges.length === 0) {
      setVisibleEdgeCount(1);
      return;
    }
    setVisibleEdgeCount((count) => Math.min(Math.max(count, 1), orderedEdges.length));
  }, [orderedEdges.length]);

  useEffect(() => {
    if (!flowInstance || nodes.length === 0) return;
    const timer = window.setTimeout(() => {
      flowInstance.fitView({ padding: 0.18, duration: 360, includeHiddenNodes: false });
    }, 90);
    return () => window.clearTimeout(timer);
  }, [boundaryView, edges.length, flowInstance, nodes.length, visibleEdgeCount]);

  useEffect(() => {
    let cancelled = false;
    async function loadRecords() {
      try {
        const records = await listGlassBoxRecords(5);
        if (!cancelled) setRecentRecords(records);
      } catch {
        if (typeof window === "undefined" || cancelled) return;
        const raw = window.localStorage.getItem(LOCAL_RECORDS_KEY);
        if (!raw) return;
        try {
          setRecentRecords(JSON.parse(raw).slice(0, 5));
        } catch {
          setRecentRecords([]);
        }
      }
    }
    loadRecords();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const { levels, rowsByLevel } = buildLayout(visibleNodes, visibleEdges);
    const participating = new Set<string>();
    const blockedNodes = new Set<string>();
    visibleEdges.forEach((edge) => {
      participating.add(edge.source);
      participating.add(edge.target);
      if (edge.status === "blocked") {
        blockedNodes.add(edge.source);
        blockedNodes.add(edge.target);
      }
    });

    const flowNodes: Node[] = visibleNodes.map((node) => {
      const level = levels.get(node.id) || 0;
      const row = (rowsByLevel.get(level) || []).indexOf(node.id);
      const isActive = activeEdge?.source === node.id || activeEdge?.target === node.id;
      const tone = nodeTone(node, isActive, blockedNodes.has(node.id));

      return {
        id: node.id,
        position: { x: 48 + level * COLUMN_WIDTH, y: 48 + Math.max(row, 0) * ROW_HEIGHT },
        data: { label: node.label || node.id },
        style: {
          width: NODE_WIDTH,
          minHeight: 66,
          padding: "14px 16px",
          borderRadius: 8,
          border: tone.border,
          background: tone.background,
          color: "#0f172a",
          boxShadow: tone.shadow,
          fontSize: 13,
          fontWeight: 700,
          opacity: participating.has(node.id) ? 1 : 0.7,
          transition: "transform 220ms ease, box-shadow 220ms ease, border-color 220ms ease, opacity 220ms ease",
          cursor: "pointer",
        },
      };
    });

    const flowEdges: Edge[] = visibleEdges.map((edge, index) => {
      const permissions = edge.permissions || [];
      const isActive = index === visibleEdges.length - 1;
      const tone = edgeTone(edge, isActive);
      return {
        id: edge.id || `edge-${edge.source}-${edge.target}-${index}`,
        source: edge.source,
        target: edge.target,
        animated: edge.status !== "blocked" && (isActive || isPlaying),
        label: edge.status === "blocked" ? "blocked escalation" : shortPermissions(permissions),
        markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18, color: tone.stroke },
        style: {
          stroke: tone.stroke,
          strokeWidth: tone.width,
          strokeDasharray: edge.status === "blocked" ? "8 5" : undefined,
        },
        labelStyle: { fill: tone.label, fontSize: 11, fontWeight: 700 },
        labelBgStyle: { fill: tone.labelBg, fillOpacity: 0.94 },
        data: {
          source: edge.source,
          target: edge.target,
          permissions,
          budget: edge.budget || 0,
          status: edge.status || "verified",
          severity: edge.severity || "normal",
          proofSignature: edge.proofSignature,
          reason: edge.reason,
          step: index + 1,
        },
        interactionWidth: 28,
      };
    });

    setNodes(flowNodes);
    setEdges(flowEdges);
  }, [activeEdge, isPlaying, setEdges, setNodes, visibleEdges, visibleNodes]);

  const onEdgeClick = useCallback((event: React.MouseEvent, edge: Edge) => {
    event.stopPropagation();
    setSelectedProof(edge.data as SelectedProof);
  }, []);

  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    event.stopPropagation();
    const relatedEdge = [...visibleEdges]
      .reverse()
      .find((edge) => edge.source === node.id || edge.target === node.id);

    if (!relatedEdge) {
      setSelectedProof({
        source: node.id,
        target: node.id,
        permissions: [],
        budget: 0,
        status: "verified",
        severity: "normal",
        proofSignature: String(node.data?.label || node.id),
        reason: "Agent is present in the live delegation graph.",
        step: 0,
      });
      return;
    }

    const step = visibleEdges.findIndex((edge) => edge === relatedEdge) + 1;
    setSelectedProof({
      source: relatedEdge.source,
      target: relatedEdge.target,
      permissions: relatedEdge.permissions || [],
      budget: relatedEdge.budget || 0,
      status: relatedEdge.status || "verified",
      severity: relatedEdge.severity || "normal",
      proofSignature: relatedEdge.proofSignature,
      reason: relatedEdge.reason,
      step,
    });
  }, [visibleEdges]);

  const startReplay = useCallback(() => {
    setReplayMode(true);
    setIsPlaying(true);
    setVisibleEdgeCount(1);
    setSelectedProof(null);
    setSavedRecord(null);
    setSaveError(null);
  }, []);

  useEffect(() => {
    setReplayMode(true);
    setIsPlaying(true);
    setVisibleEdgeCount(1);
    setBoundaryView(false);
    setSelectedProof(null);
    setSavedRecord(null);
    setSaveError(null);
    setShowSnapshotTrail(false);
  }, [activeRunId]);

  const toggleBoundaryView = useCallback(() => {
    setBoundaryView((value) => {
      const nextValue = !value;
      setVisibleEdgeCount(nextValue ? Math.max(boundaryEventCount, 1) : Math.max(runOrderedEdges.length, 1));
      setSelectedProof(null);
      return nextValue;
    });
  }, [boundaryEventCount, runOrderedEdges.length]);

  const saveAuditRecord = useCallback(async () => {
    if (savingRecord) return;
    setSavingRecord(true);
    setShowSnapshotTrail(true);
    setSaveError(null);
    setSavedRecord(null);
    let snapshotNodes = data?.nodes || [];
    let snapshotEdges = allOrderedEdges;
    if (snapshotEdges.length === 0) {
      try {
        const liveGraph = await loadGraphData();
        snapshotNodes = liveGraph.nodes || [];
        snapshotEdges = [...(liveGraph.edges || [])].sort((left, right) => (left.timestamp || 0) - (right.timestamp || 0));
      } catch (error) {
        setSaveError(error instanceof Error ? `Snapshot unavailable: ${error.message}` : "Snapshot unavailable: graph did not load");
        setSavingRecord(false);
        return;
      }
    }
    const snapshotRunEdges = snapshotEdges.filter((edge) => activeRun.match(edge));
    const snapshotVisibleEdges = replayMode ? snapshotRunEdges.slice(0, Math.max(1, Math.min(visibleEdgeCount, snapshotRunEdges.length))) : snapshotRunEdges;
    if (snapshotRunEdges.length === 0) {
      setSaveError(`Snapshot unavailable: ${activeRun.title} has no live events yet`);
      setSavingRecord(false);
      return;
    }
    const exportedAt = new Date().toISOString();
    const record: GlassBoxRecord = {
      exported_at: exportedAt,
      source: "/api/v1/agents/delegation-graph",
      view: "Certior Agent Glass Box",
      mode: replayMode ? "replay" : "live",
      active_phase: `${activeRun.title}, ${activePhase}`,
      visible_events: snapshotVisibleEdges.length,
      total_events: snapshotRunEdges.length,
      blocked_events: snapshotRunEdges.filter((edge) => edge.status === "blocked").length,
      boundary_view: boundaryView,
      boundary_model: {
        engine: "Lean4",
        purpose: "Capability, permission, and budget bounds for orchestrated agents",
      },
      use_cases: ["multi-agent security", activeRun.title],
      selected_inspection: selectedProof,
      graph: {
        nodes: snapshotNodes,
        edges: snapshotRunEdges,
      },
    };
    const localRecord: GlassBoxRecord = {
      ...record,
      id: localRecordId(),
      record_hash: "syncing-server-hash",
      stored_at: Date.now() / 1000,
      storage: "browser-local-pending-server-sync",
    };
    const localPendingId = localRecord.id;
    setSavedRecord(localRecord);
    setRecentRecords((records) => [localRecord, ...records].slice(0, 5));
    if (typeof window !== "undefined") {
      const raw = window.localStorage.getItem(LOCAL_RECORDS_KEY);
      const existing = raw ? JSON.parse(raw) : [];
      window.localStorage.setItem(LOCAL_RECORDS_KEY, JSON.stringify([localRecord, ...existing].slice(0, 20)));
    }
    try {
      const nextRecord = await saveGlassBoxRecord(record);
      setSavedRecord(nextRecord);
      setRecentRecords((records) => [nextRecord, ...records.filter((item) => item.id !== nextRecord.id && item.id !== localPendingId)].slice(0, 5));
      if (typeof window !== "undefined") {
        const raw = window.localStorage.getItem(LOCAL_RECORDS_KEY);
        const existing = raw ? JSON.parse(raw) : [];
        window.localStorage.setItem(
          LOCAL_RECORDS_KEY,
          JSON.stringify([nextRecord, ...existing.filter((item: GlassBoxRecord) => item.id !== localPendingId && item.id !== nextRecord.id)].slice(0, 20)),
        );
      }
    } catch (error) {
      const localRecord: GlassBoxRecord = {
        ...record,
        id: `local_${Date.now()}`,
        record_hash: "pending-server-sync",
        stored_at: Date.now() / 1000,
        storage: "browser-local-fallback",
      };
      setSavedRecord(localRecord);
      setRecentRecords((records) => [localRecord, ...records].slice(0, 5));
      if (typeof window !== "undefined") {
        const raw = window.localStorage.getItem(LOCAL_RECORDS_KEY);
        const existing = raw ? JSON.parse(raw) : [];
        window.localStorage.setItem(LOCAL_RECORDS_KEY, JSON.stringify([localRecord, ...existing].slice(0, 20)));
      }
      setSaveError(error instanceof Error ? `Saved locally; server persistence unavailable: ${error.message}` : "Saved locally; server persistence unavailable");
    } finally {
      setSavingRecord(false);
    }
  }, [activePhase, activeRun, allOrderedEdges, boundaryView, data?.nodes, replayMode, savingRecord, selectedProof, visibleEdgeCount]);

  const hasSnapshotTrail = Boolean(savedRecord || saveError || visibleSnapshotRecords.length > 0);
  const showSnapshotPanel = showSnapshotTrail && hasSnapshotTrail;

  if (error) {
    return <div className="p-6 text-sm text-red-600">Failed to load graph data. Confirm the API and Studio proxy are running.</div>;
  }

  return (
    <div className="flex h-[calc(100vh-88px)] flex-col gap-3 text-slate-950">
      <div className="flex flex-col gap-3 border-b border-slate-200 pb-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="max-w-3xl">
          <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-blue-700">
            <Box className="h-4 w-4" />
            Agent handoff evidence
          </div>
          <h1 className="font-display text-2xl font-bold tracking-normal text-slate-950">Agent Glass Box</h1>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            Inspect agent handoffs as they request capabilities, hit Lean4-defined guardrails before delegated actions run, and leave evidence you can review during and after orchestration.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={saveAuditRecord}
            disabled={savingRecord}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 text-sm font-semibold text-emerald-800 shadow-sm hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Save className="h-4 w-4" />
            {savingRecord ? "Saving record" : "Record snapshot"}
          </button>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-50 px-4 py-3">
            <div className="flex items-center gap-3">
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-blue-600 text-white">
                <Activity className="h-4 w-4" />
              </span>
              <div>
                <div className="text-sm font-bold text-slate-950">{activePhase}</div>
                <div className="text-xs text-slate-500">
                  {isLoading ? "Loading graph" : `${visibleEdges.length}/${orderedEdges.length} events visible`}
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-600">
              <button
                type="button"
                onClick={startReplay}
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2 py-1 text-slate-700 hover:bg-slate-50"
              >
                <Clock3 className="h-3.5 w-3.5" />
                Replay
              </button>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-emerald-700">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Live API polling every 3s
              </span>
              <span className="rounded-md border border-red-200 bg-red-50 px-2 py-1 text-red-700">{blockedCount} blocked</span>
              <button
                type="button"
                onClick={toggleBoundaryView}
                className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 ${boundaryView ? "border-blue-300 bg-blue-50 text-blue-800" : "border-slate-200 bg-white text-slate-600"}`}
              >
                <Layers3 className="h-3.5 w-3.5" />
                {boundaryView ? `Boundary view on (${boundaryEventCount})` : `Boundary events ${boundaryEventCount}/${allOrderedEdges.length}`}
              </button>
            </div>
          </div>

          <div className="flex min-h-0 flex-1 overflow-hidden">
            <div className="flex min-w-0 flex-1 flex-col">
              <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-2 text-xs font-semibold text-slate-600">
                <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-blue-600" /> Intake</span>
                <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-emerald-600" /> Review</span>
                <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-amber-600" /> Release</span>
                <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-red-600" /> Blocked</span>
                <span className="ml-auto text-slate-500">{activeRun.title}</span>
              </div>

              <div className="relative min-h-0 flex-1 overflow-hidden bg-slate-50">
                <button
                  type="button"
                  onClick={toggleBoundaryView}
                  className="absolute right-6 top-5 z-20 inline-flex items-center gap-2 rounded-md border border-blue-200 bg-white/90 px-3 py-2 text-xs font-bold text-blue-800 shadow-sm hover:bg-blue-50"
                >
                  <Layers3 className="h-4 w-4" />
                  {boundaryView ? `Showing ${boundaryEventCount} boundary events` : "Focus boundary-critical events"}
                </button>
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={onNodeClick}
                  onEdgeClick={onEdgeClick}
                  onInit={setFlowInstance}
                  proOptions={{ hideAttribution: true }}
                  fitView
                  fitViewOptions={{ padding: 0.12 }}
                  minZoom={0.25}
                  maxZoom={1.8}
                  className="relative z-10"
                >
                  <Controls position="top-left" />
                  <Background gap={22} size={1} color="#d5dde7" />
                </ReactFlow>
              </div>
            </div>
          </div>

          <div className="max-h-[38vh] shrink-0 overflow-auto border-t border-slate-200 bg-white">
            <div className={`grid gap-3 p-3 ${showSnapshotPanel ? "xl:grid-cols-[minmax(0,1fr)_300px]" : "grid-cols-1"}`}>
              <div className="min-w-0">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-bold uppercase text-slate-500">Lean control</div>
                  <button
                    type="button"
                    onClick={() => setShowSnapshotTrail((value) => !value)}
                    disabled={!hasSnapshotTrail}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-bold text-slate-600 shadow-sm hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    Snapshot trail
                    {hasSnapshotTrail && <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-500">latest</span>}
                  </button>
                </div>
                {selectedProof ? (
                  <div className="grid gap-3 lg:grid-cols-[180px_minmax(0,1.1fr)_minmax(220px,0.9fr)_minmax(260px,1fr)_36px] lg:items-start">
                    <div className="min-w-0">
                  <div className={`inline-flex items-center gap-2 rounded-md px-2 py-1 text-xs font-bold ${selectedProof.status === "blocked" ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"}`}>
                    {selectedProof.status === "blocked" ? <Ban className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
                    {selectedProof.status === "blocked" ? "Blocked before execution" : "Proof verified"}
                  </div>
                  <div className="mt-1 text-xs font-semibold text-slate-500">Step {selectedProof.step}</div>
                </div>

                    <div className="min-w-0">
                  <div className="text-xs font-semibold uppercase text-slate-500">Handoff</div>
                  <div className="mt-1 rounded-md border border-slate-200 bg-slate-50 p-2 text-sm font-semibold leading-5 text-slate-900 break-words">
                    {selectedProof.source} -&gt; {selectedProof.target}
                  </div>
                </div>

                    <div className="min-w-0">
                  <div className="text-xs font-semibold uppercase text-slate-500">Requested bounds</div>
                  <div className="mt-1 flex max-h-24 flex-wrap gap-1.5 overflow-auto pr-1">
                    {selectedProof.permissions.length > 0 ? selectedProof.permissions.map((permission) => (
                      <span key={permission} className={`max-w-full rounded-md border px-2 py-1 text-xs font-semibold ${selectedProof.status === "blocked" ? "border-red-200 bg-red-50 text-red-800" : "border-blue-200 bg-blue-50 text-blue-800"}`}>
                        {formatPermissionLabel(permission)}
                      </span>
                    )) : (
                      <span className="rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-semibold text-slate-500">No extra permissions</span>
                    )}
                    <span className="rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-bold text-slate-700">{formatBudget(selectedProof.budget)}</span>
                  </div>
                </div>

                    <div className="min-w-0">
                  <div className="text-xs font-semibold uppercase text-slate-500">Evaluation</div>
                  <div className={`mt-1 rounded-md border p-2 text-sm font-semibold leading-5 break-words ${selectedProof.status === "blocked" ? "border-red-200 bg-red-50 text-red-800" : "border-emerald-200 bg-emerald-50 text-emerald-800"}`}>
                    {selectedProof.reason}
                  </div>
                  <details className="mt-1 text-xs text-slate-600">
                    <summary className="cursor-pointer font-semibold">Proof detail</summary>
                    <pre className="mt-1 max-h-20 overflow-auto rounded-md bg-slate-950 p-2 text-[11px] leading-relaxed text-slate-100">{selectedProof.proofSignature}</pre>
                  </details>
                </div>

                    <button
                  type="button"
                  onClick={() => setSelectedProof(null)}
                  className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-slate-200 text-slate-500 hover:bg-slate-50 hover:text-slate-950"
                  aria-label="Close proof details"
                >
                  <X className="h-4 w-4" />
                </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs font-semibold text-slate-500">
                    <ShieldCheck className="h-4 w-4 text-slate-400" />
                    Select a node or edge to inspect its verifier result.
                  </div>
                )}
              </div>

              {showSnapshotPanel && <aside className={`min-w-0 rounded-md border p-3 text-xs ${saveError ? "border-amber-200 bg-amber-50 text-amber-800" : "border-slate-200 bg-slate-50 text-slate-700"}`}>
                <div className="flex items-center justify-between gap-2">
                  <div className="font-bold uppercase text-slate-500">Snapshot trail</div>
                  <button type="button" onClick={() => setShowSnapshotTrail(false)} className="rounded p-1 text-slate-400 hover:bg-white hover:text-slate-700" aria-label="Hide snapshot trail">
                    <X className="h-3.5 w-3.5" />
                  </button>
                  {savedRecord && <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-bold uppercase text-emerald-700">recorded</span>}
                </div>
                {savedRecord && (
                  <div className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 p-2 text-emerald-800">
                    <div className="font-bold">Audit snapshot recorded</div>
                    <div className="mt-1 truncate font-semibold">{savedRecord.id}</div>
                    <div className="mt-1 truncate text-[11px]">{savedRecord.record_hash?.slice(0, 28)}...{savedRecord.storage ? `, ${savedRecord.storage}` : ""}</div>
                  </div>
                )}
                {saveError && <div className="mt-2 rounded-md border border-amber-200 bg-white/70 p-2 font-semibold">{saveError}</div>}
                {visibleSnapshotRecords.length > 0 ? (
                  <div className="mt-2 space-y-1.5">
                    {visibleSnapshotRecords.map((record) => (
                      <div key={record.id} className="flex items-center justify-between gap-2 rounded border border-white/70 bg-white/80 px-2 py-1.5 font-semibold">
                        <span className="min-w-0 truncate">{record.id}</span>
                        <span className="shrink-0 text-[11px] text-slate-500">{pluralize(record.blocked_events, "blocked")}, {pluralize(record.total_events, "event")}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-2 text-slate-500">No recorded snapshots yet.</div>
                )}
              </aside>}
            </div>
          </div>
      </div>
    </div>
  );
}
