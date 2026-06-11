export type GlassBoxOrchestration = {
  id: string;
  title: string;
  subtitle: string;
  status: "captured" | "complete" | "blocked";
  colorClass: string;
};

export const GLASS_BOX_ORCHESTRATIONS: GlassBoxOrchestration[] = [
  {
    id: "all",
    title: "All company agent traffic",
    subtitle: "Delegation and boundary events",
    status: "captured",
    colorClass: "bg-blue-600",
  },
  {
    id: "privacy-review",
    title: "Privacy review swarm",
    subtitle: "PHI review, redaction, policy checks",
    status: "captured",
    colorClass: "bg-emerald-600",
  },
  {
    id: "release-gate",
    title: "Public release gate",
    subtitle: "Approval, publish, audit logger",
    status: "complete",
    colorClass: "bg-amber-500",
  },
  {
    id: "security-blocks",
    title: "Security blocks",
    subtitle: "Denied cross-boundary escalations",
    status: "blocked",
    colorClass: "bg-red-600",
  },
  {
    id: "audit-evidence",
    title: "Audit evidence builders",
    subtitle: "Evidence graph and compliance trail",
    status: "captured",
    colorClass: "bg-violet-600",
  },
];