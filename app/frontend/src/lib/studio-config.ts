import type { WorkflowStageRequest } from "./types";

export interface StageRoleOption {
  value: string;
  label: string;
  hint: string;
}

export interface TaskTemplate {
  id: string;
  label: string;
  task: string;
  compliance_policy: string;
  budget_cents: number;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  stages: WorkflowStageRequest[];
}

export const STAGE_ROLE_OPTIONS: StageRoleOption[] = [
  {
    value: "intake",
    label: "Intake",
    hint: "Collects context and prepares a safe internal artifact for the next stage.",
  },
  {
    value: "reviewer",
    label: "Reviewer",
    hint: "Validates disclosure risk, reasoning quality, and policy compliance.",
  },
  {
    value: "release",
    label: "Release",
    hint: "Makes the final release decision after upstream review evidence is present.",
  },
  {
    value: "worker",
    label: "Specialist",
    hint: "Performs a bounded task under its own policy and budget.",
  },
];

export const TASK_TEMPLATES: TaskTemplate[] = [
  {
    id: "privacy-review",
    label: "Privacy Review",
    task: "Review the intake note for privacy-sensitive details and return a safe internal recommendation.",
    compliance_policy: "hipaa",
    budget_cents: 1800,
  },
  {
    id: "policy-summary",
    label: "Policy Summary",
    task: "Summarize the provided material into an internal briefing with clear action items and no unnecessary disclosure.",
    compliance_policy: "default",
    budget_cents: 1200,
  },
  {
    id: "release-check",
    label: "Release Check",
    task: "Evaluate whether this artifact is ready for external release and explain any remaining blockers.",
    compliance_policy: "legal_privilege",
    budget_cents: 1600,
  },
];

export const WORKFLOW_TEMPLATES: WorkflowTemplate[] = [
  {
    id: "two-stage-review",
    name: "Two-stage review workflow",
    description: "Sequential specialist flow with independent verification at each step.",
    stages: [
      {
        name: "Intake",
        task: "Draft a minimum-necessary intake artifact for downstream review.",
        compliance_policy: "hipaa",
        budget_cents: 1500,
        stage_role: "intake",
      },
      {
        name: "Review",
        task: "Review the prior artifact for disclosure, privilege, and policy leakage. Return GO or NO-GO with rationale.",
        compliance_policy: "legal_privilege",
        budget_cents: 1200,
        stage_role: "reviewer",
      },
    ],
  },
  {
    id: "compliance-handoff",
    name: "Compliance handoff workflow",
    description: "Moves from internal analysis to release readiness with a clear reviewer checkpoint.",
    stages: [
      {
        name: "Analysis",
        task: "Prepare an internal analysis brief with key risks, policy references, and unresolved questions.",
        compliance_policy: "default",
        budget_cents: 1400,
        stage_role: "worker",
      },
      {
        name: "Approval Review",
        task: "Review the brief, identify any release blockers, and return an approval recommendation.",
        compliance_policy: "sox",
        budget_cents: 1500,
        stage_role: "reviewer",
      },
    ],
  },
];