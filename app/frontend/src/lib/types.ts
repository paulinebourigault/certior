/* ──────────────────────────────────────────────────────────────
   Certior API type definitions
   Mirrors the Python dataclasses / Pydantic models exactly.
   ────────────────────────────────────────────────────────────── */

// ── Auth ──

export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "operator" | "viewer";
  created_at: number;
  is_active: boolean;
}

/** Backend RegisterResponse - does NOT include created_at / is_active. */
export interface RegisterResponse {
  id: string;
  email: string;
  name: string;
  role: string;
  api_key: string;
}

export interface LoginResponse {
  api_key: string;
  user: User;
}

// ── Executions ──

export type ExecutionStatus =
  | "queued"
  | "planning"
  | "executing"
  | "verifying"
  | "completed"
  | "failed"
  | "cancelled";

export interface VerificationSummary {
  steps: number;
  duration_ms: number | null;
  total_input_tokens: number;
  total_output_tokens: number;
}

export interface Execution {
  id: string;
  user_id: string;
  task: string;
  status: ExecutionStatus;
  current_step: number;
  error: string;
  created_at: number;          // epoch seconds
  updated_at: number;          // epoch seconds
  completed_at: number | null; // epoch seconds | null
  cost_cents: number;
  certificate_count: number;
  certificate_ids?: string[];
  proof_properties?: string[];
  compliance_policy?: string | null;
  output?: string | null;                       // agent's final text output
  verification_summary?: VerificationSummary;   // verification stats
}

// ── Tasks ──

export interface TaskRequest {
  task: string;
  compliance_policy?: string;
  budget_cents?: number;
  webhook_url?: string;
  permissions?: string[];
  provider?: string;   // "anthropic" | "openai"
  model?: string;      // e.g. "gpt-4o-mini", "claude-haiku-4-5-20251001"
  api_key?: string;
}

export interface TaskResponse {
  execution_id: string;
  status: string;
  websocket_url: string;
}

// ── Workflows ──

export type WorkflowStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type WorkflowStageStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "blocked"
  | "cancelled";

export interface WorkflowStageRequest {
  name: string;
  task: string;
  compliance_policy: string;
  budget_cents: number;
  stage_role: string;
  provider?: string;
  model?: string;
  api_key?: string;
  permissions?: string[];
  upstream_stage_ids?: string[];
}

export interface WorkflowRequest {
  name: string;
  description?: string;
  stages: WorkflowStageRequest[];
}

export interface WorkflowStage {
  id: string;
  name: string;
  task: string;
  compliance_policy: string;
  budget_cents: number;
  stage_role: string;
  provider?: string | null;
  model?: string | null;
  permissions: string[];
  upstream_stage_ids: string[];
  status: WorkflowStageStatus;
  execution_id?: string | null;
  started_at?: number | null;
  completed_at?: number | null;
  error: string;
  output_summary?: string | null;
}

export interface Workflow {
  id: string;
  user_id: string;
  user_role: string;
  name: string;
  description: string;
  mode: string;
  status: WorkflowStatus;
  created_at: number;
  updated_at: number;
  completed_at?: number | null;
  current_stage_index: number;
  error: string;
  stage_count: number;
  completed_stage_count: number;
  stages: WorkflowStage[];
}

export interface WorkflowExportStage {
  stage: WorkflowStage;
  execution?: Record<string, unknown> | null;
  compliance_package?: Record<string, unknown> | null;
}

export interface WorkflowExport {
  workflow: Workflow;
  exported_at: number;
  stages: WorkflowExportStage[];
}

// ── Compliance ──

export interface CompliancePreset {
  name: string;
  key: string;
  required_proofs: string[];
  human_approvals: string[];
  retention_days: number;
}

export interface ComplianceCertificate {
  id: string;
  type?: string;
  prover?: string;
  verified_properties?: string[];
  detail?: string;
  regime?: string;
  profile_name?: string;
  requirements?: string[];
  all_passed?: boolean;
  [k: string]: unknown;
}

export interface ComplianceAttestation {
  regime: string;
  retention_days: number;
  proofs_required: string[];
  proofs_satisfied: string[];
  proofs_missing: string[];
  human_approvals_required: string[];
  certificate_count: number;
  verified_properties: string[];
  compliant: boolean;
}

export interface VerificationRuntimeSummary {
  lean_status: "active" | "unavailable" | "unknown" | string;
  mode: string;
  detail: string;
  binary?: string;
  steps_checked: number;
  certificates_issued: number;
  flow_violations: number;
  total_requests: number;
  avg_latency_ms: number;
}

export interface CompliancePackage {
  package_id: string;
  compliance_regime: string;
  generated_at: number;
  execution_summary: Record<string, unknown>;
  certificates: ComplianceCertificate[];
  safety_scans: unknown[];
  flow_analysis: Record<string, unknown>;
  verification_runtime: VerificationRuntimeSummary;
  policy_applied: { name: string; [k: string]: unknown };
  audit_trail: unknown[];
  attestation: ComplianceAttestation;
}

// ── Tokens ──

export interface CapabilityToken {
  id: string;
  agent_id: string;
  permissions: string[];
  budget_cents: number;
  budget_remaining_cents: number;
  valid: boolean;
}

// ── LLM Providers ──

export interface ProviderInfo {
  id: string;        // "anthropic" | "openai"
  name: string;      // "Anthropic (Claude)"
  available: boolean; // API key configured
  active: boolean;   // currently selected default
  model: string;     // current model
  models: string[];  // all available models
}

export interface ProvidersResponse {
  providers: ProviderInfo[];
  active_provider: string | null;
  mode: string; // "agentic" | "legacy"
}

export interface ProviderValidationResponse {
  provider: string;
  model: string;
  valid: boolean;
  status: string;
  message: string;
}

// ── WebSocket ──

export interface WsUpdate {
  execution_id: string;
  status: string;
  data: Record<string, unknown>;
  timestamp?: number;
  type?: string;
}
