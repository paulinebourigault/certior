/* ──────────────────────────────────────────────────────────────
   Certior API client
   Wraps fetch() + WebSocket with auth header injection,
   reconnection logic, and typed error handling.
   ────────────────────────────────────────────────────────────── */

import type {
  User,
  LoginResponse,
  RegisterResponse,
  TaskRequest,
  TaskResponse,
  Execution,
  CompliancePreset,
  CompliancePackage,
  CapabilityToken,
  ProvidersResponse,
  ProviderValidationResponse,
  WsUpdate,
  Workflow,
  WorkflowExport,
  WorkflowRequest,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? "";
const REQUEST_TIMEOUT_MS = 10000;

function resolveApiOrigin(): string {
  if (typeof window === "undefined") return BASE;
  if (BASE) {
    return new URL(BASE, window.location.origin).origin;
  }

  // In local development the Studio runs on 3001 while the backend runs on 8000.
  // Defaulting WebSockets to the Studio origin breaks live execution streaming.
  if (window.location.port === "3001") {
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }

  return window.location.origin;
}

function resolveWebSocketUrl(executionId: string): string {
  if (typeof window === "undefined") return "";

  const base = WS_BASE || resolveApiOrigin();
  const resolved = new URL(base, window.location.origin);
  resolved.protocol = resolved.protocol === "https:" ? "wss:" : "ws:";
  resolved.pathname = `/ws/executions/${executionId}`;
  resolved.search = "";
  resolved.hash = "";
  return resolved.toString();
}

// ── API key management ──

function getApiKey(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("certior_api_key") ?? "";
}

export function setApiKey(key: string) {
  localStorage.setItem("certior_api_key", key);
}

export function clearApiKey() {
  localStorage.removeItem("certior_api_key");
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}

// ── Request helpers ──

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
): Promise<T> {
  const key = getApiKey();
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  if (key) headers["Authorization"] = `Bearer ${key}`;

  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...opts,
      headers,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError(408, "Request timed out");
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? "Unknown error");
  }
  return res.json();
}

// ── Auth ──

export async function register(
  email: string,
  password?: string,
  options?: { name?: string; organization?: string },
): Promise<RegisterResponse> {
  return request<RegisterResponse>(
    "/api/v1/auth/register",
    {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        name: options?.name ?? email,
        organization: options?.organization ?? "",
      }),
    },
  );
}

export async function login(
  email: string,
  password: string,
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function getMe(): Promise<User> {
  return request<User>("/api/v1/auth/me");
}

export async function rotateKey(): Promise<string> {
  const data = await request<{ api_key: string }>("/api/v1/auth/rotate", {
    method: "POST",
  });
  return data.api_key;
}

// ── Tasks ──

export async function submitTask(req: TaskRequest): Promise<TaskResponse> {
  return request<TaskResponse>("/api/v1/tasks", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function createWorkflow(req: WorkflowRequest): Promise<Workflow> {
  return request<Workflow>("/api/v1/workflows", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function listWorkflows(
  status?: string,
  limit = 20,
): Promise<Workflow[]> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  params.set("limit", String(limit));
  return request<Workflow[]>(`/api/v1/workflows?${params}`);
}

export async function getWorkflow(id: string): Promise<Workflow> {
  return request<Workflow>(`/api/v1/workflows/${id}`);
}

export async function cancelWorkflow(
  id: string,
): Promise<{ workflow_id: string; status: string }> {
  return request(`/api/v1/workflows/${id}`, { method: "DELETE" });
}

export async function exportWorkflow(id: string): Promise<WorkflowExport> {
  return request<WorkflowExport>(`/api/v1/workflows/${id}/export`);
}

export async function downloadWorkflowExport(id: string): Promise<void> {
  const key = getApiKey();
  const headers: Record<string, string> = {};
  if (key) headers["Authorization"] = `Bearer ${key}`;
  const res = await fetch(`${BASE}/api/v1/workflows/${id}/export`, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? "Workflow export failed");
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `workflow-${id.slice(0, 8)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ── Executions ──

export async function listExecutions(
  status?: string,
  limit = 20,
): Promise<Execution[]> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  params.set("limit", String(limit));
  return request<Execution[]>(`/api/v1/executions?${params}`);
}

export async function getExecution(id: string): Promise<Execution> {
  return request<Execution>(`/api/v1/executions/${id}`);
}

export async function cancelExecution(
  id: string,
): Promise<{ execution_id: string; status: string }> {
  return request(`/api/v1/executions/${id}`, { method: "DELETE" });
}

// ── Compliance ──

export async function getCompliancePresets(): Promise<CompliancePreset[]> {
  return request<CompliancePreset[]>("/api/v1/compliance/presets");
}

export async function exportCompliance(
  executionId: string,
  preset?: string,
): Promise<CompliancePackage> {
  const query = preset ? `?preset=${encodeURIComponent(preset)}` : "";
  return request<CompliancePackage>(
    `/api/v1/compliance/${executionId}/export${query}`,
  );
}

export async function downloadCompliancePdf(
  executionId: string,
  preset?: string,
): Promise<void> {
  const key = getApiKey();
  const headers: Record<string, string> = {};
  if (key) headers["Authorization"] = `Bearer ${key}`;
  const query = new URLSearchParams({ format: "pdf" });
  if (preset) query.set("preset", preset);

  const res = await fetch(
    `${BASE}/api/v1/compliance/${executionId}/export?${query.toString()}`,
    { headers },
  );

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? "PDF download failed");
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `certior-audit-${executionId.slice(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function downloadComplianceJson(
  executionId: string,
  preset?: string,
): Promise<void> {
  const pkg = await exportCompliance(executionId, preset);
  const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `certior-audit-${executionId.slice(0, 8)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ── LLM Providers ──

export async function getProviders(): Promise<ProvidersResponse> {
  return request<ProvidersResponse>("/api/v1/settings/providers");
}

export async function switchProvider(
  provider: string,
  model?: string,
): Promise<{ provider: string; model: string; message: string }> {
  return request("/api/v1/settings/provider", {
    method: "POST",
    body: JSON.stringify({ provider, model: model || undefined }),
  });
}

export async function validateProvider(
  provider: string,
  model: string,
  apiKey: string,
): Promise<ProviderValidationResponse> {
  return request<ProviderValidationResponse>("/api/v1/settings/provider/validate", {
    method: "POST",
    body: JSON.stringify({ provider, model, api_key: apiKey }),
  });
}

// ── Tokens ──

export async function issueToken(
  agentId: string,
  permissions: string[],
  budgetCents: number,
): Promise<CapabilityToken> {
  return request<CapabilityToken>("/api/v1/tokens", {
    method: "POST",
    body: JSON.stringify({
      agent_id: agentId,
      permissions,
      budget_cents: budgetCents,
    }),
  });
}

// ── WebSocket with reconnection ──

interface WsConnection {
  close: () => void;
}

const WS_RECONNECT_BASE_MS = 1000;
const WS_RECONNECT_MAX_MS = 15000;
const WS_KEEPALIVE_MS = 25_000;

export function connectExecution(
  executionId: string,
  onUpdate: (update: WsUpdate) => void,
  onConnectionChange?: (connected: boolean) => void,
): WsConnection {
  let ws: WebSocket | null = null;
  let pingInterval: ReturnType<typeof setInterval> | null = null;
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  let disposed = false;

  function buildUrl(): string {
    return resolveWebSocketUrl(executionId);
  }

  function connect() {
    if (disposed) return;

    ws = new WebSocket(buildUrl());

    ws.onopen = () => {
      attempt = 0;
      onConnectionChange?.(true);
      // Keepalive ping
      pingInterval = setInterval(() => {
        if (ws?.readyState === WebSocket.OPEN) ws.send("ping");
      }, WS_KEEPALIVE_MS);
    };

    ws.onmessage = (e) => {
      try {
        const update = JSON.parse(e.data) as WsUpdate;
        onUpdate(update);
        // Stop reconnecting once execution is terminal
        const terminal = ["completed", "failed", "cancelled"];
        if (terminal.includes(update.status?.replace("execution.", "") ?? "")) {
          disposed = true;
        }
      } catch {
        // ignore non-JSON messages (pong, etc.)
      }
    };

    ws.onclose = () => {
      onConnectionChange?.(false);
      if (pingInterval) clearInterval(pingInterval);
      pingInterval = null;
      // Exponential backoff reconnect
      if (!disposed) {
        const delay = Math.min(
          WS_RECONNECT_BASE_MS * Math.pow(2, attempt),
          WS_RECONNECT_MAX_MS,
        );
        attempt += 1;
        reconnectTimeout = setTimeout(connect, delay);
      }
    };

    ws.onerror = () => {
      // onclose will fire after onerror, triggering reconnect
    };
  }

  connect();

  return {
    close: () => {
      disposed = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (pingInterval) clearInterval(pingInterval);
      ws?.close();
    },
  };
}
