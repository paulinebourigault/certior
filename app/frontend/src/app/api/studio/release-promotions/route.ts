import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const API_BASE = process.env.INTERNAL_API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const DEMO_EMAIL = process.env.CERTIOR_STUDIO_DEMO_EMAIL || "studio-demo-reader@certior.local";
const DEMO_PASSWORD = process.env.CERTIOR_STUDIO_DEMO_PASSWORD || "certior-demo-password";
const REQUEST_TIMEOUT_MS = 10000;

async function backendFetch(path: string, init: RequestInit = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(`${API_BASE}${path}`, {
      ...init,
      cache: "no-store",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function readJson(response: Response) {
  return response.json().catch(() => ({}));
}

async function loginDemoUser() {
  const response = await backendFetch("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: DEMO_EMAIL, password: DEMO_PASSWORD }),
  });
  if (!response.ok) return null;
  const payload = await readJson(response);
  return typeof payload.api_key === "string" ? payload.api_key : null;
}

async function registerDemoUser(email = DEMO_EMAIL) {
  const response = await backendFetch("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email,
      name: "Studio Demo Reader",
      password: DEMO_PASSWORD,
      organization: "Certior",
      role: "admin",
    }),
  });
  if (!response.ok) return null;
  const payload = await readJson(response);
  return typeof payload.api_key === "string" ? payload.api_key : null;
}

async function getDemoApiKey() {
  if (process.env.CERTIOR_STUDIO_DEMO_API_KEY) return process.env.CERTIOR_STUDIO_DEMO_API_KEY;

  const existingKey = await loginDemoUser();
  if (existingKey) return existingKey;

  const registeredKey = await registerDemoUser();
  if (registeredKey) return registeredKey;

  const uniqueEmail = `studio-demo-reader-${Date.now()}@certior.local`;
  return registerDemoUser(uniqueEmail);
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const repoRoot = searchParams.get("repo_root") || "certior-oss/agents";
  const apiKey = await getDemoApiKey();

  if (!apiKey) {
    return NextResponse.json({ detail: "Studio demo operator could not be created." }, { status: 502 });
  }

  const response = await backendFetch(`/api/v1/releases/promotions?repo_root=${encodeURIComponent(repoRoot)}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "X-Operator-Role": "ADMIN",
    },
  });

  if (!response.ok) {
    const payload = await readJson(response);
    return NextResponse.json({ detail: payload.detail || "Release history unavailable." }, { status: response.status });
  }

  const payload = await readJson(response);
  return NextResponse.json({ ...payload, source: "live", repo_root: repoRoot });
}