export interface RuntimeLLMSetup {
  provider: string;
  model: string;
  apiKey: string;
  valid: boolean;
  status: string;
  message: string;
  validatedAt: number | null;
}

const META_KEY = "certior_runtime_llm_meta";
const SECRET_KEY = "certior_runtime_llm_secret";

interface RuntimeLLMMeta {
  provider: string;
  model: string;
  valid: boolean;
  status: string;
  message: string;
  validatedAt: number | null;
}

function readMeta(): RuntimeLLMMeta | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(META_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as RuntimeLLMMeta;
  } catch {
    return null;
  }
}

function readSecret(): string {
  if (typeof window === "undefined") return "";
  return sessionStorage.getItem(SECRET_KEY) ?? "";
}

export function getRuntimeLLMSetup(): RuntimeLLMSetup | null {
  const meta = readMeta();
  if (!meta) return null;
  return {
    ...meta,
    apiKey: readSecret(),
  };
}

export function saveRuntimeLLMSetup(setup: RuntimeLLMSetup) {
  if (typeof window === "undefined") return;
  const meta: RuntimeLLMMeta = {
    provider: setup.provider,
    model: setup.model,
    valid: setup.valid,
    status: setup.status,
    message: setup.message,
    validatedAt: setup.validatedAt,
  };
  localStorage.setItem(META_KEY, JSON.stringify(meta));
  sessionStorage.setItem(SECRET_KEY, setup.apiKey);
}

export function clearRuntimeLLMSetup() {
  if (typeof window === "undefined") return;
  localStorage.removeItem(META_KEY);
  sessionStorage.removeItem(SECRET_KEY);
}