import { useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import type { ProviderInfo } from "@/lib/types";
import type { RuntimeLLMSetup } from "@/lib/runtime-llm";

interface Props {
  open: boolean;
  initialSetup?: RuntimeLLMSetup | null;
  onClose?: () => void;
  onSaved: (setup: RuntimeLLMSetup) => void;
}

const FALLBACK_PROVIDERS: ProviderInfo[] = [
  {
    id: "openai",
    name: "OpenAI",
    available: true,
    active: false,
    model: "gpt-4o",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o4-mini", "o3-mini"],
  },
  {
    id: "anthropic",
    name: "Anthropic",
    available: true,
    active: false,
    model: "claude-sonnet-4-20250514",
    models: ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-20250514"],
  },
];

const PROVIDER_HINTS: Record<string, string> = {
  openai: "Best for teams already running GPT-based review or drafting flows.",
  anthropic: "Best for longer analytical prompts and staged review steps.",
};

export default function LLMSetupDialog({ open, initialSetup, onClose, onSaved }: Props) {
  const [providers, setProviders] = useState<ProviderInfo[]>(FALLBACK_PROVIDERS);
  const [provider, setProvider] = useState(initialSetup?.provider ?? "openai");
  const [model, setModel] = useState(initialSetup?.model ?? "gpt-4o-mini");
  const [apiKey, setApiKey] = useState(initialSetup?.apiKey ?? "");
  const [validating, setValidating] = useState(false);
  const [status, setStatus] = useState(initialSetup?.status ?? "");
  const [message, setMessage] = useState(initialSetup?.message ?? "");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!open) return;
    api.getProviders().then((response) => {
      if (response.providers.length > 0) {
        setProviders(response.providers);
        const current = response.providers.find((item) => item.id === (initialSetup?.provider ?? provider));
        if (current && !model) {
          setModel(current.model);
        }
      }
    }).catch(() => {});
  }, [open, initialSetup?.provider, provider, model]);

  useEffect(() => {
    if (!open) return;
    setProvider(initialSetup?.provider ?? "openai");
    setModel(initialSetup?.model ?? "gpt-4o-mini");
    setApiKey(initialSetup?.apiKey ?? "");
    setStatus(initialSetup?.status ?? "");
    setMessage(initialSetup?.message ?? "");
    setSaved(false);
  }, [open, initialSetup]);

  const selectedProvider = useMemo(
    () => providers.find((item) => item.id === provider) ?? FALLBACK_PROVIDERS[0],
    [provider, providers],
  );

  const canSave = apiKey.trim().length >= 8 && model.trim().length > 0 && status === "ready" && !saved;
  const statusTone = saved
    ? "border-verified/20 bg-verified-bg text-verified"
    : status === "ready"
    ? "border-verified/20 bg-verified-bg text-verified"
    : status === "billing_issue" || status === "invalid_key" || status === "error"
      ? "border-blocked/20 bg-blocked-bg text-blocked"
      : "border-warn/20 bg-warn-bg text-warn";

  const handleValidate = async () => {
    if (!apiKey.trim() || !model.trim()) return;
    setValidating(true);
    setStatus("");
    setMessage("");
    try {
      const result = await api.validateProvider(provider, model.trim(), apiKey.trim());
      setStatus(result.status);
      setMessage(result.message);
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof api.ApiError ? error.message : "Validation failed");
    } finally {
      setValidating(false);
    }
  };

  const handleSave = () => {
    if (!canSave) return;
    const nextSetup = {
      provider,
      model: model.trim(),
      apiKey: apiKey.trim(),
      valid: true,
      status,
      message,
      validatedAt: Date.now(),
    };
    setSaved(true);
    setMessage("Saved for this browser session. You can start runs now.");
    window.setTimeout(() => {
      onSaved(nextSetup);
      onClose?.();
    }, 450);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Model setup">
      <div className="absolute inset-0 bg-white/55 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl panel-warm rounded-[30px] p-6 space-y-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <p className="label">Runtime setup</p>
            <h2 className="text-2xl font-display text-slate-900">Model setup</h2>
            <p className="text-sm text-slate-600">Choose a provider, model, and API key before submitting runs.</p>
          </div>
          <span className={`badge border ${statusTone}`}>{saved ? "Saved" : status === "ready" ? "Ready" : "Needs check"}</span>
        </div>

        <div className="space-y-3">
          <p className="label">Provider</p>
          <div className="grid gap-3 md:grid-cols-2">
            {providers.map((item) => {
              const selected = item.id === provider;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setProvider(item.id);
                    setModel(item.model);
                    setStatus("");
                    setMessage("");
                  }}
                  className={`rounded-[22px] border p-4 text-left transition-colors ${selected ? "border-accent/40 bg-accent-bg" : "border-base-700/50 bg-white/78 hover:bg-white/90"}`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-slate-900">{item.name}</p>
                      <p className="mt-1 text-xs text-slate-500">Default: {item.model}</p>
                    </div>
                    {selected && <span className="badge border border-accent/20 bg-white/80 text-accent">Selected</span>}
                  </div>
                </button>
              );
            })}
          </div>
          <div className="rounded-[22px] border border-base-700/50 bg-white/78 px-4 py-4 text-sm text-slate-600">
            <p className="font-medium text-slate-900">{selectedProvider.name}</p>
            <p className="mt-1 leading-6">{PROVIDER_HINTS[selectedProvider.id] ?? "Use the provider that matches your team’s model access and cost preferences."}</p>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="block label mb-2">Model</label>
            <input
              list="provider-models"
              value={model}
              onChange={(event) => {
                setModel(event.target.value);
                setStatus("");
                setMessage("");
              }}
              className="input-field"
              placeholder="Enter model name"
            />
            <datalist id="provider-models">
              {selectedProvider.models.map((item) => (
                <option key={item} value={item} />
              ))}
            </datalist>
          </div>
        </div>

        <div>
          <label className="block label mb-2">Provider API key</label>
          <input
            type="password"
            value={apiKey}
            onChange={(event) => {
              setApiKey(event.target.value);
              setStatus("");
              setMessage("");
            }}
            className="input-field font-mono text-xs"
            placeholder={provider === "anthropic" ? "sk-ant-..." : "sk-..."}
          />
          <p className="mt-2 text-xs text-slate-500">Stored only in this browser session and attached to runs at execution time.</p>
        </div>

        <div className={`rounded-[22px] border px-4 py-3 text-sm ${statusTone}`}>
          <p className="font-medium">Status</p>
          <p className="mt-1">{message || "Run validation to confirm the key and model can be used."}</p>
        </div>

        <div className="flex flex-wrap justify-end gap-3">
          {onClose && (
            <button type="button" onClick={onClose} className="btn-ghost text-sm px-4 py-2">
              Close
            </button>
          )}
          <button type="button" onClick={handleValidate} disabled={validating || !apiKey.trim() || !model.trim()} className="btn-ghost text-sm px-4 py-2 text-accent-dim hover:text-accent">
            {validating ? "Checking..." : "Check"}
          </button>
          <button type="button" onClick={handleSave} disabled={!canSave} className="btn-primary px-4 py-2">
            {saved ? "Saved" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}