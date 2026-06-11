import Head from "next/head";
import { useCallback, useEffect, useState } from "react";
import { useAuth, useRuntimeLLMSetup } from "@/lib/hooks";
import * as api from "@/lib/api";
import { useToast } from "@/components/Toast";
import type { ProviderInfo } from "@/lib/types";
import LLMSetupDialog from "@/components/LLMSetupDialog";

export default function SettingsPage() {
  const { user } = useAuth();
  const { setup, save, clear } = useRuntimeLLMSetup();
  const { toast } = useToast();
  const [rotating, setRotating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [mode, setMode] = useState<string>("legacy");
  const [setupOpen, setSetupOpen] = useState(false);

  const loadProviders = useCallback(() => {
    api.getProviders().then((response) => {
      setProviders(response.providers);
      setMode(response.mode);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  const handleRotateKey = useCallback(async () => {
    setRotating(true);
    try {
      const key = await api.rotateKey();
      setNewKey(key);
      api.setApiKey(key);
      toast("success", "API key rotated");
      setConfirmRotate(false);
    } catch (error) {
      toast("error", error instanceof api.ApiError ? error.message : "Key rotation failed");
    } finally {
      setRotating(false);
    }
  }, [toast]);

  const handleLogout = useCallback(() => {
    api.clearApiKey();
    window.location.reload();
  }, []);

  if (!user) return null;

  return (
    <>
      <Head>
        <title>Certior Studio - Settings</title>
      </Head>

      <LLMSetupDialog
        open={setupOpen}
        initialSetup={setup}
        onClose={() => setSetupOpen(false)}
        onSaved={(next) => {
          save(next);
          setSetupOpen(false);
          toast("success", "Model setup saved");
        }}
      />

      <div className="p-6 lg:p-8 max-w-2xl mx-auto space-y-8">
        <div className="hero-band rounded-[30px] border border-base-700/60 px-6 py-6 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="label mb-2">Account and runtime</p>
              <h1 className="text-3xl font-semibold font-display text-slate-900">Settings</h1>
              <p className="mt-2 max-w-xl text-sm leading-6 text-slate-600">Manage operator access, update the model setup for this browser session, and rotate the Certior API key when needed.</p>
            </div>
            <div className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-3 text-sm text-slate-600">
              <p className="font-medium text-slate-900">Session-based model setup</p>
              <p className="mt-1 text-xs">Provider keys stay in the browser session.</p>
            </div>
          </div>
        </div>

        <section className="panel-warm rounded-[28px] overflow-hidden">
          <div className="border-b border-base-700/40 px-6 py-4">
            <h2 className="label mb-0">Profile</h2>
          </div>
          <div className="px-6 py-5 space-y-4">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-accent/20 to-proof/20 border border-base-600/40 flex items-center justify-center text-lg font-display font-bold text-slate-700">
                {user.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-medium text-slate-800">{user.name}</p>
                <p className="text-xs text-slate-500">{user.email}</p>
              </div>
              <span className={`badge ml-auto ${user.role === "admin" ? "bg-proof-bg text-proof border border-proof/20" : user.role === "operator" ? "bg-accent-bg text-accent border border-accent/20" : "bg-base-700/50 text-slate-500 border border-base-600/30"}`}>
                {user.role}
              </span>
            </div>
          </div>
        </section>

        <section className="panel-warm rounded-[28px] overflow-hidden">
          <div className="border-b border-base-700/40 px-6 py-4 flex items-center justify-between">
            <h2 className="label mb-0">Model setup</h2>
            <span className={`badge text-[10px] ${mode === "agentic" ? "bg-verified-bg text-verified border border-verified/20" : "bg-warn-bg text-warn border border-warn/20"}`}>
              {mode === "agentic" ? "Studio default ready" : "Studio default only"}
            </span>
          </div>
          <div className="px-6 py-5 space-y-4">
            <div className="rounded-2xl border border-base-700/60 bg-white/82 p-4 space-y-3">
              <p className="text-sm font-medium text-slate-800">Browser session</p>
              <p className="text-sm text-slate-600">{setup?.valid ? `${setup.provider}, ${setup.model}` : "No validated model setup saved for this browser session."}</p>
              <div className="flex flex-wrap gap-2">
                <button onClick={() => setSetupOpen(true)} className="btn-primary px-4 py-2 text-sm">
                  {setup?.valid ? "Update" : "Set up"}
                </button>
                {setup?.valid && (
                  <button onClick={() => { clear(); toast("info", "Model setup cleared"); }} className="btn-ghost px-4 py-2 text-sm text-blocked hover:text-blocked">
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="grid gap-3">
              {providers.map((provider) => (
                <div key={provider.id} className="rounded-lg border border-base-700/60 bg-white/75 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-slate-800">{provider.name}</p>
                      <p className="text-xs text-slate-500">{provider.available ? provider.model : "Not configured in the backend"}</p>
                    </div>
                    {provider.active && <span className="badge bg-accent-bg text-accent border border-accent/20">Default provider</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel-warm rounded-[28px] overflow-hidden">
          <div className="border-b border-base-700/40 px-6 py-4">
            <h2 className="label mb-0">Certior API key</h2>
          </div>
          <div className="px-6 py-5 space-y-4">
            <div>
              <p className="label mb-1.5">Current key</p>
              <div className="flex items-center gap-2">
                <code className="mono text-slate-600 bg-white/70 px-3 py-2 rounded-lg border border-base-700/40 flex-1">
                  ck-••••••••••••••••••••••••••••••••
                </code>
              </div>
            </div>

            {newKey && (
              <div className="rounded-2xl border border-verified/20 bg-verified-bg p-4 space-y-2 animate-slide-up">
                <p className="text-xs font-medium text-verified">New API key</p>
                <div className="relative">
                  <input readOnly value={newKey} className="input-field font-mono text-xs pr-16" onFocus={(event) => event.target.select()} aria-label="New API key" />
                  <button onClick={() => { navigator.clipboard.writeText(newKey); toast("info", "Copied to clipboard"); }} className="absolute right-2 top-1/2 -translate-y-1/2 btn-ghost text-[10px] px-2 py-1" aria-label="Copy new API key">
                    Copy
                  </button>
                </div>
              </div>
            )}

            {!confirmRotate ? (
              <button onClick={() => setConfirmRotate(true)} className="btn-ghost text-xs text-warn/90 hover:text-warn">
                Rotate API key
              </button>
            ) : (
              <div className="rounded-2xl border border-warn/20 bg-warn-bg p-4 space-y-3 animate-slide-up">
                <p className="text-xs text-warn">This revokes the current key and issues a new one.</p>
                <div className="flex gap-2">
                  <button onClick={handleRotateKey} disabled={rotating} className="btn text-xs bg-warn/10 text-warn border border-warn/20 hover:bg-warn/20">
                    {rotating ? "Rotating..." : "Confirm"}
                  </button>
                  <button onClick={() => setConfirmRotate(false)} className="btn-ghost text-xs">Cancel</button>
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="panel-warm rounded-[28px] overflow-hidden border-blocked/10">
          <div className="border-b border-base-700/40 px-6 py-4">
            <h2 className="label mb-0 text-blocked/60">Sign out</h2>
          </div>
          <div className="px-6 py-5">
            <button onClick={handleLogout} className="btn-danger text-xs">Sign out of Studio</button>
          </div>
        </section>
      </div>
    </>
  );
}
