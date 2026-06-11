/* ──────────────────────────────────────────────────────────────
  LoginGate - email/password sign-in and first-run registration.
  Uses the backend API-key auth under the hood and keeps the
  returned key in the browser for quick return visits.
  ────────────────────────────────────────────────────────────── */

import { useState } from "react";
import * as api from "@/lib/api";
import BrandMark from "./BrandMark";

interface Props {
  onAuthenticated: () => void;
  authError?: string | null;
}

export default function LoginGate({ onAuthenticated, authError }: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [name, setName] = useState("");
  const [organization, setOrganization] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [registerOpen, setRegisterOpen] = useState(false);

  const handleLogin = async () => {
    if (!email.trim() || !password.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(email.trim(), password);
      api.setApiKey(res.api_key);
      onAuthenticated();
    } catch (e) {
      api.clearApiKey();
      setError(e instanceof api.ApiError ? e.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!email.trim() || !password.trim() || password !== confirmPassword) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.register(email.trim(), password, {
        name: name.trim() || email.trim(),
        organization: organization.trim() || undefined,
      });
      api.setApiKey(res.api_key);
      setRegisterOpen(false);
      onAuthenticated();
    } catch (e) {
      setError(e instanceof api.ApiError ? e.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  const canOpenRegister =
    !!email.trim() &&
    password.length >= 8 &&
    confirmPassword.length >= 8 &&
    password === confirmPassword;

  const resetRegisterDialog = () => {
    setRegisterOpen(false);
    setName("");
    setOrganization("");
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(230,186,143,0.22),_transparent_28%),radial-gradient(circle_at_82%_12%,_rgba(243,222,198,0.28),_transparent_24%),radial-gradient(circle_at_bottom_right,_rgba(156,182,145,0.14),_transparent_28%)]" />
      <div className="relative grid w-full max-w-5xl gap-6 lg:grid-cols-[1.18fr_0.82fr]">
        <section className="panel-warm rounded-[36px] px-7 py-8 lg:px-12 lg:py-12">
          <div className="flex min-h-full max-w-xl items-center">
            <BrandMark
              size={72}
              variant="editorial"
              subtitle="verified agentic operations"
              className="items-start"
            />
          </div>
        </section>

        <div className="card panel-warm rounded-[30px] p-6 lg:p-7 space-y-5">
          <p className="text-sm font-medium tracking-[0.01em] text-slate-700">Sign in to enter Certior Studio</p>

          {authError && (
            <div className="rounded-2xl border border-warn/20 bg-warn-bg px-4 py-3 text-sm text-warn">
              <p className="font-medium">Session reset</p>
              <p className="mt-1 text-xs leading-5">{authError}. Sign in again to restore your session.</p>
            </div>
          )}

          <div className="flex rounded-xl bg-base-800 p-0.5" role="tablist" aria-label="Authentication method">
            <button
              role="tab"
              aria-selected={mode === "login"}
              onClick={() => { setMode("login"); setError(null); }}
              className={`flex-1 rounded-md py-2 text-xs font-medium transition-colors ${
                mode === "login" ? "bg-white text-slate-800" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              Sign in
            </button>
            <button
              role="tab"
              aria-selected={mode === "register"}
              onClick={() => { setMode("register"); setError(null); }}
              className={`flex-1 rounded-md py-2 text-xs font-medium transition-colors ${
                mode === "register" ? "bg-white text-slate-800" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              Register
            </button>
          </div>

          {mode === "login" ? (
            <>
              <div>
                <label htmlFor="email-input" className="block label mb-1.5">Email</label>
                <input
                  id="email-input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="input-field"
                  autoFocus
                  autoComplete="email"
                />
              </div>
              <div>
                <label htmlFor="password-input" className="block label mb-1.5">Password</label>
                <input
                  id="password-input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                  placeholder="Enter your password"
                  className="input-field"
                  autoComplete="current-password"
                />
              </div>
              <button onClick={handleLogin} disabled={loading || !email.trim() || !password.trim()} className="btn-primary w-full">
                {loading ? "Signing in…" : "Sign in"}
              </button>
            </>
          ) : (
            <>
              <div>
                <label htmlFor="email-input" className="block label mb-1.5">Email</label>
                <input
                  id="email-input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="input-field"
                  autoFocus
                  autoComplete="email"
                />
              </div>
              <div>
                <label htmlFor="register-password-input" className="block label mb-1.5">Password</label>
                <input
                  id="register-password-input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  className="input-field"
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label htmlFor="confirm-password-input" className="block label mb-1.5">Confirm password</label>
                <input
                  id="confirm-password-input"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && canOpenRegister && setRegisterOpen(true)}
                  placeholder="Repeat your password"
                  className="input-field"
                  autoComplete="new-password"
                />
              </div>
              <button onClick={() => setRegisterOpen(true)} disabled={!canOpenRegister || loading} className="btn-primary w-full">
                Continue
              </button>
            </>
          )}

          {error && <p className="text-xs text-blocked text-center" role="alert">{error}</p>}
        </div>

        {registerOpen && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-slate-900/18 px-4 py-8 backdrop-blur-[2px]">
            <div className="w-full max-w-md rounded-[28px] border border-base-700/60 bg-[linear-gradient(180deg,rgba(255,252,247,0.98),rgba(248,239,228,0.96))] p-6 shadow-[0_28px_80px_rgba(89,65,47,0.24)]">
              <div className="space-y-2">
                <p className="label">Register</p>
                <h3 className="text-2xl font-display text-slate-900">Create your profile</h3>
                <p className="text-sm leading-6 text-slate-600">Add a few details, then Studio will create the account and sign you in immediately.</p>
              </div>

              <div className="mt-5 space-y-4">
                <div>
                  <label htmlFor="name-input" className="block label mb-1.5">Full name</label>
                  <input
                    id="name-input"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Your name"
                    className="input-field"
                    autoComplete="name"
                  />
                </div>
                <div>
                  <label htmlFor="organization-input" className="block label mb-1.5">Organization (optional)</label>
                  <input
                    id="organization-input"
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleRegister()}
                    placeholder="Team or company"
                    className="input-field"
                    autoComplete="organization"
                  />
                </div>
              </div>

              <div className="mt-6 flex gap-3">
                <button onClick={resetRegisterDialog} className="btn-ghost flex-1 border border-base-700/60">
                  Back
                </button>
                <button onClick={handleRegister} disabled={loading} className="btn-primary flex-1">
                  {loading ? "Creating account…" : "Create account"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
