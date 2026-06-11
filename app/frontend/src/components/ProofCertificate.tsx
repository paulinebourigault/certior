/* ──────────────────────────────────────────────────────────────
   ProofCertificate - renders a single proof certificate.
   Displays prover, verified properties, hash, and timestamp
   in a format that mirrors a mathematical proof document.
   ────────────────────────────────────────────────────────────── */

import { useState } from "react";

export interface CertificateData {
  id: string;
  prover: "z3" | "dafny" | "lean4" | string;
  theorem: string;
  properties: string[];
  plan_hash: string;
  issued_at: number;
  proof_trace?: string;
}

interface Props {
  certificate: CertificateData;
}

const PROVER_META: Record<string, { label: string; color: string }> = {
  z3:    { label: "Z3 SMT Solver", color: "text-accent" },
  dafny: { label: "Dafny",         color: "text-verified" },
  lean4: { label: "Lean 4",        color: "text-warn" },
};

export default function ProofCertificate({ certificate }: Props) {
  const [showTrace, setShowTrace] = useState(false);
  const prover = PROVER_META[certificate.prover] ?? { label: certificate.prover, color: "text-gray-400" };

  const issuedDate = new Date(
    certificate.issued_at < 1e12 ? certificate.issued_at * 1000 : certificate.issued_at,
  );

  return (
    <div className="card overflow-hidden animate-fade-in">
      {/* Decorative top line */}
      <div className="h-px bg-gradient-to-r from-transparent via-verified/40 to-transparent" />

      <div className="p-5 space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.15em] text-gray-500 font-medium">
              Proof Certificate
            </p>
            <p className="text-sm font-semibold text-gray-200 mt-0.5 font-display">
              {certificate.theorem.replace(/_/g, " ")}
            </p>
          </div>
          <span className={`badge border border-current/20 ${prover.color}`}>
            {prover.label}
          </span>
        </div>

        {/* Proven properties - styled like a formal proof */}
        <div className="rounded-lg bg-base-900/70 border border-base-700/40 p-4 space-y-2">
          <p className="text-[10px] uppercase tracking-[0.15em] text-gray-500 font-medium mb-2">
            Verified Properties
          </p>
          {certificate.properties.map((prop, i) => (
            <div key={i} className="flex items-start gap-2.5">
              <span className="text-verified font-mono text-xs mt-px flex-shrink-0">
                {i + 1}.
              </span>
              <div>
                <code className="font-mono text-xs text-gray-300 leading-relaxed">
                  {prop}
                </code>
                <span className="ml-2 text-verified text-[10px]">□</span>
              </div>
            </div>
          ))}
        </div>

        {/* Metadata */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <span className="text-gray-500 block mb-0.5">Certificate ID</span>
            <code className="mono text-gray-400">{certificate.id.slice(0, 12)}…</code>
          </div>
          <div>
            <span className="text-gray-500 block mb-0.5">Plan Hash</span>
            <code className="mono text-gray-400">{certificate.plan_hash.slice(0, 12)}…</code>
          </div>
          <div>
            <span className="text-gray-500 block mb-0.5">Issued</span>
            <span className="text-gray-400">
              {issuedDate.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}{" "}
              {issuedDate.toLocaleTimeString("en-GB", { hour12: false })}
            </span>
          </div>
          <div>
            <span className="text-gray-500 block mb-0.5">Prover</span>
            <span className={prover.color}>{prover.label}</span>
          </div>
        </div>

        {/* Proof trace toggle */}
        {certificate.proof_trace && (
          <div>
            <button
              onClick={() => setShowTrace(!showTrace)}
              className="btn-ghost text-xs w-full justify-between"
            >
              <span>Proof Trace</span>
              <svg
                className={`h-3.5 w-3.5 transition-transform ${showTrace ? "rotate-180" : ""}`}
                viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
              >
                <path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            {showTrace && (
              <pre className="mt-2 rounded-lg bg-base-950 border border-base-700/30 p-3 text-[11px] leading-relaxed font-mono text-gray-500 overflow-x-auto max-h-48 animate-slide-up">
                {certificate.proof_trace}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
