/* ──────────────────────────────────────────────────────────────
   VerificationBadge - THE Certior differentiator.
   Shows the mathematical verification status with a distinctive
   proof-shield animation.  Compact or expanded.
   ────────────────────────────────────────────────────────────── */

import { useState } from "react";

interface Props {
  certificateCount: number;
  status: "verified" | "pending" | "failed";
  proofProperties?: string[];
  compact?: boolean;
}

const SHIELD = (
  <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5" stroke="currentColor" strokeWidth={1.8}>
    <path d="M12 2l7 3.5v5c0 5.25-3 9.5-7 11-4-1.5-7-5.75-7-11v-5L12 2z" />
    <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const PROOF_SYMBOLS = ["∀", "⊢", "∧", "⊨", "→", "∃", "≡", "⊆"];

export default function VerificationBadge({
  certificateCount,
  status,
  proofProperties = [],
  compact = false,
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const safeCertificateCount = Math.max(certificateCount, proofProperties.length > 0 ? 1 : 0);

  if (status === "pending") {
    return (
      <span className="badge bg-base-700 text-gray-400 border border-base-600" role="status" aria-label="Verification in progress">
        <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
          <circle cx="12" cy="12" r="10" strokeDasharray="60" strokeDashoffset="20" />
        </svg>
        Verifying…
      </span>
    );
  }

  if (status === "failed") {
    return (
      <span className="badge bg-blocked-bg text-blocked border border-blocked/20">
        <svg viewBox="0 0 24 24" fill="none" className="h-3.5 w-3.5" stroke="currentColor" strokeWidth={2}>
          <circle cx="12" cy="12" r="10" />
          <path d="M15 9l-6 6M9 9l6 6" strokeLinecap="round" />
        </svg>
        Verification failed
      </span>
    );
  }

  // Verified
  if (compact) {
    return (
      <span className="badge bg-verified-bg text-verified border border-verified/20 animate-pulse-verified">
        {SHIELD}
        <span className="font-semibold">Verified</span>
        {safeCertificateCount > 0 && (
          <span className="text-verified-dim">· {safeCertificateCount} cert{safeCertificateCount !== 1 ? "s" : ""}</span>
        )}
      </span>
    );
  }

  return (
    <div className="card border-verified/20 overflow-hidden animate-fade-in">
      {/* Scan-line effect */}
      <div className="relative h-1 w-full bg-verified/10 overflow-hidden">
        <div className="absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-verified/40 to-transparent animate-scan-line" />
      </div>

      <div className="p-4">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex w-full items-center gap-3 text-left"
        >
          {/* Proof shield */}
          <div className="relative flex-shrink-0">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-verified/10 text-verified animate-pulse-verified">
              {SHIELD}
            </div>
            {/* Orbiting proof symbols */}
            <div className="absolute -inset-1 pointer-events-none">
              {PROOF_SYMBOLS.slice(0, 4).map((sym, i) => (
                <span
                  key={i}
                  className="absolute font-mono text-[9px] text-verified/30"
                  style={{
                    top: `${50 + 45 * Math.sin((i * Math.PI) / 2)}%`,
                    left: `${50 + 45 * Math.cos((i * Math.PI) / 2)}%`,
                    transform: "translate(-50%, -50%)",
                  }}
                >
                  {sym}
                </span>
              ))}
            </div>
          </div>

          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-verified">
              Mathematically Verified
            </p>
            <p className="text-xs text-gray-400">
              {safeCertificateCount} proof certificate{safeCertificateCount !== 1 ? "s" : ""} issued
              {proofProperties.length > 0 && `, ${proofProperties.length} properties proven`}
            </p>
          </div>

          <svg
            className={`h-4 w-4 text-gray-500 transition-transform ${expanded ? "rotate-180" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>

        {expanded && (
          <div className="mt-3 space-y-1 border-t border-base-700 pt-3 animate-slide-up">
            {proofProperties.length > 0 ? (
              <>
                <p className="text-[10px] uppercase tracking-widest text-gray-500 font-medium mb-2">
                  Proven Properties
                </p>
                {proofProperties.map((prop, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="text-verified">⊢</span>
                    <code className="mono text-gray-300">{prop}</code>
                  </div>
                ))}
              </>
            ) : (
              <p className="text-xs text-gray-500">Certificate details were issued for this run, but no individual proof properties were persisted.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
