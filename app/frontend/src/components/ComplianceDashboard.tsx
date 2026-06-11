import { useCallback, useEffect, useState } from "react";
import type { ComplianceCertificate, CompliancePackage, CompliancePreset } from "@/lib/types";
import * as api from "@/lib/api";
import { useToast } from "./Toast";

interface Props {
  executionId: string;
  defaultPreset?: string;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-[10px] uppercase tracking-[0.15em] text-slate-500 font-medium">{title}</h3>
      {children}
    </div>
  );
}

function formatCertificateTitle(cert: ComplianceCertificate): string {
  return cert.type?.replaceAll("_", " ") ?? "proof certificate";
}

function formatLeanRuntime(pkg: CompliancePackage): { label: string; tone: string; detail: string } {
  const runtime = pkg.verification_runtime;
  const mode = runtime.mode?.replaceAll("_", "-") ?? "unknown";

  if (runtime.lean_status === "active") {
    return {
      label: `Lean active, ${mode}`,
      tone: "bg-verified-bg text-verified border-verified/20",
      detail: runtime.detail || "Lean kernel active for this execution.",
    };
  }

  if (runtime.lean_status === "unavailable") {
    return {
      label: `Lean unavailable, ${mode}`,
      tone: "bg-warn-bg text-warn border-warn/20",
      detail: runtime.detail || "Execution fell back to Z3-only verification.",
    };
  }

  return {
    label: "Lean status unknown",
    tone: "bg-base-700/40 text-slate-500 border-base-600/30",
    detail: runtime.detail || "Lean verification status was not recorded.",
  };
}

const REGIME_COLORS: Record<string, string> = {
  HIPAA: "text-blocked border-blocked/20 bg-blocked-bg",
  SOX: "text-warn border-warn/20 bg-warn-bg",
  "Legal Privilege": "text-accent border-accent/20 bg-accent-bg",
  Default: "text-slate-500 border-base-600 bg-white/70",
};

export default function ComplianceDashboard({ executionId, defaultPreset }: Props) {
  const [presets, setPresets] = useState<CompliancePreset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState(defaultPreset ?? "default");
  const [pkg, setPkg] = useState<CompliancePackage | null>(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState<"json" | "pdf" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    api.getCompliancePresets().then(setPresets).catch(() => {});
  }, []);

  useEffect(() => {
    setSelectedPreset(defaultPreset ?? "default");
  }, [defaultPreset, executionId]);

  const loadPackage = useCallback(async (preset: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.exportCompliance(executionId, preset);
      setPkg(data);
    } catch (err) {
      setError(err instanceof api.ApiError ? err.message : "Export failed");
      setPkg(null);
    } finally {
      setLoading(false);
    }
  }, [executionId]);

  useEffect(() => {
    loadPackage(selectedPreset);
  }, [selectedPreset, loadPackage]);

  const handleDownload = useCallback(async () => {
    if (!pkg) return;
    setDownloading("json");
    try {
      await api.downloadComplianceJson(executionId, selectedPreset);
      toast("success", "Compliance package downloaded");
    } catch (err) {
      toast("error", err instanceof api.ApiError ? err.message : "JSON export failed");
    } finally {
      setDownloading(null);
    }
  }, [pkg, executionId, selectedPreset, toast]);

  const handlePdfDownload = useCallback(async () => {
    setDownloading("pdf");
    try {
      await api.downloadCompliancePdf(executionId, selectedPreset);
      toast("success", "PDF audit package downloaded");
    } catch (err) {
      toast("error", err instanceof api.ApiError ? err.message : "PDF export failed");
    } finally {
      setDownloading(null);
    }
  }, [executionId, selectedPreset, toast]);

  return (
    <div className="panel-warm rounded-[28px] overflow-hidden animate-fade-in">
      <div className="border-b border-base-700/60 p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-[10px] uppercase tracking-[0.15em] text-slate-500 font-medium">Compliance package</p>
            <p className="mono text-slate-500 mt-0.5">{executionId.slice(0, 8)}</p>
          </div>
          <div className="flex items-center gap-2">
            <select value={selectedPreset} onChange={(event) => setSelectedPreset(event.target.value)} className="input-field py-1.5 px-3 text-xs w-auto" aria-label="Select compliance preset">
              {presets.map((preset) => (
                <option key={preset.key} value={preset.key}>{preset.name}</option>
              ))}
            </select>
            <button onClick={handlePdfDownload} disabled={!pkg || downloading !== null} className="btn-verified text-xs">
              {downloading === "pdf" ? "Preparing..." : "PDF"}
            </button>
            <button onClick={handleDownload} disabled={!pkg || downloading !== null} className="btn-ghost text-xs">
              {downloading === "json" ? "Preparing..." : "JSON"}
            </button>
          </div>
        </div>
      </div>

      {loading && <div className="p-8 text-sm text-slate-500 text-center">Loading compliance data...</div>}
      {error && <div className="p-5"><p className="text-sm text-blocked">{error}</p></div>}

      {pkg && !loading && (
        <div className="p-5 space-y-5">
          {(() => {
            const runtime = formatLeanRuntime(pkg);
            return (
              <div className="rounded-2xl border border-base-700/40 bg-white/82 p-4 space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`badge text-[11px] border ${runtime.tone}`}>{runtime.label}</span>
                  <span className="text-[11px] text-slate-500">{pkg.verification_runtime.steps_checked} flow checks</span>
                  <span className="text-[11px] text-slate-500">{pkg.verification_runtime.certificates_issued} Lean certificates</span>
                </div>
                <p className="text-xs text-slate-600">{runtime.detail}</p>
              </div>
            );
          })()}

          <div className="flex items-center gap-3">
            <span className={`badge text-sm px-3 py-1 ${REGIME_COLORS[pkg.compliance_regime] ?? REGIME_COLORS.Default}`}>{pkg.compliance_regime}</span>
            <span className="text-xs text-slate-500">Exported {new Date(pkg.generated_at * 1000).toLocaleString("en-GB")}</span>
          </div>

          <Section title="Policy applied">
            <div className="rounded-2xl bg-white/82 border border-base-700/40 p-4 space-y-2">
              <p className="text-sm text-slate-800 font-medium">{pkg.policy_applied.name}</p>
              {Array.isArray(pkg.policy_applied.blocked_categories) && (
                <div className="flex flex-wrap gap-1">
                  {(pkg.policy_applied.blocked_categories as string[]).map((category) => (
                    <span key={category} className="badge bg-blocked-bg text-blocked/80 border border-blocked/10 text-[10px]">{category}</span>
                  ))}
                </div>
              )}
            </div>
          </Section>

          <Section title={`Certificates (${pkg.certificates.length})`}>
            {pkg.certificates.length === 0 ? (
              <p className="text-xs text-slate-500">No certificates issued for this execution.</p>
            ) : (
              <div className="space-y-3">
                {pkg.certificates.map((cert, index) => (
                  <div key={cert.id ?? index} className="rounded-2xl bg-white/82 border border-base-700/40 p-4 space-y-2">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="text-verified">⊢</span>
                      <code className="mono text-slate-700">{cert.id}</code>
                      <span className="badge bg-base-700/40 text-slate-500 border border-base-600/30 text-[10px] capitalize">{formatCertificateTitle(cert)}</span>
                    </div>
                    {Array.isArray(cert.verified_properties) && cert.verified_properties.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {cert.verified_properties.map((property) => (
                          <span key={property} className="badge bg-verified-bg text-verified border border-verified/10 text-[10px]">{property}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Section>

          <Section title="Attestation">
            <div className={`rounded-2xl border p-4 space-y-3 ${pkg.attestation.compliant ? "bg-verified-bg border-verified/10" : "bg-blocked-bg border-blocked/10"}`}>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className={`badge border ${pkg.attestation.compliant ? "bg-verified-bg text-verified border-verified/20" : "bg-blocked-bg text-blocked border-blocked/20"}`}>
                  {pkg.attestation.compliant ? "Compliant" : "Not compliant"}
                </span>
                <span className="text-slate-600">Retention {pkg.attestation.retention_days} days</span>
              </div>
              {pkg.attestation.proofs_satisfied.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {pkg.attestation.proofs_satisfied.map((proof) => (
                    <span key={proof} className="badge bg-white/75 text-slate-700 border border-base-600/30 text-[10px]">{proof}</span>
                  ))}
                </div>
              )}
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
