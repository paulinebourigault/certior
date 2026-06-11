import { useEffect, useMemo, useState } from "react";
import type { CompliancePreset, TaskRequest } from "@/lib/types";
import * as api from "@/lib/api";
import { useToast } from "./Toast";
import type { RuntimeLLMSetup } from "@/lib/runtime-llm";

interface Props {
  onSubmitted: (executionId: string) => void;
  runtimeSetup: RuntimeLLMSetup | null;
}

export default function TaskInput({ onSubmitted, runtimeSetup }: Props) {
  const [task, setTask] = useState("");
  const [policy, setPolicy] = useState("default");
  const [budget, setBudget] = useState(10000);
  const [presets, setPresets] = useState<CompliancePreset[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    api.getCompliancePresets().then(setPresets).catch(() => {});
  }, []);

  const policyOptions = useMemo(() => {
    const fallback = { key: "default", name: "Default", required_proofs: [], human_approvals: [], retention_days: 365 };
    if (presets.length === 0) return [fallback];
    return [fallback, ...presets.filter((preset) => preset.key !== "default")];
  }, [presets]);

  const selectedPreset = policyOptions.find((preset) => preset.key === policy);
  const suggestedTasks = [
    "Review this release note for privacy or disclosure risk.",
    "Summarize a policy update for an internal operations audience.",
    "Prepare a short control summary with evidence-ready wording.",
  ];

  const handleSubmit = async () => {
    if (!task.trim() || !runtimeSetup?.valid || !runtimeSetup.apiKey) return;
    setSubmitting(true);
    try {
      const req: TaskRequest = {
        task: task.trim(),
        compliance_policy: policy,
        budget_cents: budget,
        provider: runtimeSetup.provider,
        model: runtimeSetup.model,
        api_key: runtimeSetup.apiKey,
      };
      const res = await api.submitTask(req);
      toast("success", "Task submitted");
      onSubmitted(res.execution_id);
      setTask("");
    } catch (error) {
      toast("error", error instanceof api.ApiError ? error.message : "Submission failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="panel-warm rounded-[28px] p-6 space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2">
          <p className="label">Single run</p>
          <h2 className="text-2xl font-display text-slate-900">Start one verified task</h2>
          <p className="text-sm leading-6 text-slate-600">
            {runtimeSetup?.valid ? `${runtimeSetup.provider}, ${runtimeSetup.model}` : "Set up a model first, then send one task through a single verified run."}
          </p>
        </div>
        <span className={`badge border ${runtimeSetup?.valid ? "border-verified/20 bg-verified-bg text-verified" : "border-warn/20 bg-warn-bg text-warn"}`}>
          {runtimeSetup?.valid ? "Ready" : "Setup required"}
        </span>
      </div>

      <div className="rounded-[24px] border border-base-700/50 bg-white/78 p-4 space-y-4">
        <div>
          <label htmlFor="task-input" className="block label mb-2">Task</label>
          <textarea
            id="task-input"
            value={task}
            onChange={(event) => setTask(event.target.value)}
            placeholder="Describe the work you want completed."
            rows={5}
            className="input-field resize-none"
            onKeyDown={(event) => {
              if (event.key === "Enter" && event.metaKey) handleSubmit();
            }}
          />
        </div>

        <div className="space-y-2">
          <p className="label">Try one of these</p>
          <div className="flex flex-wrap gap-2">
            {suggestedTasks.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => setTask(suggestion)}
                className="rounded-full border border-base-700/50 bg-white/88 px-3 py-2 text-xs text-slate-600 transition-colors hover:bg-white hover:text-slate-900"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.4fr_0.8fr]">
        <div className="rounded-[24px] border border-base-700/50 bg-white/78 p-4 space-y-3">
          <p className="label">Policy</p>
          <div className="flex flex-wrap gap-2">
            {policyOptions.map((preset) => (
              <button
                key={preset.key}
                type="button"
                onClick={() => setPolicy(preset.key)}
                className={`rounded-full border px-3 py-2 text-xs transition-colors ${
                  policy === preset.key
                    ? "border-accent/60 bg-accent-bg text-slate-900"
                    : "border-base-700/60 bg-white/85 text-slate-600 hover:bg-white hover:text-slate-900"
                }`}
              >
                {preset.name}
              </button>
            ))}
          </div>

          {selectedPreset && (selectedPreset.required_proofs.length > 0 || selectedPreset.human_approvals.length > 0) && (
            <div className="rounded-2xl border border-base-700/50 bg-base-900/50 p-4 space-y-2">
              <div className="flex flex-wrap gap-1.5">
                {selectedPreset.required_proofs.map((proof) => (
                  <span key={proof} className="badge border border-verified/20 bg-verified-bg text-verified/90 text-[10px]">
                    {proof}
                  </span>
                ))}
              </div>
              {selectedPreset.human_approvals.length > 0 && (
                <p className="text-[11px] text-warn/90">Approvals: {selectedPreset.human_approvals.join(", ")}</p>
              )}
            </div>
          )}
        </div>

        <div className="rounded-[24px] border border-base-700/50 bg-white/78 p-4 space-y-3">
          <label htmlFor="budget-input" className="block label">Budget</label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm" aria-hidden="true">$
            </span>
            <input
              id="budget-input"
              type="number"
              value={budget / 100}
              onChange={(event) => setBudget(Math.round(Number(event.target.value) * 100))}
              min={1}
              max={10000}
              step={1}
              className="input-field pl-7"
              aria-label="Budget in dollars"
            />
          </div>
          <p className="text-xs leading-5 text-slate-500">Set a simple spend cap for this run. Studio will attach it to the verified execution request.</p>
        </div>
      </div>

      <button onClick={handleSubmit} disabled={submitting || !task.trim() || !runtimeSetup?.valid || !runtimeSetup.apiKey} className="btn-primary w-full py-3">
        {submitting ? "Submitting..." : "Start run"}
      </button>
    </div>
  );
}
