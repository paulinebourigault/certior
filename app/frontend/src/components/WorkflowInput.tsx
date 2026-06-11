import { useEffect, useMemo, useState } from "react";
import type { CompliancePreset, WorkflowRequest, WorkflowStageRequest } from "@/lib/types";
import * as api from "@/lib/api";
import { useToast } from "./Toast";
import { STAGE_ROLE_OPTIONS } from "@/lib/studio-config";
import type { RuntimeLLMSetup } from "@/lib/runtime-llm";

interface Props {
  onSubmitted: (workflowId: string) => void;
  runtimeSetup: RuntimeLLMSetup | null;
}

function createWorkflowState() {
  return {
    name: "Workflow",
    description: "",
    stages: [
      {
        name: "Stage 1",
        task: "Describe the work for this stage.",
        compliance_policy: "default",
        budget_cents: 1000,
        stage_role: "worker",
      },
    ] as WorkflowStageRequest[],
  };
}

export default function WorkflowInput({ onSubmitted, runtimeSetup }: Props) {
  const initialWorkflow = createWorkflowState();
  const [name, setName] = useState(initialWorkflow.name);
  const [description, setDescription] = useState(initialWorkflow.description);
  const [stages, setStages] = useState<WorkflowStageRequest[]>(initialWorkflow.stages);
  const [policyOptions, setPolicyOptions] = useState<CompliancePreset[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    api.getCompliancePresets()
      .then((presets) => {
        setPolicyOptions([
          { key: "default", name: "Default", required_proofs: [], human_approvals: [], retention_days: 365 },
          ...presets.filter((preset) => preset.key !== "default"),
        ]);
      })
      .catch(() => {});
  }, []);

  const policies = useMemo(() => policyOptions, [policyOptions]);
  const stageCount = stages.length;

  const updateStage = (index: number, patch: Partial<WorkflowStageRequest>) => {
    setStages((current) => current.map((stage, currentIndex) => (
      currentIndex === index ? { ...stage, ...patch } : stage
    )));
  };

  const addStage = () => {
    setStages((current) => [
      ...current,
      {
        name: `Stage ${current.length + 1}`,
        task: "Describe the work for this stage.",
        compliance_policy: "default",
        budget_cents: 1000,
        stage_role: "worker",
      },
    ]);
  };

  const removeStage = (index: number) => {
    setStages((current) => current.filter((_, currentIndex) => currentIndex !== index));
  };

  const handleSubmit = async () => {
    if (!name.trim() || stages.some((stage) => !stage.name.trim() || !stage.task.trim())) {
      toast("error", "Complete each stage before submitting");
      return;
    }
    if (!runtimeSetup?.valid || !runtimeSetup.apiKey) {
      toast("error", "Model setup required");
      return;
    }

    setSubmitting(true);
    try {
      const payload: WorkflowRequest = {
        name: name.trim(),
        description: description.trim(),
        stages: stages.map((stage, index) => ({
          ...stage,
          name: stage.name.trim(),
          task: stage.task.trim(),
          provider: runtimeSetup.provider,
          model: runtimeSetup.model,
          api_key: runtimeSetup.apiKey,
          upstream_stage_ids: index === 0 ? [] : undefined,
        })),
      };
      const workflow = await api.createWorkflow(payload);
      toast("success", "Workflow submitted");
      onSubmitted(workflow.id);
    } catch (error) {
      toast("error", error instanceof api.ApiError ? error.message : "Workflow submission failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="panel-warm rounded-[28px] p-6 space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2">
          <p className="label">Workflow run</p>
          <h2 className="text-2xl font-display text-slate-900">Build a staged handoff</h2>
          <p className="text-sm leading-6 text-slate-600">
            {runtimeSetup?.valid ? `${runtimeSetup.provider}, ${runtimeSetup.model}` : "Set up a model first, then chain several verified stages together."}
          </p>
        </div>
        <span className="badge border border-base-700/50 bg-white/78 text-slate-600">{stageCount} stage{stageCount === 1 ? "" : "s"}</span>
      </div>

      <div className="rounded-[24px] border border-base-700/50 bg-white/78 p-4 grid grid-cols-1 gap-4">
        <div>
          <label className="block label mb-2">Workflow name</label>
          <input value={name} onChange={(event) => setName(event.target.value)} className="input-field" placeholder="Clinical intake review" />
        </div>
        <div>
          <label className="block label mb-2">Description</label>
          <textarea value={description} onChange={(event) => setDescription(event.target.value)} className="input-field resize-none" rows={2} placeholder="Short summary of the handoff chain" />
        </div>
      </div>

      <div className="space-y-3">
        {stages.map((stage, index) => (
          <div key={`${stage.name}-${index}`} className="rounded-[24px] border border-base-700/60 bg-white/78 p-4 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="label mb-1">Stage {index + 1}</p>
                <p className="text-sm font-medium text-slate-900">{stage.name || `Stage ${index + 1}`}</p>
              </div>
              {stages.length > 1 && (
                <button type="button" onClick={() => removeStage(index)} className="text-xs text-blocked hover:text-blocked/80 transition-colors">
                  Remove
                </button>
              )}
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label className="block label mb-2">Stage name</label>
                <input value={stage.name} onChange={(event) => updateStage(index, { name: event.target.value })} className="input-field" />
              </div>
              <div>
                <label className="block label mb-2">Role</label>
                <select value={stage.stage_role} onChange={(event) => updateStage(index, { stage_role: event.target.value })} className="input-field appearance-none cursor-pointer">
                  {STAGE_ROLE_OPTIONS.map((role) => (
                    <option key={role.value} value={role.value}>{role.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block label mb-2">Task</label>
              <textarea value={stage.task} onChange={(event) => updateStage(index, { task: event.target.value })} className="input-field resize-none" rows={3} />
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label className="block label mb-2">Policy</label>
                <select value={stage.compliance_policy} onChange={(event) => updateStage(index, { compliance_policy: event.target.value })} className="input-field appearance-none cursor-pointer">
                  {policies.map((policy) => (
                    <option key={policy.key} value={policy.key}>{policy.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block label mb-2">Budget</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">$</span>
                  <input
                    type="number"
                    value={stage.budget_cents / 100}
                    onChange={(event) => updateStage(index, { budget_cents: Math.round(Number(event.target.value || 0) * 100) })}
                    min={1}
                    step={1}
                    className="input-field pl-7"
                  />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        <button type="button" onClick={addStage} className="btn-ghost border border-base-700/60 text-xs px-3 py-2 text-accent-dim hover:text-accent">
          Add stage
        </button>
        <button type="button" onClick={() => {
          const empty = createWorkflowState();
          setName(empty.name);
          setDescription(empty.description);
          setStages(empty.stages);
        }} className="btn-ghost border border-base-700/60 text-xs px-3 py-2">
          Reset
        </button>
      </div>

      <button onClick={handleSubmit} disabled={submitting || !runtimeSetup?.valid || !runtimeSetup.apiKey} className="btn-primary w-full py-3">
        {submitting ? "Submitting..." : "Start workflow"}
      </button>
    </div>
  );
}