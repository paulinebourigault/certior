import Head from "next/head";

const EXAMPLES = [
  {
    title: "Single task",
    note: "Use when one verified answer is enough.",
    items: [
      "Summarize a policy change for internal review.",
      "Check a draft release note for privacy issues.",
      "Prepare a short SOX control summary for finance.",
    ],
  },
  {
    title: "Workflow",
    note: "Use when work must pass through several stages.",
    items: [
      "Stage 1: draft a patient-safe summary.",
      "Stage 2: review for disclosure risk.",
      "Stage 3: release only after review passes.",
    ],
  },
  {
    title: "Compliance",
    note: "Use after a run is complete.",
    items: [
      "Open a completed execution.",
      "Switch to Compliance.",
      "Export JSON or PDF evidence.",
    ],
  },
];

export default function ExamplesPage() {
  return (
    <>
      <Head>
        <title>Certior Studio - Examples</title>
      </Head>

      <div className="p-6 lg:p-8 max-w-5xl mx-auto space-y-6">
        <div className="hero-band rounded-[30px] border border-base-700/60 px-6 py-6 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="label mb-2">Quick guidance</p>
              <h1 className="text-3xl font-display text-slate-900">Examples</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Use these starter prompts and short steps when you want a fast path through the main Studio flows.</p>
            </div>
            <div className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-3 text-sm text-slate-600">
              <p className="font-medium text-slate-900">Simple, fast, visible</p>
              <p className="mt-1 text-xs">One page for prompts, one page for evidence.</p>
            </div>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {EXAMPLES.map((section) => (
            <section key={section.title} className="panel-warm rounded-[28px] p-5 space-y-4">
              <div className="space-y-2">
                <p className="label">{section.title}</p>
                <h2 className="text-xl font-display text-slate-900">{section.note}</h2>
              </div>
              <div className="space-y-2">
                {section.items.map((item) => (
                  <div key={item} className="rounded-2xl border border-base-700/50 bg-white/72 px-4 py-3 text-sm leading-6 text-slate-700">{item}</div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </>
  );
}