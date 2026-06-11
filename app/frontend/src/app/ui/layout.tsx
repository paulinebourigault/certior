"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Box, ChevronDown, FileKey2, ListTree, Network } from "lucide-react";
import { GLASS_BOX_ORCHESTRATIONS } from "@/lib/glassBoxOrchestrations";

function currentRunFromLocation() {
  if (typeof window === "undefined") return "all";
  return new URLSearchParams(window.location.search).get("run") || "all";
}

export default function CommandCenterLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [activeRunId, setActiveRunId] = useState("all");
  const [pathname, setPathname] = useState("/ui/agentic");
  const onAgenticPage = pathname === "/ui/agentic";

  useEffect(() => {
    const syncFromLocation = () => {
      setPathname(window.location.pathname);
      setActiveRunId(currentRunFromLocation());
    };
    syncFromLocation();
    window.addEventListener("popstate", syncFromLocation);
    return () => window.removeEventListener("popstate", syncFromLocation);
  }, []);

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-64 panel-warm sticky top-0 h-screen flex flex-col pt-8 pb-4 px-4 z-10 border-r border-[#d9c8b8]">
        <div className="px-2 mb-8">
          <Link href="/ui/agentic" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#bda894] flex items-center justify-center">
              <Box className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="font-display font-semibold text-lg text-[#3d352d] leading-none">Certior</h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-0.5">Agent Glass Box</p>
            </div>
          </Link>
        </div>

        <nav className="flex-1 space-y-1">
          <p className="px-2 text-xs font-semibold text-[#867059] mb-2 mt-4 tracking-wider uppercase">Runtime</p>
          <Link href="/ui/agentic" className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#fffaf3] text-[#3d352d] ring-1 ring-[#d9c8b8] transition-colors group">
            <Network className="w-4 h-4 text-blue-700" />
            <span className="font-semibold text-sm">Agent Glass Box</span>
            <ChevronDown className="ml-auto h-3.5 w-3.5 text-[#867059]" />
          </Link>

          <div className="ml-4 mt-2 space-y-1 border-l border-[#d9c8b8] pl-3">
            {GLASS_BOX_ORCHESTRATIONS.map((run) => {
              const selected = onAgenticPage && activeRunId === run.id;
              const href = run.id === "all" ? "/ui/agentic" : `/ui/agentic?run=${run.id}`;
              return (
                <Link
                  key={run.id}
                  href={href}
                  onClick={() => {
                    setPathname("/ui/agentic");
                    setActiveRunId(run.id);
                    window.dispatchEvent(new CustomEvent("certior:glass-box-run", { detail: run.id }));
                  }}
                  className={`group block rounded-md px-2.5 py-2 transition-colors ${selected ? "bg-white text-[#3d352d] ring-1 ring-[#d9c8b8]" : "text-slate-700 hover:bg-[#fffaf3] hover:text-[#3d352d]"}`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`h-2.5 w-2.5 rounded-full ${run.colorClass}`} />
                    <span className="truncate text-[13px] font-semibold">{run.title}</span>
                  </div>
                  <div className="mt-1 flex items-center justify-between gap-2 pl-4">
                    <span className="truncate text-[11px] text-slate-500">{run.subtitle}</span>
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${run.status === "blocked" ? "bg-red-50 text-red-700" : run.status === "complete" ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-700"}`}>{run.status}</span>
                  </div>
                </Link>
              );
            })}
          </div>

          <p className="px-2 text-xs font-semibold text-[#867059] mb-2 mt-5 tracking-wider uppercase">Evidence</p>
          
          <Link href="/ui/releases" className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-700 hover:bg-[#fffaf3] hover:text-[#9c8773] transition-colors group">
            <ListTree className="w-4 h-4 text-[#867059] group-hover:text-[#9c8773]" />
            <span className="font-medium text-sm">Release Attestations</span>
          </Link>

          <Link href="/ui/policies" className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-700 hover:bg-[#fffaf3] hover:text-[#9c8773] transition-colors group">
            <FileKey2 className="w-4 h-4 text-[#867059] group-hover:text-[#9c8773]" />
            <span className="font-medium text-sm">Policy Bound Config</span>
          </Link>
          
        </nav>
        
        <div className="mt-auto" />
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 pb-16 px-8 lg:px-12 pt-10">
        <div className="mx-auto w-full max-w-6xl animate-fade-in stagger">
          {children}
        </div>
      </main>
    </div>
  );
}
