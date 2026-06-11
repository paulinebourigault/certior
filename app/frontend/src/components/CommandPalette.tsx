/* ──────────────────────────────────────────────────────────────
   CommandPalette - ⌘K quick navigation for power users.
   Provides fast access to pages, actions, and recent executions.
   ────────────────────────────────────────────────────────────── */

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  icon: string;
  action: () => void;
  keywords?: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function CommandPalette({ open, onClose }: Props) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");

  const commands: CommandItem[] = [
    { id: "dashboard", label: "Dashboard", icon: "⊞", action: () => router.push("/"), keywords: "home" },
    { id: "executions", label: "Executions", icon: "⊟", action: () => router.push("/tasks"), keywords: "tasks list browse" },
    { id: "workflows", label: "Workflows", icon: "⇉", action: () => router.push("/workflows"), keywords: "workflow orchestration stages multi agent" },
    { id: "compliance", label: "Compliance", icon: "⊠", action: () => router.push("/compliance"), keywords: "audit export hipaa sox" },
    { id: "examples", label: "Examples", icon: "☰", action: () => router.push("/examples"), keywords: "examples guide help" },
    { id: "settings", label: "Settings", icon: "⚙", action: () => router.push("/settings"), keywords: "api key profile rotate" },
    { id: "new-task", label: "New Task", description: "Submit a verified task", icon: "▸", action: () => { router.push("/"); /* TaskInput focuses automatically */ }, keywords: "submit create run" },
    { id: "new-workflow", label: "New Workflow", description: "Run a staged verified workflow", icon: "⇶", action: () => { router.push("/?mode=workflow"); }, keywords: "orchestration multi agent staged review" },
  ];

  const filtered = query.trim()
    ? commands.filter((c) => {
        const q = query.toLowerCase();
        return c.label.toLowerCase().includes(q) || c.keywords?.toLowerCase().includes(q);
      })
    : commands;

  const [selected, setSelected] = useState(0);

  // Reset on open
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Reset selection when filter changes
  useEffect(() => { setSelected(0); }, [query]);

  const execute = useCallback((item: CommandItem) => {
    onClose();
    item.action();
  }, [onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelected((s) => Math.min(s + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelected((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter" && filtered[selected]) {
      e.preventDefault();
      execute(filtered[selected]);
    } else if (e.key === "Escape") {
      onClose();
    }
  }, [filtered, selected, execute, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-white/50 backdrop-blur-sm" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-lg rounded-xl border border-base-600/60 bg-white/95 backdrop-blur-md shadow-2xl shadow-slate-300/30 overflow-hidden animate-slide-up">
        {/* Search input */}
        <div className="flex items-center gap-3 border-b border-base-700/50 px-4">
          <span className="text-slate-500 text-sm" aria-hidden="true">⌘</span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search commands…"
            className="flex-1 bg-transparent py-3.5 text-sm text-slate-700 placeholder-slate-400 outline-none"
            aria-label="Search commands"
          />
          <kbd className="text-[10px] text-slate-500 bg-base-800 px-1.5 py-0.5 rounded font-mono">esc</kbd>
        </div>

        {/* Results */}
        <div className="max-h-64 overflow-y-auto py-1.5">
          {filtered.length === 0 && (
            <p className="px-4 py-6 text-center text-sm text-slate-500">No commands found</p>
          )}
          {filtered.map((item, i) => (
            <button
              key={item.id}
              onClick={() => execute(item)}
              onMouseEnter={() => setSelected(i)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                i === selected ? "bg-accent-bg text-slate-800" : "text-slate-600 hover:bg-base-800 hover:text-slate-800"
              }`}
              role="option"
              aria-selected={i === selected}
            >
              <span className="text-sm w-5 text-center flex-shrink-0 opacity-60">{item.icon}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm">{item.label}</p>
                {item.description && <p className="text-[11px] text-slate-500">{item.description}</p>}
              </div>
              {i === selected && (
                <span className="text-[10px] text-slate-500 flex-shrink-0">↵</span>
              )}
            </button>
          ))}
        </div>

        {/* Footer hint */}
        <div className="border-t border-base-700/50 px-4 py-2 flex items-center gap-3 text-[10px] text-slate-500">
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}
