/* ──────────────────────────────────────────────────────────────
   Layout - persistent app shell with sidebar, header, and
   ⌘K command palette integration.
   ────────────────────────────────────────────────────────────── */

import Link from "next/link";
import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/hooks";
import CommandPalette from "./CommandPalette";
import BrandMark from "./BrandMark";
import type { ReactNode } from "react";

interface Props {
  children: ReactNode;
}

const NAV_ITEMS = [
  {
    href: "/",
    label: "Dashboard",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <rect x="3" y="3" width="7" height="9" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="3" y="16" width="7" height="5" rx="1.5" />
        <rect x="14" y="12" width="7" height="9" rx="1.5" />
      </svg>
    ),
  },
  {
    href: "/tasks",
    label: "Executions",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
        <rect x="9" y="3" width="6" height="4" rx="1" />
        <path d="M9 14l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    href: "/workflows",
    label: "Workflows",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <path d="M6 6h6v6H6z" />
        <path d="M12 9h6" strokeLinecap="round" />
        <path d="M18 9l-2-2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M18 9l-2 2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M18 18h-6v-6h6z" />
        <path d="M12 15H6" strokeLinecap="round" />
        <path d="M6 15l2-2" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M6 15l2 2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    href: "/compliance",
    label: "Compliance",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <path d="M12 2l7 3.5v5c0 5.25-3 9.5-7 11-4-1.5-7-5.75-7-11v-5L12 2z" />
        <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    href: "/examples",
    label: "Examples",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <path d="M5 5h14v14H5z" />
        <path d="M9 9h6" strokeLinecap="round" />
        <path d="M9 13h6" strokeLinecap="round" />
        <path d="M9 17h4" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    href: "/settings",
    label: "Settings",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-[18px] w-[18px]">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
      </svg>
    ),
  },
];

export default function Layout({ children }: Props) {
  const router = useRouter();
  const { user, logout } = useAuth();
  const [cmdOpen, setCmdOpen] = useState(false);

  // Global ⌘K listener
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  return (
    <>
      <div className="relative flex h-screen overflow-hidden text-slate-700">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(234,194,158,0.16),_transparent_20%),radial-gradient(circle_at_bottom_right,_rgba(218,170,148,0.12),_transparent_22%)]" />
        {/* Sidebar */}
        <aside className="relative z-10 w-64 flex-shrink-0 flex flex-col border-r border-base-700/60 bg-[linear-gradient(180deg,rgba(255,250,245,0.86),rgba(248,239,228,0.74))] backdrop-blur-xl">
          {/* Logo */}
          <div className="p-5 border-b border-base-700/60">
            <Link href="/" className="flex items-center gap-2.5 group">
              <BrandMark size={34} variant="monogram" subtitle="verified agentic operations" />
            </Link>
          </div>

          {/* Search shortcut */}
          <div className="px-3 pt-3">
            <button
              onClick={() => setCmdOpen(true)}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-xl border border-base-700/60 bg-white/75
                         text-xs text-slate-500 hover:text-slate-700 hover:border-accent/40 transition-colors"
              aria-label="Open command palette"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-3.5 w-3.5">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" strokeLinecap="round" />
              </svg>
              <span className="flex-1 text-left">Search…</span>
              <kbd className="font-mono text-[9px] bg-base-800 px-1 py-0.5 rounded text-slate-500">⌘K</kbd>
            </button>
          </div>

          {/* Nav */}
          <nav className="flex-1 p-3 space-y-1 mt-1" aria-label="Main navigation">
            {NAV_ITEMS.map((item) => {
              const active = item.href === "/"
                ? router.pathname === "/"
                : router.pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`
                    flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition-all duration-150
                    ${active
                      ? "bg-white/95 text-slate-900 font-medium shadow-sm ring-1 ring-accent/30"
                      : "text-slate-600 hover:text-slate-900 hover:bg-white/72"
                    }
                  `}
                  aria-current={active ? "page" : undefined}
                >
                  {item.icon}
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* User footer */}
          {user && (
            <div className="border-t border-base-700/60 p-3">
              <div className="flex items-center gap-2.5 px-1">
                <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-accent/25 to-proof/25 border border-base-600/50 flex items-center justify-center text-[11px] text-slate-700 font-display font-bold">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] text-slate-800 truncate font-medium">{user.name}</p>
                  <p className="text-[10px] text-slate-500 truncate">{user.role}</p>
                </div>
                <button
                  onClick={logout}
                  className="p-1.5 text-slate-400 hover:text-slate-700 transition-colors rounded-md hover:bg-base-800"
                  title="Sign out"
                  aria-label="Sign out"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="h-3.5 w-3.5">
                    <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </div>
            </div>
          )}
        </aside>

        {/* Main content */}
        <main className="relative z-10 flex-1 overflow-y-auto bg-transparent">
          {children}
        </main>
      </div>

      {/* Command palette */}
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </>
  );
}
