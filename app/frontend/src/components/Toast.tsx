/* ──────────────────────────────────────────────────────────────
   Toast - lightweight notification system.
   Manages a stack of auto-dismissing toasts.
   ────────────────────────────────────────────────────────────── */

import { createContext, useCallback, useContext, useRef, useState } from "react";
import type { ReactNode } from "react";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastContextValue {
  toast: (kind: ToastKind, message: string) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

const KIND_STYLE: Record<ToastKind, { bg: string; border: string; text: string; icon: string }> = {
  success: { bg: "bg-verified-bg", border: "border-verified/20", text: "text-verified", icon: "✓" },
  error:   { bg: "bg-blocked-bg",  border: "border-blocked/20",  text: "text-blocked",  icon: "✗" },
  info:    { bg: "bg-accent-bg",   border: "border-accent/20",   text: "text-accent",   icon: "ℹ" },
};

const AUTO_DISMISS_MS = 4000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const toast = useCallback((kind: ToastKind, message: string) => {
    const id = nextId.current++;
    setToasts((prev) => [...prev, { id, kind, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, AUTO_DISMISS_MS);
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}

      {/* Toast container - fixed bottom-right */}
      {toasts.length > 0 && (
        <div
          className="fixed bottom-4 right-4 z-50 flex flex-col-reverse gap-2 max-w-sm"
          aria-live="polite"
          aria-label="Notifications"
        >
          {toasts.map((t) => {
            const s = KIND_STYLE[t.kind];
            return (
              <div
                key={t.id}
                className={`${s.bg} ${s.border} border rounded-lg px-4 py-3 shadow-lg backdrop-blur-sm
                            flex items-center gap-3 animate-slide-up`}
                role="status"
              >
                <span className={`${s.text} text-sm font-semibold flex-shrink-0`}>{s.icon}</span>
                <p className="text-sm text-gray-200 flex-1">{t.message}</p>
                <button
                  onClick={() => dismiss(t.id)}
                  className="text-gray-500 hover:text-gray-300 flex-shrink-0"
                  aria-label="Dismiss notification"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-3.5 w-3.5">
                    <path d="M18 6L6 18M6 6l12 12" strokeLinecap="round" />
                  </svg>
                </button>
              </div>
            );
          })}
        </div>
      )}
    </ToastContext.Provider>
  );
}
