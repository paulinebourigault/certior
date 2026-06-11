/* ──────────────────────────────────────────────────────────────
   RealTimeLog - streaming event feed from WebSocket updates.
   Renders each WS message as a timestamped log line with
   phase-appropriate icons and color coding.
   ────────────────────────────────────────────────────────────── */

import { useEffect, useRef } from "react";
import type { ExecutionStatus, WsUpdate } from "@/lib/types";

interface Props {
  events: WsUpdate[];
  status: ExecutionStatus;
}

/* ── Event icon + color ── */

function eventStyle(type: string): { icon: string; color: string } {
  const t = type.toLowerCase();
  if (t.includes("complet") || t.includes("done"))     return { icon: "✓", color: "text-verified" };
  if (t.includes("fail") || t.includes("error"))       return { icon: "✗", color: "text-blocked" };
  if (t.includes("cancel"))                             return { icon: "⊘", color: "text-gray-500" };
  if (t.includes("verif") || t.includes("proof"))      return { icon: "⊢", color: "text-verified/70" };
  if (t.includes("plan"))                               return { icon: "◈", color: "text-accent" };
  if (t.includes("exec") || t.includes("run"))          return { icon: "▸", color: "text-accent-glow" };
  if (t.includes("queue"))                              return { icon: "◻", color: "text-gray-400" };
  if (t.includes("warn"))                               return { icon: "⚠", color: "text-warn" };
  return { icon: "·", color: "text-gray-400" };
}

function formatTime(ts?: number): string {
  if (!ts) return "";
  const d = new Date(typeof ts === "number" && ts < 1e12 ? ts * 1000 : ts);
  return d.toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function RealTimeLog({ events, status }: Props) {
  const endRef = useRef<HTMLDivElement>(null);

  // Auto-scroll on new events
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  if (events.length === 0) {
    const isWaiting = status === "queued";
    return (
      <div className="p-5 flex items-center justify-center gap-2 text-sm text-gray-500">
        {isWaiting ? (
          <>
            <span className="h-2 w-2 rounded-full bg-gray-600 animate-pulse" />
            Waiting for execution to start…
          </>
        ) : (
          "No events yet"
        )}
      </div>
    );
  }

  return (
    <div className="divide-y divide-base-700/30" role="log" aria-label="Execution event log" aria-live="polite">
      {events.map((ev, i) => {
        const typeLabel = ev.type ?? ev.status ?? "event";
        const { icon, color } = eventStyle(typeLabel);
        return (
          <div
            key={i}
            className="flex items-start gap-3 px-5 py-2.5 text-xs animate-slide-up"
            style={{ animationDelay: `${Math.min(i * 30, 300)}ms` }}
          >
            {/* Timestamp */}
            <span className="mono text-gray-600 flex-shrink-0 w-16 text-right tabular-nums">
              {formatTime(ev.timestamp)}
            </span>

            {/* Icon */}
            <span className={`flex-shrink-0 w-4 text-center ${color}`}>
              {icon}
            </span>

            {/* Content */}
            <div className="min-w-0 flex-1">
              <span className={`font-medium ${color}`}>
                {typeLabel.replace("execution.", "").replace(/_/g, " ")}
              </span>
              {ev.data && Object.keys(ev.data).length > 0 && (
                <span className="ml-2 text-gray-500">
                  {summariseData(ev.data)}
                </span>
              )}
            </div>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

/* ── Summarise event data into a short string ── */

function summariseData(data: Record<string, unknown>): string {
  const parts: string[] = [];
  if (data.step !== undefined) parts.push(`step ${data.step}`);
  if (data.tool) parts.push(`tool=${data.tool}`);
  if (data.cost_cents) parts.push(`$${(Number(data.cost_cents) / 100).toFixed(2)}`);
  if (data.error) parts.push(String(data.error).slice(0, 60));
  if (data.certificates) parts.push(`${data.certificates} certs`);
  if (parts.length === 0) {
    const keys = Object.keys(data).slice(0, 3);
    return keys.length > 0 ? keys.join(", ") : "";
  }
  return parts.join(", ");
}
