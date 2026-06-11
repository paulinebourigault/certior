/* ──────────────────────────────────────────────────────────────
   Shared React hooks
   ────────────────────────────────────────────────────────────── */

import { useCallback, useEffect, useRef, useState } from "react";
import type { User, Execution, WsUpdate } from "./types";
import * as api from "./api";
import {
  clearRuntimeLLMSetup,
  getRuntimeLLMSetup,
  saveRuntimeLLMSetup,
  type RuntimeLLMSetup,
} from "./runtime-llm";

/* ── useAuth ── */

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!api.hasApiKey()) {
      setUser(null);
      setError(null);
      setLoading(false);
      return;
    }
    try {
      const me = await api.getMe();
      setUser(me);
      setError(null);
    } catch (e) {
      api.clearApiKey();
      setUser(null);
      setError(e instanceof api.ApiError ? e.message : "Auth failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!api.hasApiKey()) {
      setUser(null);
      setError(null);
      setLoading(false);
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setLoading(false);
      setError((current) => current ?? "Studio took too long to respond");
    }, 12000);

    void refresh().finally(() => window.clearTimeout(timeoutId));
    return () => window.clearTimeout(timeoutId);
  }, [refresh]);

  const login = useCallback(
    async (key: string) => {
      api.setApiKey(key);
      setLoading(true);
      await refresh();
    },
    [refresh],
  );

  const logout = useCallback(() => {
    api.clearApiKey();
    setUser(null);
  }, []);

  return { user, loading, error, login, logout, refresh };
}

/* ── useExecution ── */

export function useExecution(executionId: string | null) {
  const [execution, setExecution] = useState<Execution | null>(null);
  const [events, setEvents] = useState<WsUpdate[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<{ close: () => void } | null>(null);

  // Fetch initial state
  useEffect(() => {
    if (!executionId) {
      setExecution(null);
      setEvents([]);
      return;
    }
    api.getExecution(executionId).then(setExecution).catch(() => {});
  }, [executionId]);

  // WebSocket subscription with reconnection
  useEffect(() => {
    if (!executionId) return;

    const conn = api.connectExecution(
      executionId,
      (update) => {
        setEvents((prev) => [...prev, update]);
        // Merge WS status into execution
        const rawStatus = update.status?.replace("execution.", "") ?? "";
        if (rawStatus) {
          setExecution((prev) =>
            prev ? { ...prev, status: rawStatus as Execution["status"] } : prev,
          );
          // Re-fetch full execution on terminal state to get agent output
          const terminal = ["completed", "failed", "cancelled"];
          if (terminal.includes(rawStatus)) {
            api.getExecution(executionId).then(setExecution).catch(() => {});
          }
        }
        // Merge extra fields if the server sends them
        if (update.data) {
          setExecution((prev) => {
            if (!prev) return prev;
            const patch: Partial<Execution> = {};
            if (typeof update.data.current_step === "number")
              patch.current_step = update.data.current_step;
            if (typeof update.data.cost_cents === "number")
              patch.cost_cents = update.data.cost_cents;
            if (typeof update.data.certificate_count === "number")
              patch.certificate_count = update.data.certificate_count;
            if (typeof update.data.error === "string")
              patch.error = update.data.error;
            return { ...prev, ...patch };
          });
        }
      },
      (isConnected) => setConnected(isConnected),
    );
    wsRef.current = conn;

    return () => {
      conn.close();
      setConnected(false);
    };
  }, [executionId]);

  const refresh = useCallback(async () => {
    if (!executionId) return;
    const ex = await api.getExecution(executionId);
    setExecution(ex);
  }, [executionId]);

  return { execution, events, connected, refresh };
}

/* ── usePolling ── */

export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  enabled = true,
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;

    let active = true;

    const poll = async () => {
      try {
        const result = await fetcher();
        if (active) {
          setData(result);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (active) {
          setError(e instanceof api.ApiError ? e.message : "Fetch failed");
          setLoading(false);
        }
      }
    };

    poll();
    const id = setInterval(poll, intervalMs);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [fetcher, intervalMs, enabled]);

  return { data, loading, error };
}

/* ── useRuntimeLLMSetup ── */

export function useRuntimeLLMSetup() {
  const [setup, setSetup] = useState<RuntimeLLMSetup | null>(null);

  useEffect(() => {
    setSetup(getRuntimeLLMSetup());
  }, []);

  const save = useCallback((next: RuntimeLLMSetup) => {
    saveRuntimeLLMSetup(next);
    setSetup(next);
  }, []);

  const clear = useCallback(() => {
    clearRuntimeLLMSetup();
    setSetup(null);
  }, []);

  return { setup, save, clear };
}
