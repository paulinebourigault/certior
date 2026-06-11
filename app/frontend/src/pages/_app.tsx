/* ──────────────────────────────────────────────────────────────
   _app.tsx - Next.js custom App.
   Wraps all pages with global styles, error boundary,
   toast notifications, authentication gate, and layout shell.
   ────────────────────────────────────────────────────────────── */

import type { AppProps } from "next/app";
import Head from "next/head";
import { useCallback, useState } from "react";
import "@/styles/globals.css";
import { useAuth } from "@/lib/hooks";
import Layout from "@/components/Layout";
import LoginGate from "@/components/LoginGate";
import ErrorBoundary from "@/components/ErrorBoundary";
import { ToastProvider } from "@/components/Toast";

export default function App({ Component, pageProps }: AppProps) {
  const { user, loading, error, refresh } = useAuth();
  const [authKey, setAuthKey] = useState(0);

  const handleAuthenticated = useCallback(() => {
    setAuthKey((k) => k + 1);
    refresh();
  }, [refresh]);

  return (
    <>
      <Head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content="Certior Studio - verified agentic operations" />
        <meta name="theme-color" content="#f8efe3" />
        <link rel="icon" href="/favicon.png" type="image/png" />
        <title>Certior Studio</title>
      </Head>

      <ToastProvider>
        <ErrorBoundary>
          {loading ? (
            <div className="flex min-h-screen items-center justify-center" role="status" aria-label="Loading application">
              <div className="panel-warm rounded-[28px] px-6 py-5 text-center space-y-3">
                <div className="flex items-center justify-center gap-3 text-slate-600 text-sm">
                  <svg className="h-5 w-5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
                    <circle cx="12" cy="12" r="10" strokeDasharray="60" strokeDashoffset="20" />
                  </svg>
                  Loading Studio…
                </div>
                <p className="text-xs text-slate-500">Checking the current browser session.</p>
              </div>
            </div>
          ) : !user ? (
            <LoginGate onAuthenticated={handleAuthenticated} authError={error} />
          ) : (
            <Layout key={authKey}>
              <ErrorBoundary>
                <Component {...pageProps} />
              </ErrorBoundary>
            </Layout>
          )}
        </ErrorBoundary>
      </ToastProvider>
    </>
  );
}
