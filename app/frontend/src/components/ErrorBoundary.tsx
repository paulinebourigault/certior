/* ──────────────────────────────────────────────────────────────
   ErrorBoundary - catches unhandled component errors.
   Prevents a single widget failure from killing the whole app.
   ────────────────────────────────────────────────────────────── */

import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Optional fallback renderer. Receives the error. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  private reset = () => this.setState({ error: null });

  render() {
    if (this.state.error) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset);
      }
      return (
        <div className="card border-blocked/20 p-6 text-center space-y-3" role="alert">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blocked-bg text-blocked mx-auto">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-5 w-5">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4M12 16h.01" strokeLinecap="round" />
            </svg>
          </div>
          <p className="text-sm text-gray-300">Something went wrong</p>
          <p className="mono text-gray-500 max-w-md mx-auto break-words">{this.state.error.message}</p>
          <button onClick={this.reset} className="btn-ghost text-xs mx-auto">
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
