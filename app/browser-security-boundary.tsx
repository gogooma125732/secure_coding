"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";

type BrowserEventKind = "react_render_error" | "window_error" | "unhandled_rejection" | "csp_violation";

type BrowserSecurityEvent = {
  kind: BrowserEventKind;
  message: string;
  source?: string;
  line?: number;
  column?: number;
  componentStack?: string;
  route: string;
};

type Props = { children: ReactNode };
type State = { failed: boolean };

export class BrowserSecurityBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidMount(): void {
    window.addEventListener("error", this.onWindowError);
    window.addEventListener("unhandledrejection", this.onUnhandledRejection);
    document.addEventListener("securitypolicyviolation", this.onCspViolation);
  }

  componentWillUnmount(): void {
    window.removeEventListener("error", this.onWindowError);
    window.removeEventListener("unhandledrejection", this.onUnhandledRejection);
    document.removeEventListener("securitypolicyviolation", this.onCspViolation);
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    void reportBrowserSecurityEvent({
      kind: "react_render_error",
      message: error.name,
      componentStack: info.componentStack?.slice(0, 1_500),
      route: safeRoute(),
    });
  }

  private onWindowError = (event: ErrorEvent): void => {
    void reportBrowserSecurityEvent({
      kind: "window_error",
      message: event.error instanceof Error ? event.error.name : "ScriptError",
      source: safeSource(event.filename),
      line: boundedLocation(event.lineno),
      column: boundedLocation(event.colno),
      route: safeRoute(),
    });
  };

  private onUnhandledRejection = (event: PromiseRejectionEvent): void => {
    void reportBrowserSecurityEvent({
      kind: "unhandled_rejection",
      message: event.reason instanceof Error ? event.reason.name : "UnhandledPromiseRejection",
      route: safeRoute(),
    });
  };

  private onCspViolation = (event: SecurityPolicyViolationEvent): void => {
    void reportBrowserSecurityEvent({
      kind: "csp_violation",
      message: event.effectiveDirective || "unknown-directive",
      source: safeSource(event.blockedURI),
      line: boundedLocation(event.lineNumber),
      column: boundedLocation(event.columnNumber),
      route: safeRoute(),
    });
  };

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="fatal-error" role="alert">
          <span aria-hidden="true">◇</span>
          <h1>화면을 안전하게 표시하지 못했습니다</h1>
          <p>오류가 기록되었습니다. 새로고침해도 계속되면 잠시 후 다시 이용해 주세요.</p>
          <button className="button primary" onClick={() => window.location.reload()}>안전하게 새로고침</button>
        </main>
      );
    }
    return this.props.children;
  }
}

const recentEvents = new Map<string, number>();

async function reportBrowserSecurityEvent(event: BrowserSecurityEvent): Promise<void> {
  const fingerprint = `${event.kind}:${event.message}:${event.source ?? ""}:${event.route}`.slice(0, 600);
  const now = Date.now();
  const lastSentAt = recentEvents.get(fingerprint) ?? 0;
  if (now - lastSentAt < 30_000 || recentEvents.size > 50) return;
  recentEvents.set(fingerprint, now);
  try {
    await fetch("/api/security/browser-event", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
      keepalive: true,
    });
  } catch {
    // Telemetry must never create a second user-facing failure.
  }
}

function safeRoute(): string {
  return `${window.location.pathname}`.slice(0, 256);
}

function safeSource(value: string): string {
  if (!value || value === "inline" || value === "eval") return value.slice(0, 256);
  try {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin ? url.pathname.slice(0, 256) : url.origin.slice(0, 256);
  } catch {
    return "invalid-source";
  }
}

function boundedLocation(value: number): number | undefined {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000_000 ? value : undefined;
}
