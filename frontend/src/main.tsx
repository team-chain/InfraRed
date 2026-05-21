import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./styles.css";

// ── Sentry 초기화 (DSN 없으면 no-op) ────────────────────────────────────
// VITE_SENTRY_DSN, VITE_SENTRY_ENVIRONMENT, VITE_SENTRY_TRACES_RATE 를 빌드 시 주입.
const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN as string | undefined;
if (SENTRY_DSN) {
  // dynamic import — DSN 없으면 번들에서 제외 효과
  import("@sentry/react").then((Sentry) => {
    Sentry.init({
      dsn: SENTRY_DSN,
      environment: (import.meta.env.VITE_SENTRY_ENVIRONMENT as string) || "production",
      tracesSampleRate: Number(import.meta.env.VITE_SENTRY_TRACES_RATE ?? 0.1),
      // 보안 제품 — PII / 입력값 노출 최소화
      sendDefaultPii: false,
      // unhandled promise rejection + window.onerror 자동 캡처
    });
    // eslint-disable-next-line no-console
    console.info("[infrared] sentry initialized");
  }).catch((err) => {
    // eslint-disable-next-line no-console
    console.warn("[infrared] sentry init failed:", err);
  });
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
