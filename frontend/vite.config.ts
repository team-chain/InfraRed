import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// 로컬 개발: VITE_BACKEND_PROXY_URL 환경변수로 프록시 대상 지정
// Docker 내부 실행 시: http://ingestion:8000
// 로컬 npm dev  : http://localhost:8000 (기본값)
const backendTarget =
  process.env.VITE_BACKEND_PROXY_URL ?? "http://localhost:8000";

// API 경로 목록 – 이 prefix로 시작하는 요청은 백엔드로 프록시
const API_PREFIXES = [
  "/incidents",
  "/auth",
  "/events",
  "/settings",
  "/api-keys",
  "/detection-rules",
  "/audit-logs",
  "/assets",
  "/users",
  "/ingest",
  "/agents",
  "/allowlist",
  "/suppressions",
  "/policy",
  "/api",
  "/healthz",
  "/metrics",
  "/reports",
  "/onboarding",
  "/members",
  "/rules",
  "/search",
  "/sse",
  "/health",
  "/config",
  "/notify",
  "/maintenance-windows",
];

const proxyEntries = Object.fromEntries(
  API_PREFIXES.map((prefix) => [
    prefix,
    {
      target: backendTarget,
      changeOrigin: true,
      secure: false,
    },
  ])
);

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 3000,
    proxy: proxyEntries,
  },
  build: {
    emptyOutDir: false,
  },
});
