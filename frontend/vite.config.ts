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
      // 브라우저 페이지 이동(HTML 요청)은 프록시하지 않고 SPA index.html 반환
      bypass: (req: any) => {
        if (req.headers?.accept?.includes("text/html")) {
          return "/index.html";
        }
      },
    },
  ])
);

// Vite 5+ Host 헤더 검증: 알 수 없는 호스트는 403. 도메인 운영용 화이트리스트.
// VITE_ALLOWED_HOSTS 환경변수 (쉼표 구분)로 추가 호스트를 주입할 수 있음.
const defaultAllowedHosts = [
  "app.infrared.kr",
  "infrared.kr",
  ".infrared.kr",
  "localhost",
  "127.0.0.1",
];
const extraAllowedHosts = (process.env.VITE_ALLOWED_HOSTS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const allowedHosts = Array.from(
  new Set([...defaultAllowedHosts, ...extraAllowedHosts])
);

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 3000,
    proxy: proxyEntries,
    allowedHosts,
  },
  build: {
    emptyOutDir: false,
  },
});
