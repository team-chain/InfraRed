/**
 * Public Status Page
 *
 * 인증 불필요. 외부 사용자도 InfraRed 서비스 상태를 확인할 수 있습니다.
 * 30초마다 자동 새로고침. status.infrared.kr 등 별도 도메인에도 동일한 코드 재사용 가능.
 */

import { useEffect, useState } from "react";
import { CheckCircle2, AlertTriangle, XCircle, RefreshCw } from "lucide-react";
import { Logo } from "../components/Logo";

type ComponentStatus = "operational" | "degraded" | "down";

type StatusComponent = {
  id: string;
  name: string;
  description: string;
  status: ComponentStatus;
  latency_ms: number | null;
  message: string | null;
};

type StatusResponse = {
  overall: ComponentStatus;
  checked_at: string;
  components: StatusComponent[];
};

const API_BASE_URL =
  import.meta.env.DEV ? "" : (import.meta.env.VITE_API_BASE_URL ?? "");

const POLL_INTERVAL_MS = 30_000;

function statusMeta(status: ComponentStatus): {
  label: string;
  color: string;
  bg: string;
  icon: React.ReactNode;
} {
  switch (status) {
    case "operational":
      return {
        label: "정상 작동",
        color: "var(--c-green-600)",
        bg: "var(--c-green-50)",
        icon: <CheckCircle2 size={18} />,
      };
    case "degraded":
      return {
        label: "성능 저하",
        color: "var(--c-amber-600)",
        bg: "var(--c-amber-50)",
        icon: <AlertTriangle size={18} />,
      };
    case "down":
      return {
        label: "서비스 중단",
        color: "var(--c-red-600)",
        bg: "var(--c-red-50)",
        icon: <XCircle size={18} />,
      };
  }
}

function overallBanner(status: ComponentStatus): {
  label: string;
  bg: string;
  text: string;
} {
  switch (status) {
    case "operational":
      return {
        label: "모든 시스템 정상",
        bg: "linear-gradient(135deg, #16a34a 0%, #22c55e 100%)",
        text: "현재 모든 서비스가 정상 작동 중입니다.",
      };
    case "degraded":
      return {
        label: "일부 시스템 성능 저하",
        bg: "linear-gradient(135deg, #d97706 0%, #f59e0b 100%)",
        text: "일부 컴포넌트의 응답 시간이 임계값을 초과하고 있습니다.",
      };
    case "down":
      return {
        label: "서비스 중단",
        bg: "linear-gradient(135deg, #dc2626 0%, #ef4444 100%)",
        text: "하나 이상의 핵심 컴포넌트가 응답하지 않습니다. 복구 중입니다.",
      };
  }
}

export function StatusPage() {
  const [data, setData] = useState<StatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastFetchedAt, setLastFetchedAt] = useState<Date | null>(null);

  async function fetchStatus() {
    try {
      const res = await fetch(`${API_BASE_URL}/status/public`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: StatusResponse = await res.json();
      setData(json);
      setError(null);
      setLastFetchedAt(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "상태 조회 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const overall = data?.overall ?? "operational";
  const banner = overallBanner(overall);

  return (
    <div className="status-root">
      {/* ── Top header ────────────────────────────────────── */}
      <header className="status-header">
        <div className="status-header-inner">
          <a href="/" className="status-brand">
            <Logo height={28} />
          </a>
          <button
            className="status-refresh"
            onClick={() => {
              setLoading(true);
              fetchStatus();
            }}
            disabled={loading}
            title="지금 새로 고침"
          >
            <RefreshCw size={14} className={loading ? "status-spin" : ""} /> 새로고침
          </button>
        </div>
      </header>

      {/* ── Overall banner ────────────────────────────────── */}
      <section className="status-banner" style={{ background: banner.bg }}>
        <div className="status-banner-inner">
          <h1>{banner.label}</h1>
          <p>{banner.text}</p>
          {lastFetchedAt && (
            <span className="status-banner-time">
              마지막 확인 · {lastFetchedAt.toLocaleString("ko-KR")}
            </span>
          )}
        </div>
      </section>

      {/* ── Components list ───────────────────────────────── */}
      <section className="status-components">
        <div className="status-components-inner">
          <h2>컴포넌트 상태</h2>
          {error && !data && (
            <div className="status-error">
              <XCircle size={18} /> 상태를 가져올 수 없습니다 — {error}
            </div>
          )}
          {data?.components.map((c) => {
            const meta = statusMeta(c.status);
            return (
              <div key={c.id} className="status-row">
                <div className="status-row-left">
                  <div className="status-row-name">{c.name}</div>
                  <div className="status-row-desc">{c.description}</div>
                  {c.message && (
                    <div className="status-row-message">{c.message}</div>
                  )}
                </div>
                <div className="status-row-right">
                  {c.latency_ms !== null && (
                    <span className="status-row-latency">{c.latency_ms}ms</span>
                  )}
                  <span
                    className="status-row-pill"
                    style={{ color: meta.color, background: meta.bg }}
                  >
                    {meta.icon} {meta.label}
                  </span>
                </div>
              </div>
            );
          })}
          {!data && loading && (
            <div className="status-loading">상태 확인 중...</div>
          )}
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────────── */}
      <footer className="status-footer">
        <p>
          이 페이지는 30초마다 자동으로 새로고침됩니다 · <a href="/">홈으로</a>
        </p>
      </footer>
    </div>
  );
}
