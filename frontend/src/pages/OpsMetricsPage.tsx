/**
 * Operations Metrics Dashboard (owner-only).
 *
 * 운영 메트릭을 한 화면에서 확인 — 이벤트량, 인시던트 분포, 에이전트 상태,
 * Redis 메모리, 알림 발송/실패. 30초마다 자동 새로고침.
 *
 * 호출: GET /admin/ops-metrics  (RBAC: owner)
 */

import { useEffect, useState } from "react";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Bell,
  Database,
  Monitor,
  RefreshCw,
  Server,
  XCircle,
} from "lucide-react";
import type { AuthUser } from "../lib/api";

type Props = { user: AuthUser };

type OpsMetrics = {
  tenant_id: string;
  generated_at: string;
  events: { last_24h: number; last_7d: number };
  incidents: {
    open: number;
    last_24h: { critical: number; high: number; medium: number; low: number };
    last_7d_total: number;
  };
  agents: {
    total: number;
    online: number;
    offline: number;
    never_connected: number;
  };
  redis: {
    memory_used_mb: number | null;
    memory_peak_mb: number | null;
    connected_clients: number | null;
    ok: boolean;
  };
  notifications: {
    discord_sent_24h: number;
    discord_failed_24h: number;
    slack_sent_24h: number;
    slack_failed_24h: number;
    email_sent_24h: number;
    email_failed_24h: number;
  };
};

const API_BASE = (import.meta as any).env?.DEV
  ? ""
  : ((import.meta as any).env?.VITE_API_BASE_URL ?? "");

const POLL_INTERVAL_MS = 30_000;

function fmt(n: number | null | undefined): string {
  if (n === null || n === undefined) return "-";
  return n.toLocaleString("ko-KR");
}

export function OpsMetricsPage({ user }: Props) {
  const [data, setData] = useState<OpsMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const isOwner = user.role === "owner";

  async function load() {
    if (!isOwner) return;
    try {
      const token = localStorage.getItem("infrared_token") || "";
      const res = await fetch(`${API_BASE}/admin/ops-metrics`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: OpsMetrics = await res.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "메트릭 조회 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!isOwner) return;
    load();
    const id = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOwner]);

  if (!isOwner) {
    return (
      <div className="ops-shell">
        <div className="ops-empty">
          <AlertCircle size={32} />
          <h2>owner 전용 페이지</h2>
          <p>운영 메트릭은 owner 권한이 있어야 조회할 수 있습니다.</p>
        </div>
      </div>
    );
  }

  const agentHealthRatio = data
    ? data.agents.total === 0
      ? 0
      : Math.round((data.agents.online / data.agents.total) * 100)
    : 0;

  return (
    <div className="ops-shell">
      <div className="ops-header">
        <div>
          <h1>운영 메트릭</h1>
          <p>
            {data ? (
              <>마지막 갱신 · {new Date(data.generated_at).toLocaleString("ko-KR")} · 30초 자동 새로고침</>
            ) : (
              "메트릭 조회 중..."
            )}
          </p>
        </div>
        <button
          className="ops-refresh"
          onClick={() => {
            setLoading(true);
            load();
          }}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? "status-spin" : ""} /> 새로고침
        </button>
      </div>

      {error && (
        <div className="ops-error">
          <XCircle size={18} /> {error}
        </div>
      )}

      {data && (
        <>
          {/* ── Section: Events ────────────────────────────── */}
          <h2 className="ops-section-title">
            <Activity size={16} /> 이벤트 처리
          </h2>
          <div className="ops-grid">
            <MetricCard
              label="지난 24시간"
              value={fmt(data.events.last_24h)}
              suffix="events"
            />
            <MetricCard
              label="지난 7일"
              value={fmt(data.events.last_7d)}
              suffix="events"
            />
          </div>

          {/* ── Section: Incidents ────────────────────────── */}
          <h2 className="ops-section-title">
            <AlertTriangle size={16} /> 인시던트
          </h2>
          <div className="ops-grid">
            <MetricCard
              label="현재 열린 인시던트"
              value={fmt(data.incidents.open)}
              tone={data.incidents.open > 0 ? "warn" : undefined}
            />
            <MetricCard
              label="지난 7일 발생"
              value={fmt(data.incidents.last_7d_total)}
            />
            <MetricCard
              label="24h Critical/High"
              value={`${data.incidents.last_24h.critical}/${data.incidents.last_24h.high}`}
              tone={
                data.incidents.last_24h.critical > 0
                  ? "danger"
                  : data.incidents.last_24h.high > 0
                  ? "warn"
                  : undefined
              }
            />
            <MetricCard
              label="24h Medium/Low"
              value={`${data.incidents.last_24h.medium}/${data.incidents.last_24h.low}`}
            />
          </div>

          {/* ── Section: Agents ───────────────────────────── */}
          <h2 className="ops-section-title">
            <Monitor size={16} /> 에이전트
          </h2>
          <div className="ops-grid">
            <MetricCard
              label="총 에이전트"
              value={fmt(data.agents.total)}
            />
            <MetricCard
              label="온라인"
              value={fmt(data.agents.online)}
              tone={agentHealthRatio === 100 ? "success" : undefined}
              suffix={data.agents.total > 0 ? `(${agentHealthRatio}%)` : ""}
            />
            <MetricCard
              label="오프라인"
              value={fmt(data.agents.offline)}
              tone={data.agents.offline > 0 ? "danger" : undefined}
            />
            <MetricCard
              label="미연결"
              value={fmt(data.agents.never_connected)}
            />
          </div>

          {/* ── Section: Redis ────────────────────────────── */}
          <h2 className="ops-section-title">
            <Database size={16} /> Redis
          </h2>
          <div className="ops-grid">
            <MetricCard
              label="현재 메모리"
              value={data.redis.memory_used_mb !== null ? data.redis.memory_used_mb.toString() : "-"}
              suffix="MB"
              tone={data.redis.ok ? undefined : "danger"}
            />
            <MetricCard
              label="피크 메모리"
              value={data.redis.memory_peak_mb !== null ? data.redis.memory_peak_mb.toString() : "-"}
              suffix="MB"
            />
            <MetricCard
              label="연결된 클라이언트"
              value={fmt(data.redis.connected_clients)}
            />
            <MetricCard
              label="연결 상태"
              value={data.redis.ok ? "정상" : "오류"}
              tone={data.redis.ok ? "success" : "danger"}
            />
          </div>

          {/* ── Section: Notifications ────────────────────── */}
          <h2 className="ops-section-title">
            <Bell size={16} /> 알림 발송 (24h)
          </h2>
          <div className="ops-grid">
            <MetricCard
              label="Discord 발송"
              value={fmt(data.notifications.discord_sent_24h)}
              suffix={data.notifications.discord_failed_24h > 0 ? `(실패 ${data.notifications.discord_failed_24h})` : ""}
              tone={data.notifications.discord_failed_24h > 0 ? "warn" : undefined}
            />
            <MetricCard
              label="Slack 발송"
              value={fmt(data.notifications.slack_sent_24h)}
              suffix={data.notifications.slack_failed_24h > 0 ? `(실패 ${data.notifications.slack_failed_24h})` : ""}
              tone={data.notifications.slack_failed_24h > 0 ? "warn" : undefined}
            />
            <MetricCard
              label="Email 발송"
              value={fmt(data.notifications.email_sent_24h)}
              suffix={data.notifications.email_failed_24h > 0 ? `(실패 ${data.notifications.email_failed_24h})` : ""}
              tone={data.notifications.email_failed_24h > 0 ? "warn" : undefined}
            />
          </div>

          {/* ── Hint ──────────────────────────────────────── */}
          <div className="ops-hint">
            <Server size={14} />
            <span>
              에이전트 추가 · Redis 설정 · 알림 채널 구성은 좌측 메뉴의 <strong>설정</strong>·<strong>멤버</strong> 탭에서 진행할 수 있습니다.
            </span>
          </div>
        </>
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  suffix,
  tone,
}: {
  label: string;
  value: string | number;
  suffix?: string;
  tone?: "success" | "warn" | "danger";
}) {
  return (
    <div className={`ops-card${tone ? ` ops-card-${tone}` : ""}`}>
      <div className="ops-card-label">{label}</div>
      <div className="ops-card-value">
        {value}
        {suffix && <span className="ops-card-suffix"> {suffix}</span>}
      </div>
    </div>
  );
}
