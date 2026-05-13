/**
 * Phase 2-B: 헬스체크 대시보드 페이지
 * - 시스템 전체 상태 (agent_connectivity, detection_stream, llm_queue, etc.)
 * - 에이전트별 상태 목록
 */
import { useEffect, useState } from "react";
import {
  fetchHealthDashboard,
  fetchAgentHealth,
  type HealthDashboard,
  type AgentHealthItem,
} from "../lib/api";
import { RefreshCw, Wifi, WifiOff, AlertCircle, CheckCircle2, Activity } from "lucide-react";

function StatusBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: "3px 10px",
        borderRadius: 20,
        fontSize: 12,
        fontWeight: 600,
        background: ok ? "#d1fae5" : "#fee2e2",
        color: ok ? "#065f46" : "#991b1b",
      }}
    >
      {ok ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
      {label}
    </span>
  );
}

function MetricCard({
  title,
  value,
  ok,
  detail,
  threshold,
}: {
  title: string;
  value: string | number;
  ok: boolean;
  detail?: string;
  threshold?: string;
}) {
  return (
    <div
      style={{
        background: "white",
        border: `1px solid ${ok ? "#d1fae5" : "#fecaca"}`,
        borderLeft: `4px solid ${ok ? "#10b981" : "#ef4444"}`,
        borderRadius: 10,
        padding: "16px 20px",
        minWidth: 180,
      }}
    >
      <div style={{ fontSize: 12, color: "#6b7280", marginBottom: 6, fontWeight: 600, textTransform: "uppercase" }}>
        {title}
      </div>
      <div style={{ fontSize: 26, fontWeight: 700, color: ok ? "#065f46" : "#991b1b" }}>
        {value}
      </div>
      {detail && <div style={{ fontSize: 12, color: "#6b7280", marginTop: 4 }}>{detail}</div>}
      {threshold && <div style={{ fontSize: 11, color: "#9ca3af", marginTop: 2 }}>기준: {threshold}</div>}
    </div>
  );
}

function AgentStatusDot({ status }: { status: string }) {
  const color =
    status === "online" ? "#10b981" :
    status === "offline" ? "#ef4444" :
    status === "never_connected" ? "#9ca3af" : "#f59e0b";
  const label =
    status === "online" ? "온라인" :
    status === "offline" ? "오프라인" :
    status === "never_connected" ? "미연결" : "비활성";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
      <span style={{ fontSize: 12, color }}>{label}</span>
    </span>
  );
}

export function HealthDashboardPage() {
  const [dashboard, setDashboard] = useState<HealthDashboard | null>(null);
  const [agents, setAgents] = useState<AgentHealthItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [d, a] = await Promise.all([fetchHealthDashboard(), fetchAgentHealth()]);
      setDashboard(d);
      setAgents(a);
      setLastUpdated(new Date());
    } catch (e: any) {
      setError(e.message || "헬스체크 데이터 로드 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const checks = dashboard?.checks ?? {};
  const overallOk = dashboard?.overall === "ok";

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">시스템 헬스체크</h2>
            <p className="page-subtitle">
              실시간 시스템 상태 모니터링 · 30초마다 자동 갱신
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {lastUpdated && (
              <span style={{ fontSize: 12, color: "#6b7280" }}>
                마지막 갱신: {lastUpdated.toLocaleTimeString("ko-KR")}
              </span>
            )}
            <button className="btn btn-sm" onClick={load} disabled={loading}>
              <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="alert" style={{ marginBottom: 16 }}>⚠ {error}</div>
      )}

      {/* 전체 상태 배너 */}
      {dashboard && (
        <div
          style={{
            padding: "14px 20px",
            borderRadius: 10,
            background: overallOk ? "#d1fae5" : "#fee2e2",
            border: `1px solid ${overallOk ? "#6ee7b7" : "#fca5a5"}`,
            marginBottom: 24,
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          {overallOk ? (
            <CheckCircle2 size={20} color="#065f46" />
          ) : (
            <AlertCircle size={20} color="#991b1b" />
          )}
          <span style={{ fontWeight: 700, fontSize: 15, color: overallOk ? "#065f46" : "#991b1b" }}>
            {overallOk ? "모든 시스템이 정상 동작 중입니다" : "일부 시스템에 문제가 감지되었습니다"}
          </span>
        </div>
      )}

      {/* 메트릭 카드 */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 28 }}>
        {checks.agent_connectivity != null && (
          <MetricCard
            title="에이전트 연결"
            value={`${checks.agent_connectivity.online ?? 0} / ${checks.agent_connectivity.total ?? 0}`}
            ok={checks.agent_connectivity.ok}
            detail="온라인 / 전체"
          />
        )}
        {checks.detection_stream != null && (
          <MetricCard
            title="탐지 스트림 지연"
            value={checks.detection_stream.lag ?? "-"}
            ok={checks.detection_stream.ok}
            detail="Redis Stream 백로그"
            threshold="100 미만"
          />
        )}
        {checks.llm_queue != null && (
          <MetricCard
            title="LLM 큐 길이"
            value={checks.llm_queue.depth ?? "-"}
            ok={checks.llm_queue.ok}
            detail="분석 대기 작업 수"
            threshold="10 미만"
          />
        )}
        {checks.llm_success_rate != null && (
          <MetricCard
            title="LLM 성공률"
            value={`${checks.llm_success_rate.rate ?? 0}%`}
            ok={checks.llm_success_rate.ok}
            detail="최근 1시간 기준"
            threshold="95% 이상"
          />
        )}
        {checks.discord_fail != null && (
          <MetricCard
            title="Discord 알림"
            value={checks.discord_fail.fail_count ?? 0}
            ok={checks.discord_fail.ok}
            detail="최근 실패 횟수"
            threshold="0회"
          />
        )}
        {checks.redis != null && (
          <MetricCard
            title="Redis 연결"
            value={checks.redis.ok ? "정상" : "오류"}
            ok={checks.redis.ok}
            detail="캐시 / 스트림 스토어"
          />
        )}
      </div>

      {/* 에이전트 상태 목록 */}
      <div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, color: "var(--text)" }}>
            <Activity size={15} style={{ verticalAlign: "middle", marginRight: 6 }} />
            에이전트 상태 ({agents.length})
          </h3>
          <div style={{ display: "flex", gap: 12 }}>
            {(["online", "offline", "never_connected", "deactivated"] as const).map((s) => {
              const count = agents.filter((a) => a.health_status === s).length;
              return count > 0 ? (
                <span key={s} style={{ fontSize: 12, color: "#6b7280" }}>
                  <AgentStatusDot status={s} /> {count}
                </span>
              ) : null;
            })}
          </div>
        </div>

        {agents.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "48px 24px",
              color: "var(--text-3)",
              background: "white",
              borderRadius: 10,
              border: "1px solid var(--border)",
              fontSize: 14,
            }}
          >
            {loading ? "에이전트 데이터 로딩 중…" : "등록된 에이전트가 없습니다"}
          </div>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>에이전트 ID</th>
                  <th>호스트명</th>
                  <th>버전</th>
                  <th>상태</th>
                  <th>마지막 하트비트</th>
                  <th>연결 끊김 시간</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agent_id}>
                    <td>
                      <code style={{ fontSize: 12 }}>{a.agent_id.slice(0, 16)}…</code>
                    </td>
                    <td>
                      <strong>{a.hostname ?? "-"}</strong>
                    </td>
                    <td>
                      <code style={{ fontSize: 12 }}>{a.agent_version ?? "-"}</code>
                    </td>
                    <td>
                      <AgentStatusDot status={a.health_status} />
                    </td>
                    <td style={{ fontSize: 12, color: "#6b7280" }}>
                      {a.last_heartbeat_at
                        ? new Date(a.last_heartbeat_at).toLocaleString("ko-KR")
                        : "-"}
                    </td>
                    <td style={{ fontSize: 12, color: "#6b7280" }}>
                      {a.seconds_offline != null
                        ? a.seconds_offline < 60
                          ? `${a.seconds_offline}초`
                          : a.seconds_offline < 3600
                          ? `${Math.floor(a.seconds_offline / 60)}분`
                          : `${Math.floor(a.seconds_offline / 3600)}시간`
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
