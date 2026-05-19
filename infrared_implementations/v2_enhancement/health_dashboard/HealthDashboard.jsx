/**
 * InfraRed v2 — 헬스체크 대시보드
 * 고도화_설계서_v2.0.docx Phase 1-C
 *
 * Heartbeat 구조 활용:
 * - 에이전트 상태 실시간 표시 (Online/Offline/Warning)
 * - 워커(Detection/Incident) 상태 표시
 * - 최근 Heartbeat 타임스탬프 + 지연 시간 표시
 * - 자동 30초 새로고침
 */

import { useState, useEffect, useCallback } from "react";

// ─────────────────────────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────────────────────────
function timeAgo(isoStr) {
  if (!isoStr) return "없음";
  const diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000);
  if (diff < 60)  return `${diff}초 전`;
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  return `${Math.floor(diff / 3600)}시간 전`;
}

function agentStatus(agent) {
  if (!agent.last_heartbeat) return "unknown";
  const diffSec = (Date.now() - new Date(agent.last_heartbeat).getTime()) / 1000;
  if (diffSec < 60)  return "online";
  if (diffSec < 300) return "warning";
  return "offline";
}

const STATUS_STYLE = {
  online:  { dot: "#10b981", label: "온라인",   bg: "#f0fdf4" },
  warning: { dot: "#f59e0b", label: "지연",     bg: "#fffbeb" },
  offline: { dot: "#ef4444", label: "오프라인", bg: "#fef2f2" },
  unknown: { dot: "#9ca3af", label: "알 수 없음", bg: "#f9fafb" },
};

// ─────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────
async function fetchHealthData(tenantId) {
  const [agentsRes, workersRes, metricsRes] = await Promise.all([
    fetch("/api/v1/health/agents",  { headers: { "X-Tenant-ID": tenantId } }),
    fetch("/api/v1/health/workers", { headers: { "X-Tenant-ID": tenantId } }),
    fetch("/api/v1/health/metrics", { headers: { "X-Tenant-ID": tenantId } }),
  ]);
  return {
    agents:  agentsRes.ok  ? await agentsRes.json()  : [],
    workers: workersRes.ok ? await workersRes.json() : [],
    metrics: metricsRes.ok ? await metricsRes.json() : {},
  };
}

// ─────────────────────────────────────────────────────────────
// 서브 컴포넌트
// ─────────────────────────────────────────────────────────────
function MetricCard({ label, value, unit = "", color = "#3b82f6" }) {
  return (
    <div style={styles.metricCard}>
      <div style={{ ...styles.metricValue, color }}>{value}{unit}</div>
      <div style={styles.metricLabel}>{label}</div>
    </div>
  );
}

function AgentRow({ agent }) {
  const st  = agentStatus(agent);
  const cfg = STATUS_STYLE[st];
  return (
    <tr style={{ background: cfg.bg }}>
      <td style={styles.td}>
        <span style={{ ...styles.statusDot, background: cfg.dot }} />
        {cfg.label}
      </td>
      <td style={styles.td}>{agent.hostname || agent.agent_id}</td>
      <td style={styles.td}>{agent.ip_address || "-"}</td>
      <td style={styles.td}>{agent.version || "-"}</td>
      <td style={styles.td}>{timeAgo(agent.last_heartbeat)}</td>
      <td style={styles.td}>
        {agent.signals_today != null ? agent.signals_today.toLocaleString() : "-"}
      </td>
    </tr>
  );
}

function WorkerCard({ worker }) {
  const ok = worker.status === "running";
  return (
    <div style={{ ...styles.workerCard, borderColor: ok ? "#10b981" : "#ef4444" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={styles.workerName}>{worker.name}</span>
        <span style={{
          ...styles.badge,
          background: ok ? "#d1fae5" : "#fee2e2",
          color:       ok ? "#065f46" : "#991b1b",
        }}>
          {ok ? "● 실행 중" : "● 중단"}
        </span>
      </div>
      <div style={styles.workerMeta}>
        <span>처리: {(worker.processed_count || 0).toLocaleString()}건</span>
        <span>오류: {(worker.error_count || 0).toLocaleString()}건</span>
        <span>마지막 활동: {timeAgo(worker.last_activity)}</span>
      </div>
      {worker.lag != null && (
        <div style={{ fontSize: 12, color: worker.lag > 100 ? "#ef4444" : "#6b7280", marginTop: 4 }}>
          큐 지연: {worker.lag}건
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 메인 컴포넌트
// ─────────────────────────────────────────────────────────────
export default function HealthDashboard({ tenantId = "default" }) {
  const [data,    setData]    = useState({ agents: [], workers: [], metrics: {} });
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const d = await fetchHealthData(tenantId);
      setData(d);
      setLastRefresh(new Date());
    } catch (e) {
      console.error("헬스 데이터 로드 실패:", e);
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 30_000);  // 30초 자동 새로고침
    return () => clearInterval(id);
  }, [refresh]);

  const { agents, workers, metrics } = data;
  const onlineCount  = agents.filter(a => agentStatus(a) === "online").length;
  const warningCount = agents.filter(a => agentStatus(a) === "warning").length;
  const offlineCount = agents.filter(a => agentStatus(a) === "offline").length;

  if (loading) {
    return <div style={styles.loading}>헬스체크 데이터 로딩 중...</div>;
  }

  return (
    <div style={styles.container}>
      {/* 헤더 */}
      <div style={styles.header}>
        <h2 style={styles.title}>🏥 시스템 헬스체크</h2>
        <div style={styles.refreshInfo}>
          <span style={styles.lastRefreshText}>
            {lastRefresh ? `마지막 갱신: ${lastRefresh.toLocaleTimeString()}` : ""}
          </span>
          <button style={styles.refreshBtn} onClick={refresh}>↻ 새로고침</button>
        </div>
      </div>

      {/* 요약 메트릭 */}
      <div style={styles.metricsRow}>
        <MetricCard label="온라인 에이전트"  value={onlineCount}  color="#10b981" />
        <MetricCard label="지연 에이전트"    value={warningCount} color="#f59e0b" />
        <MetricCard label="오프라인 에이전트" value={offlineCount} color="#ef4444" />
        <MetricCard label="오늘 인시던트"     value={metrics.incidents_today ?? "-"} color="#8b5cf6" />
        <MetricCard label="AI 분석 (오늘)"    value={metrics.llm_calls_today ?? "-"} color="#3b82f6" />
        <MetricCard label="평균 MTTD"         value={metrics.avg_mttd_minutes ?? "-"} unit="분" color="#6366f1" />
      </div>

      {/* 워커 상태 */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>⚙️ 워커 상태</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {workers.length === 0 ? (
            <span style={{ color: "#9ca3af" }}>워커 정보 없음</span>
          ) : (
            workers.map((w) => <WorkerCard key={w.name} worker={w} />)
          )}
        </div>
      </section>

      {/* 에이전트 목록 */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>
          🖥️ 에이전트 현황 ({agents.length}대)
        </h3>
        <div style={{ overflowX: "auto" }}>
          <table style={styles.table}>
            <thead>
              <tr style={{ background: "#f9fafb" }}>
                {["상태", "호스트명", "IP", "버전", "마지막 Heartbeat", "오늘 시그널"].map(h => (
                  <th key={h} style={styles.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {agents.length === 0 ? (
                <tr><td colSpan={6} style={{ ...styles.td, textAlign: "center", color: "#9ca3af" }}>
                  등록된 에이전트 없음
                </td></tr>
              ) : (
                agents.map(a => <AgentRow key={a.agent_id} agent={a} />)
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 스타일
// ─────────────────────────────────────────────────────────────
const styles = {
  container:       { padding: 24, fontFamily: "system-ui, sans-serif", maxWidth: 1100 },
  header:          { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  title:           { margin: 0, fontSize: 22, fontWeight: 700 },
  refreshInfo:     { display: "flex", alignItems: "center", gap: 12 },
  lastRefreshText: { color: "#9ca3af", fontSize: 13 },
  refreshBtn:      { padding: "6px 14px", background: "#f3f4f6", border: "1px solid #d1d5db", borderRadius: 6, cursor: "pointer", fontSize: 13 },
  metricsRow:      { display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" },
  metricCard:      { flex: "1 1 140px", background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "16px 20px", textAlign: "center" },
  metricValue:     { fontSize: 28, fontWeight: 700, lineHeight: 1 },
  metricLabel:     { fontSize: 12, color: "#6b7280", marginTop: 6 },
  section:         { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: 20, marginBottom: 16 },
  sectionTitle:    { margin: "0 0 16px", fontSize: 16, fontWeight: 600 },
  workerCard:      { flex: "1 1 220px", border: "2px solid", borderRadius: 8, padding: 14 },
  workerName:      { fontWeight: 600, fontSize: 14 },
  workerMeta:      { display: "flex", gap: 12, fontSize: 12, color: "#6b7280", marginTop: 8, flexWrap: "wrap" },
  badge:           { padding: "2px 10px", borderRadius: 12, fontSize: 12, fontWeight: 500 },
  table:           { width: "100%", borderCollapse: "collapse" },
  th:              { padding: "10px 12px", textAlign: "left", fontSize: 12, fontWeight: 600, color: "#6b7280", borderBottom: "1px solid #e5e7eb" },
  td:              { padding: "10px 12px", fontSize: 13, borderBottom: "1px solid #f3f4f6", verticalAlign: "middle" },
  statusDot:       { display: "inline-block", width: 8, height: 8, borderRadius: "50%", marginRight: 6 },
  loading:         { padding: 40, textAlign: "center", color: "#6b7280" },
};
