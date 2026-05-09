import { useEffect, useState } from "react";
import { fetchAssets, fetchPendingActions, approveAction, rejectAction, type Asset, type PendingAction } from "../lib/api";

const ACTION_LABELS: Record<string, string> = {
  block_ip: "IP 차단",
  lock_account: "계정 잠금",
  escalate: "심각도 상향",
  notify: "알림",
};

function statusColor(status: string) {
  if (status === "registered" || status === "online") return "var(--color-text-success)";
  if (status === "offline") return "var(--color-text-danger)";
  return "var(--color-text-secondary)";
}

function heartbeatLabel(ts?: string) {
  if (!ts) return "없음";
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}초 전`;
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  return new Date(ts).toLocaleString("ko-KR");
}

export function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [actions, setActions] = useState<PendingAction[]>([]);
  const [tab, setTab] = useState<"assets" | "pending">("assets");
  const [busy, setBusy] = useState<string>();

  async function load() {
    const [a, p] = await Promise.all([fetchAssets(), fetchPendingActions()]);
    setAssets(a);
    setActions(p);
  }

  useEffect(() => { load(); }, []);

  async function handleApprove(actionId: string) {
    setBusy(actionId);
    try {
      await approveAction(actionId);
      setActions(prev => prev.filter(a => a.action_id !== actionId));
    } finally {
      setBusy(undefined);
    }
  }

  async function handleReject(actionId: string) {
    setBusy(actionId);
    try {
      await rejectAction(actionId);
      setActions(prev => prev.filter(a => a.action_id !== actionId));
    } finally {
      setBusy(undefined);
    }
  }

  return (
    <div style={{ padding: "1.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: 18, fontWeight: 500 }}>자산 관리</h2>
        {actions.length > 0 && (
          <span style={{ fontSize: 12, padding: "3px 10px", borderRadius: "var(--border-radius-md)",
            background: "var(--color-background-warning)", color: "var(--color-text-warning)", fontWeight: 500 }}>
            승인 대기 {actions.length}건
          </span>
        )}
      </div>

      <div style={{ display: "flex", gap: 4, marginBottom: "1.5rem", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        {([ ["assets", "서버 목록"], ["pending", `승인 대기 (${actions.length})`] ] as [string, string][]).map(([key, label]) => (
          <button key={key} onClick={() => setTab(key as "assets" | "pending")} style={{
            padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
            fontSize: 14, fontWeight: tab === key ? 500 : 400,
            color: tab === key ? "var(--color-text-primary)" : "var(--color-text-secondary)",
            borderBottom: tab === key ? "2px solid var(--color-text-primary)" : "2px solid transparent",
            marginBottom: -1,
          }}>{label}</button>
        ))}
      </div>

      {/* 서버 목록 */}
      {tab === "assets" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {assets.length === 0 && (
            <div style={{ color: "var(--color-text-tertiary)", fontSize: 14, padding: "2rem 0" }}>
              연결된 서버가 없습니다. 온보딩에서 Agent를 설치하세요.
            </div>
          )}
          {assets.map(asset => (
            <div key={asset.asset_id} style={{
              display: "flex", alignItems: "center", gap: 16, padding: "14px 16px",
              border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)",
              background: "var(--color-background-primary)",
            }}>
              <div style={{ width: 10, height: 10, borderRadius: "50%",
                background: statusColor(asset.status || "unknown"), flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 500, fontSize: 14 }}>{asset.hostname}</div>
                <div style={{ fontSize: 12, color: "var(--color-text-tertiary)", marginTop: 2 }}>
                  {asset.asset_id} · {asset.os ?? "OS 미상"}
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 12, color: statusColor(asset.status || "unknown"), fontWeight: 500 }}>
                  {asset.status ?? "unknown"}
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 2 }}>
                  최근 heartbeat: {heartbeatLabel(asset.last_heartbeat)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 승인 대기 큐 */}
      {tab === "pending" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {actions.length === 0 && (
            <div style={{ color: "var(--color-text-tertiary)", fontSize: 14, padding: "2rem 0" }}>
              승인 대기 중인 액션이 없습니다.
            </div>
          )}
          {actions.map(action => (
            <div key={action.action_id} style={{
              padding: "14px 16px", border: "0.5px solid var(--color-border-tertiary)",
              borderRadius: "var(--border-radius-lg)", background: "var(--color-background-primary)",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 500, padding: "3px 10px",
                  background: "var(--color-background-warning)", color: "var(--color-text-warning)",
                  borderRadius: "var(--border-radius-md)" }}>
                  {ACTION_LABELS[action.action_type] ?? action.action_type}
                </span>
                <span style={{ fontSize: 13, fontFamily: "monospace" }}>{action.target}</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--color-text-tertiary)", marginBottom: 12 }}>
                Incident: {action.incident_id ?? "-"} · {new Date(action.created_at).toLocaleString("ko-KR")}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={() => handleApprove(action.action_id)}
                  disabled={busy === action.action_id}
                  style={{ padding: "6px 16px", fontSize: 13, cursor: "pointer",
                    border: "0.5px solid var(--color-border-success)",
                    borderRadius: "var(--border-radius-md)", background: "transparent",
                    color: "var(--color-text-success)" }}>
                  {busy === action.action_id ? "처리 중..." : "승인 → 실행"}
                </button>
                <button onClick={() => handleReject(action.action_id)}
                  disabled={busy === action.action_id}
                  style={{ padding: "6px 16px", fontSize: 13, cursor: "pointer",
                    border: "0.5px solid var(--color-border-danger)",
                    borderRadius: "var(--border-radius-md)", background: "transparent",
                    color: "var(--color-text-danger)" }}>거부</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
