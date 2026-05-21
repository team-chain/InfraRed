import { useEffect, useState } from "react";
import { ClipboardList, RefreshCw, Filter } from "lucide-react";
import type { AuthUser } from "../lib/api";

type Props = { user: AuthUser };

type AuditEntry = {
  id: string;
  tenant_id: string;
  actor: string;
  action: string;
  resource: string | null;
  ip: string | null;
  timestamp: string | null;
  metadata: Record<string, unknown> | null;
};

const API_BASE = (import.meta as any).env?.DEV
  ? ""
  : ((import.meta as any).env?.VITE_API_BASE_URL ?? "");

export function AuditLogPage({ user }: Props) {
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [actions, setActions] = useState<{ action: string; count: number }[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actorFilter, setActorFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [sinceFilter, setSinceFilter] = useState("");

  const isOwner = user.role === "owner";

  async function load() {
    if (!isOwner) return;
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (actorFilter) params.set("actor", actorFilter);
      if (actionFilter) params.set("action", actionFilter);
      if (sinceFilter) params.set("since", new Date(sinceFilter).toISOString());
      const q = params.toString() ? `?${params.toString()}` : "";
      const res = await fetch(
        `${API_BASE}/audit-logs/${encodeURIComponent(user.tenant_id)}${q}`,
        { credentials: "include" },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }

  async function loadActions() {
    if (!isOwner) return;
    try {
      const res = await fetch(
        `${API_BASE}/audit-logs/${encodeURIComponent(user.tenant_id)}/actions`,
        { credentials: "include" },
      );
      if (res.ok) {
        const data = await res.json();
        setActions(data.items ?? []);
      }
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    load();
    loadActions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!isOwner) {
    return (
      <div className="page-wrap">
        <div className="page-header">
          <h2 className="page-title">감사 로그</h2>
          <p className="page-subtitle">owner 권한이 필요합니다.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-wrap">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2 className="page-title">
            <ClipboardList size={20} style={{ marginRight: 8, verticalAlign: "text-bottom" }} />
            감사 로그
          </h2>
          <p className="page-subtitle">
            테넌트: <code style={{ fontSize: 12 }}>{user.tenant_id}</code> · 모든 권한 변경 / 로그인 / 인시던트 액션 기록
          </p>
        </div>
        <button className="btn btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
        </button>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>{error}</div>}

      {/* 필터 */}
      <div className="card" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <Filter size={14} style={{ color: "var(--text-3)" }} />
          <strong style={{ fontSize: 13 }}>필터</strong>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: "1 1 200px" }}>
            <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>
              Actor (email / id 부분 일치)
            </label>
            <input
              className="form-input"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              placeholder="ops@infrared.kr"
              style={{ width: "100%" }}
            />
          </div>
          <div style={{ flex: "1 1 200px" }}>
            <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>
              Action (prefix)
            </label>
            <select
              className="form-input"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              style={{ width: "100%" }}
            >
              <option value="">전체</option>
              {actions.map((a) => (
                <option key={a.action} value={a.action}>
                  {a.action} ({a.count})
                </option>
              ))}
            </select>
          </div>
          <div style={{ flex: "1 1 200px" }}>
            <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>
              Since
            </label>
            <input
              type="datetime-local"
              className="form-input"
              value={sinceFilter}
              onChange={(e) => setSinceFilter(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>
          <button className="btn btn-primary" onClick={load} disabled={loading}>
            적용
          </button>
        </div>
      </div>

      {/* 테이블 */}
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 170 }}>시각</th>
              <th style={{ width: 180 }}>Actor</th>
              <th style={{ width: 200 }}>Action</th>
              <th>Resource</th>
              <th style={{ width: 130 }}>IP</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <td style={{ fontSize: 12, color: "var(--text-3)", fontFamily: "var(--mono)" }}>
                  {row.timestamp ? new Date(row.timestamp).toLocaleString("ko-KR") : "-"}
                </td>
                <td style={{ fontSize: 12 }}>{row.actor || "-"}</td>
                <td>
                  <code style={{ fontSize: 11, padding: "2px 6px", background: "var(--surface-2)", borderRadius: 4 }}>
                    {row.action}
                  </code>
                </td>
                <td style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                  {row.resource || "-"}
                  {row.metadata && Object.keys(row.metadata).length > 0 && (
                    <details style={{ marginTop: 4 }}>
                      <summary style={{ fontSize: 11, color: "var(--text-3)", cursor: "pointer" }}>
                        metadata
                      </summary>
                      <pre style={{ fontSize: 10, margin: "4px 0 0", padding: 6, background: "var(--surface-2)", borderRadius: 4, overflow: "auto" }}>
                        {JSON.stringify(row.metadata, null, 2)}
                      </pre>
                    </details>
                  )}
                </td>
                <td style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-3)" }}>
                  {row.ip || "-"}
                </td>
              </tr>
            ))}
            {!items.length && !loading && (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", color: "var(--text-3)", padding: "40px" }}>
                  기록 없음
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-3)", textAlign: "right" }}>
        최대 200건 표시 — 필터로 좁히세요
      </div>
    </div>
  );
}
