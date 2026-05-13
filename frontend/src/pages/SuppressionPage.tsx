/**
 * Phase 2-C: 억제 관리 페이지
 * - Allowlist (영구 제외)
 * - Suppression (조건부, 만료 일자)
 * - Maintenance Window (시간 기반)
 */
import { useEffect, useState } from "react";
import {
  fetchAllowlist,
  addAllowlistEntry,
  deleteAllowlistEntry,
  fetchSuppressions,
  addSuppression,
  deleteSuppression,
  fetchMaintenanceWindows,
  addMaintenanceWindow,
  deleteMaintenanceWindow,
} from "../lib/api";
import { Plus, Trash2, RefreshCw } from "lucide-react";

type AllowEntry = { id: string; type: string; value: string; reason?: string; created_at: string };
type SuppEntry = { id: string; rule_id?: string; source_ip?: string; reason?: string; expires_at?: string; created_at: string };
type MWEntry = { id: string; name: string; start_at: string; end_at: string; reason?: string; created_at: string };

type ActiveTab = "allowlist" | "suppression" | "maintenance";

export function SuppressionPage() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("allowlist");
  const [allowlist, setAllowlist] = useState<AllowEntry[]>([]);
  const [suppressions, setSuppressions] = useState<SuppEntry[]>([]);
  const [mwWindows, setMwWindows] = useState<MWEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Allow form
  const [allowForm, setAllowForm] = useState({ type: "ip", value: "", reason: "" });
  // Suppression form
  const [suppForm, setSuppForm] = useState({ rule_id: "", source_ip: "", reason: "", expires_at: "" });
  // MW form
  const [mwForm, setMwForm] = useState({ name: "", start_at: "", end_at: "", reason: "" });

  async function loadAll() {
    setLoading(true);
    try {
      const [al, sp, mw] = await Promise.all([
        fetchAllowlist(),
        fetchSuppressions(),
        fetchMaintenanceWindows(),
      ]);
      setAllowlist(al);
      setSuppressions(sp);
      setMwWindows(mw);
    } catch (e: any) {
      setError(e.message || "데이터 로드 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll(); }, []);

  async function handleAddAllow(e: React.FormEvent) {
    e.preventDefault();
    if (!allowForm.value.trim()) { setError("값을 입력하세요"); return; }
    setError(null);
    try {
      await addAllowlistEntry(allowForm);
      setNotice("Allowlist에 추가되었습니다");
      setAllowForm({ type: "ip", value: "", reason: "" });
      const al = await fetchAllowlist();
      setAllowlist(al);
    } catch (e: any) { setError(e.message || "추가 실패"); }
  }

  async function handleDeleteAllow(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    setError(null);
    try {
      await deleteAllowlistEntry(id);
      setAllowlist((prev) => prev.filter((a) => a.id !== id));
      setNotice("삭제되었습니다");
    } catch (e: any) { setError(e.message || "삭제 실패"); }
  }

  async function handleAddSupp(e: React.FormEvent) {
    e.preventDefault();
    if (!suppForm.rule_id.trim() && !suppForm.source_ip.trim()) {
      setError("Rule ID 또는 Source IP 중 하나는 필수입니다");
      return;
    }
    setError(null);
    try {
      await addSuppression(suppForm);
      setNotice("억제 규칙이 추가되었습니다");
      setSuppForm({ rule_id: "", source_ip: "", reason: "", expires_at: "" });
      const sp = await fetchSuppressions();
      setSuppressions(sp);
    } catch (e: any) { setError(e.message || "추가 실패"); }
  }

  async function handleDeleteSupp(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    setError(null);
    try {
      await deleteSuppression(id);
      setSuppressions((prev) => prev.filter((s) => s.id !== id));
      setNotice("삭제되었습니다");
    } catch (e: any) { setError(e.message || "삭제 실패"); }
  }

  async function handleAddMW(e: React.FormEvent) {
    e.preventDefault();
    if (!mwForm.name.trim() || !mwForm.start_at || !mwForm.end_at) {
      setError("이름, 시작/종료 시각은 필수입니다");
      return;
    }
    setError(null);
    try {
      await addMaintenanceWindow(mwForm);
      setNotice("점검 창이 추가되었습니다");
      setMwForm({ name: "", start_at: "", end_at: "", reason: "" });
      const mw = await fetchMaintenanceWindows();
      setMwWindows(mw);
    } catch (e: any) { setError(e.message || "추가 실패"); }
  }

  async function handleDeleteMW(id: string) {
    if (!confirm("삭제하시겠습니까?")) return;
    setError(null);
    try {
      await deleteMaintenanceWindow(id);
      setMwWindows((prev) => prev.filter((m) => m.id !== id));
      setNotice("삭제되었습니다");
    } catch (e: any) { setError(e.message || "삭제 실패"); }
  }

  const tabCount = {
    allowlist: allowlist.length,
    suppression: suppressions.length,
    maintenance: mwWindows.length,
  };

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">억제 관리</h2>
            <p className="page-subtitle">Allowlist · Suppression · 점검 창 — 3단계 노이즈 감소 시스템</p>
          </div>
          <button className="btn btn-sm" onClick={loadAll} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
          </button>
        </div>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>{error}</div>}
      {notice && <div className="notice" style={{ marginBottom: 12 }}>{notice}</div>}

      {/* 탭 */}
      <div style={{ display: "flex", gap: 0, borderBottom: "2px solid var(--border)", marginBottom: 20 }}>
        {([
          { key: "allowlist", label: "Allowlist", desc: "영구 제외" },
          { key: "suppression", label: "억제 규칙", desc: "조건부 억제" },
          { key: "maintenance", label: "점검 창", desc: "시간 기반 억제" },
        ] as const).map(({ key, label, desc }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            style={{
              padding: "10px 20px",
              border: "none",
              background: "none",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: activeTab === key ? 700 : 500,
              color: activeTab === key ? "var(--accent)" : "var(--text-3)",
              borderBottom: activeTab === key ? "2px solid var(--accent)" : "2px solid transparent",
              marginBottom: -2,
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-start",
              gap: 1,
            }}
          >
            <span>{label} <span style={{
              marginLeft: 4, fontSize: 11, padding: "1px 6px",
              borderRadius: 10, background: "#e5e7eb", color: "#374151",
              fontWeight: 600,
            }}>{tabCount[key]}</span></span>
            <span style={{ fontSize: 11, color: "var(--text-3)", fontWeight: 400 }}>{desc}</span>
          </button>
        ))}
      </div>

      {/* ── ALLOWLIST ── */}
      {activeTab === "allowlist" && (
        <div>
          <form onSubmit={handleAddAllow} style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <select
              value={allowForm.type}
              onChange={(e) => setAllowForm({ ...allowForm, type: e.target.value })}
              className="form-input"
            >
              {["ip", "account", "asset_id"].map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <input
              type="text"
              value={allowForm.value}
              onChange={(e) => setAllowForm({ ...allowForm, value: e.target.value })}
              placeholder="값 (예: 192.168.1.100)"
              className="form-input" style={{ flex: 1, minWidth: 200 }}
            />
            <input
              type="text"
              value={allowForm.reason}
              onChange={(e) => setAllowForm({ ...allowForm, reason: e.target.value })}
              placeholder="사유 (선택)"
              className="form-input" style={{ flex: 1, minWidth: 180 }}
            />
            <button type="submit" className="btn btn-primary btn-sm">
              <Plus size={13} /> 추가
            </button>
          </form>

          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr><th>유형</th><th>값</th><th>사유</th><th>등록일</th><th></th></tr>
              </thead>
              <tbody>
                {allowlist.map((a) => (
                  <tr key={a.id}>
                    <td><code style={{ fontSize: 12 }}>{a.type}</code></td>
                    <td><strong style={{ fontFamily: "monospace", fontSize: 12 }}>{a.value}</strong></td>
                    <td style={{ fontSize: 12, color: "var(--text-3)" }}>{a.reason ?? "-"}</td>
                    <td style={{ fontSize: 12, color: "var(--text-3)" }}>{new Date(a.created_at).toLocaleDateString("ko-KR")}</td>
                    <td>
                      <button className="btn btn-sm btn-danger" onClick={() => handleDeleteAllow(a.id)}>
                        <Trash2 size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
                {allowlist.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-3)", padding: "32px" }}>Allowlist가 비어 있습니다</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── SUPPRESSION ── */}
      {activeTab === "suppression" && (
        <div>
          <form onSubmit={handleAddSupp} style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>Rule ID</label>
              <input
                type="text"
                value={suppForm.rule_id}
                onChange={(e) => setSuppForm({ ...suppForm, rule_id: e.target.value })}
                placeholder="예: RULE-001"
                className="form-input" style={{ width: 140 }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>Source IP</label>
              <input
                type="text"
                value={suppForm.source_ip}
                onChange={(e) => setSuppForm({ ...suppForm, source_ip: e.target.value })}
                placeholder="예: 10.0.0.5"
                className="form-input" style={{ width: 140 }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>만료 일자</label>
              <input
                type="datetime-local"
                value={suppForm.expires_at}
                onChange={(e) => setSuppForm({ ...suppForm, expires_at: e.target.value })}
                className="form-input"
              />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>사유</label>
              <input
                type="text"
                value={suppForm.reason}
                onChange={(e) => setSuppForm({ ...suppForm, reason: e.target.value })}
                placeholder="억제 사유"
                className="form-input" style={{ width: "100%" }}
              />
            </div>
            <button type="submit" className="btn btn-primary btn-sm" style={{ height: 34 }}>
              <Plus size={13} /> 추가
            </button>
          </form>

          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr><th>Rule ID</th><th>Source IP</th><th>사유</th><th>만료</th><th>등록일</th><th></th></tr>
              </thead>
              <tbody>
                {suppressions.map((s) => {
                  const expired = s.expires_at && new Date(s.expires_at) < new Date();
                  return (
                    <tr key={s.id}>
                      <td><code style={{ fontSize: 12 }}>{s.rule_id ?? "-"}</code></td>
                      <td><code style={{ fontSize: 12 }}>{s.source_ip ?? "-"}</code></td>
                      <td style={{ fontSize: 12, color: "var(--text-3)" }}>{s.reason ?? "-"}</td>
                      <td style={{ fontSize: 12 }}>
                        {s.expires_at ? (
                          <span style={{ color: expired ? "var(--c-red-500)" : "var(--c-green-500)" }}>
                            {new Date(s.expires_at).toLocaleString("ko-KR")}
                            {expired && " (만료)"}
                          </span>
                        ) : "영구"}
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-3)" }}>{new Date(s.created_at).toLocaleDateString("ko-KR")}</td>
                      <td>
                        <button className="btn btn-sm btn-danger" onClick={() => handleDeleteSupp(s.id)}>
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {suppressions.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-3)", padding: "32px" }}>억제 규칙이 없습니다</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── MAINTENANCE WINDOWS ── */}
      {activeTab === "maintenance" && (
        <div>
          <form onSubmit={handleAddMW} style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>이름 *</label>
              <input
                type="text"
                value={mwForm.name}
                onChange={(e) => setMwForm({ ...mwForm, name: e.target.value })}
                placeholder="예: 정기 점검 2026-05"
                className="form-input" style={{ width: 200 }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>시작 *</label>
              <input
                type="datetime-local"
                value={mwForm.start_at}
                onChange={(e) => setMwForm({ ...mwForm, start_at: e.target.value })}
                className="form-input"
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>종료 *</label>
              <input
                type="datetime-local"
                value={mwForm.end_at}
                onChange={(e) => setMwForm({ ...mwForm, end_at: e.target.value })}
                className="form-input"
              />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>사유</label>
              <input
                type="text"
                value={mwForm.reason}
                onChange={(e) => setMwForm({ ...mwForm, reason: e.target.value })}
                placeholder="점검 사유"
                className="form-input" style={{ width: "100%" }}
              />
            </div>
            <button type="submit" className="btn btn-primary btn-sm" style={{ height: 34 }}>
              <Plus size={13} /> 추가
            </button>
          </form>

          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr><th>이름</th><th>시작</th><th>종료</th><th>상태</th><th>사유</th><th></th></tr>
              </thead>
              <tbody>
                {mwWindows.map((m) => {
                  const now = new Date();
                  const start = new Date(m.start_at);
                  const end = new Date(m.end_at);
                  const isActive = now >= start && now <= end;
                  const isPast = now > end;
                  const statusLabel = isActive ? "진행 중" : isPast ? "종료됨" : "예정";
                  const statusColor = isActive ? "#f59e0b" : isPast ? "#9ca3af" : "#3b82f6";
                  return (
                    <tr key={m.id}>
                      <td><strong>{m.name}</strong></td>
                      <td style={{ fontSize: 12 }}>{new Date(m.start_at).toLocaleString("ko-KR")}</td>
                      <td style={{ fontSize: 12 }}>{new Date(m.end_at).toLocaleString("ko-KR")}</td>
                      <td>
                        <span style={{ fontSize: 12, fontWeight: 600, color: statusColor }}>
                          {statusLabel}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-3)" }}>{m.reason ?? "-"}</td>
                      <td>
                        <button className="btn btn-sm btn-danger" onClick={() => handleDeleteMW(m.id)}>
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {mwWindows.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-3)", padding: "32px" }}>점검 창이 없습니다</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
