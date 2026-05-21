/**
 * Phase 2-A: 룰 라이프사이클 관리 페이지
 * - Draft → Dry-run → Activate / Disable / Rollback
 * - FP 통계 배지 (fp_rate >= 30% → review_recommended)
 */
import { useEffect, useState } from "react";
import {
  fetchRules,
  createRule,
  dryRunRule,
  activateRule,
  disableRule,
  rollbackRule,
  fetchFpStats,
  type RuleItem,
  type DryRunResult,
  type FpStatItem,
} from "../lib/api";
import { Plus, Play, CheckCircle2, XCircle, RotateCcw, AlertTriangle, RefreshCw } from "lucide-react";

const STATUS_LABEL: Record<string, string> = {
  draft: "Draft",
  active: "활성",
  disabled: "비활성",
  testing: "테스트 중",
};

const STATUS_COLOR: Record<string, string> = {
  draft: "#6b7280",
  active: "#10b981",
  disabled: "#ef4444",
  testing: "#f59e0b",
};

type CreateForm = {
  rule_id: string;
  display_name: string;
  source: string;
  mitre_tactic: string;
  mitre_technique: string;
  severity: "critical" | "high" | "medium" | "info";
};

const DEFAULT_FORM: CreateForm = {
  rule_id: "",
  display_name: "",
  source: "auth.log",
  mitre_tactic: "",
  mitre_technique: "",
  severity: "high",
};

export function RuleManagementPage() {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [fpStats, setFpStats] = useState<FpStatItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dryRunResult, setDryRunResult] = useState<{ ruleId: string; result: DryRunResult } | null>(null);

  // Auto-dismiss notice after 4 seconds
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(null), 4000);
    return () => clearTimeout(t);
  }, [notice]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateForm>(DEFAULT_FORM);
  const [createLoading, setCreateLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const [r, fp] = await Promise.all([fetchRules(), fetchFpStats()]);
      setRules(r);
      setFpStats(fp);
    } catch (e: any) {
      setError(e.message || "룰 데이터 로드 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function getFpStat(ruleId: string): FpStatItem | undefined {
    return fpStats.find((f) => f.rule_id === ruleId);
  }

  async function handleDryRun(ruleId: string) {
    setBusyId(ruleId);
    setError(null);
    try {
      const result = await dryRunRule(ruleId);
      setDryRunResult({ ruleId, result });
    } catch (e: any) {
      setError(e.message || "Dry-run 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleActivate(ruleId: string) {
    setBusyId(ruleId);
    setError(null);
    try {
      await activateRule(ruleId);
      setNotice(`룰 ${ruleId} 활성화 완료`);
      await load();
    } catch (e: any) {
      setError(e.message || "활성화 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleDisable(ruleId: string) {
    setBusyId(ruleId);
    setError(null);
    try {
      await disableRule(ruleId);
      setNotice(`룰 ${ruleId} 비활성화 완료`);
      await load();
    } catch (e: any) {
      setError(e.message || "비활성화 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleRollback(ruleId: string) {
    const versionStr = prompt("롤백할 버전 번호를 입력하세요 (예: 1):");
    if (!versionStr) return;
    const targetVersion = parseInt(versionStr, 10);
    if (isNaN(targetVersion) || targetVersion < 1) {
      setError("유효한 버전 번호를 입력하세요.");
      return;
    }
    const reason = prompt("롤백 사유를 입력하세요:") || "Manual rollback";
    setBusyId(ruleId);
    setError(null);
    try {
      await rollbackRule(ruleId, targetVersion, reason);
      setNotice(`룰 ${ruleId} v${targetVersion} 롤백 완료`);
      await load();
    } catch (e: any) {
      setError(e.message || "롤백 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.rule_id.trim() || !form.display_name.trim()) {
      setError("Rule ID와 룰 이름은 필수입니다");
      return;
    }
    if (!/^[A-Z]+-[0-9]{3}$/.test(form.rule_id.trim())) {
      setError("Rule ID 형식이 올바르지 않습니다. 예: AUTH-007, WEB-008");
      return;
    }
    setCreateLoading(true);
    setError(null);
    try {
      await createRule({
        rule_id: form.rule_id.trim(),
        display_name: form.display_name.trim(),
        source: form.source || "auth.log",
        mitre_tactic: form.mitre_tactic || undefined,
        mitre_technique: form.mitre_technique || undefined,
        severity: form.severity,
        change_reason: "Initial draft",
      });
      setNotice("새 룰이 Draft 상태로 생성되었습니다");
      setShowCreate(false);
      setForm(DEFAULT_FORM);
      await load();
    } catch (e: any) {
      setError(e.message || "룰 생성 실패");
    } finally {
      setCreateLoading(false);
    }
  }

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">룰 관리</h2>
            <p className="page-subtitle">탐지 룰 라이프사이클: Draft → Dry-run → 활성화 → 비활성화 → 롤백</p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-sm" onClick={load} disabled={loading}>
              <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
              <Plus size={13} /> 새 룰
            </button>
          </div>
        </div>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>⚠ {error}</div>}
      {notice && <div className="notice" style={{ marginBottom: 12 }}>✓ {notice}</div>}

      {/* Dry-run 결과 모달 */}
      {dryRunResult && (
        <div
          style={{
            position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.4)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "white", borderRadius: 12, padding: 28,
              minWidth: 420, maxWidth: 540,
              boxShadow: "0 8px 32px rgba(0,0,0,0.2)",
            }}
          >
            <h3 style={{ margin: "0 0 16px", fontSize: 16 }}>
              Dry-run 결과: <code style={{ fontSize: 13 }}>{dryRunResult.ruleId}</code>
            </h3>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              {[
                { label: "매칭 시그널 (1h)", value: dryRunResult.result.matched_sample_count ?? 0 },
                { label: "정상 판정 수", value: dryRunResult.result.disposition_count ?? 0 },
                { label: "FP 비율", value: dryRunResult.result.fp_rate != null ? `${dryRunResult.result.fp_rate.toFixed(1)}%` : "데이터 부족" },
                { label: "통계 충분 여부", value: dryRunResult.result.data_sufficient_for_fp ? "✓ 충분" : "⚠ 부족 (30건 미만)" },
              ].map(({ label, value }) => (
                <div key={label} style={{ background: "#f9fafb", padding: "10px 14px", borderRadius: 8 }}>
                  <div style={{ fontSize: 11, color: "#6b7280", marginBottom: 4, fontWeight: 600, textTransform: "uppercase" }}>{label}</div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: "#111" }}>{value}</div>
                </div>
              ))}
            </div>

            {dryRunResult.result.review_recommended && (
              <div
                style={{
                  padding: "10px 14px",
                  background: "#fef3c7",
                  border: "1px solid #fcd34d",
                  borderRadius: 8,
                  marginBottom: 16,
                  display: "flex", alignItems: "center", gap: 8,
                  fontSize: 13, color: "#92400e",
                }}
              >
                <AlertTriangle size={15} /> FP 비율이 30%를 초과합니다. 룰 조건 검토를 권장합니다.
              </div>
            )}

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                className="btn"
                onClick={() => setDryRunResult(null)}
              >
                닫기
              </button>
              <button
                className="btn btn-primary"
                onClick={async () => {
                  setDryRunResult(null);
                  await handleActivate(dryRunResult.ruleId);
                }}
              >
                <CheckCircle2 size={13} /> 활성화
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 룰 생성 모달 */}
      {showCreate && (
        <div
          style={{
            position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.4)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "white", borderRadius: 12, padding: 28,
              width: 520, maxHeight: "90vh", overflowY: "auto",
              boxShadow: "0 8px 32px rgba(0,0,0,0.2)",
            }}
          >
            <h3 style={{ margin: "0 0 20px", fontSize: 16 }}>새 탐지 룰 생성</h3>
            <form onSubmit={handleCreate}>
              {[
                { key: "rule_id", label: "Rule ID *", placeholder: "예: AUTH-007, WEB-008 (대문자+숫자 3자리)" },
                { key: "display_name", label: "룰 이름 *", placeholder: "예: Brute Force Login Detection" },
                { key: "mitre_tactic", label: "MITRE 전술", placeholder: "예: Credential Access" },
                { key: "mitre_technique", label: "MITRE 기술 ID", placeholder: "예: T1110" },
              ].map(({ key, label, placeholder }) => (
                <div key={key} style={{ marginBottom: 14 }}>
                  <label style={{ display: "block", fontSize: 13, color: "#555", marginBottom: 4, fontWeight: 600 }}>
                    {label}
                  </label>
                  <input
                    type="text"
                    value={(form as any)[key]}
                    onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                    placeholder={placeholder}
                    style={{
                      width: "100%", padding: "8px 10px",
                      borderRadius: 6, border: "1px solid #ddd",
                      fontSize: 13, boxSizing: "border-box",
                      fontFamily: key === "rule_id" ? "monospace" : "inherit",
                    }}
                  />
                </div>
              ))}
              <div style={{ marginBottom: 14 }}>
                <label style={{ display: "block", fontSize: 13, color: "#555", marginBottom: 4, fontWeight: 600 }}>
                  로그 소스
                </label>
                <select
                  value={form.source}
                  onChange={(e) => setForm({ ...form, source: e.target.value })}
                  style={{ width: "100%", padding: "8px 10px", borderRadius: 6, border: "1px solid #ddd", fontSize: 13 }}
                >
                  {["auth.log", "nginx", "auditd", "windows", "syslog"].map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: "block", fontSize: 13, color: "#555", marginBottom: 4, fontWeight: 600 }}>
                  심각도
                </label>
                <select
                  value={form.severity}
                  onChange={(e) => setForm({ ...form, severity: e.target.value as any })}
                  style={{
                    width: "100%", padding: "8px 10px",
                    borderRadius: 6, border: "1px solid #ddd", fontSize: 13,
                  }}
                >
                  {["critical", "high", "medium", "info"].map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                <button type="button" className="btn" onClick={() => { setShowCreate(false); setForm(DEFAULT_FORM); }}>
                  취소
                </button>
                <button type="submit" className="btn btn-primary" disabled={createLoading}>
                  {createLoading ? "생성 중…" : "Draft로 생성"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 룰 목록 */}
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>이름</th>
              <th>심각도</th>
              <th>상태</th>
              <th>FP 통계</th>
              <th>액션</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => {
              const fp = getFpStat(rule.rule_id);
              const isBusy = busyId === rule.rule_id;
              return (
                <tr key={rule.rule_id}>
                  <td>
                    <code style={{ fontSize: 12 }}>{rule.rule_id}</code>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{rule.name}</div>
                    {rule.mitre_technique && (
                      <code style={{ fontSize: 11, color: "#6b7280" }}>{rule.mitre_tactic} · {rule.mitre_technique}</code>
                    )}
                  </td>
                  <td>
                    <span className={`pill pill-sm sev-${rule.severity ?? "info"}`}>{rule.severity ?? "info"}</span>
                  </td>
                  <td>
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 10px",
                        borderRadius: 20,
                        fontSize: 12,
                        fontWeight: 600,
                        background: `${STATUS_COLOR[rule.status ?? "draft"]}20`,
                        color: STATUS_COLOR[rule.status ?? "draft"],
                      }}
                    >
                      {STATUS_LABEL[rule.status ?? "draft"] ?? rule.status}
                    </span>
                    {rule.version && (
                      <span style={{ fontSize: 11, color: "#9ca3af", marginLeft: 6 }}>v{rule.version}</span>
                    )}
                  </td>
                  <td>
                    {fp ? (
                      <div>
                        <span
                          style={{
                            fontSize: 12,
                            fontWeight: 600,
                            color: fp.review_recommended ? "#b45309" : "#065f46",
                          }}
                        >
                          FP {fp.fp_rate_pct.toFixed(1)}%
                        </span>
                        {fp.review_recommended && (
                          <span
                            style={{
                              marginLeft: 6,
                              fontSize: 10,
                              padding: "1px 6px",
                              borderRadius: 10,
                              background: "#fef3c7",
                              color: "#92400e",
                              fontWeight: 600,
                            }}
                          >
                            검토 필요
                          </span>
                        )}
                        <div style={{ fontSize: 11, color: "#9ca3af" }}>{fp.total}건 판정</div>
                      </div>
                    ) : (
                      <span style={{ fontSize: 12, color: "#9ca3af" }}>데이터 없음</span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {/* Dry-run: draft or active */}
                      {(rule.status === "draft" || rule.status === "active") && (
                        <button
                          className="btn btn-sm"
                          onClick={() => handleDryRun(rule.rule_id)}
                          disabled={isBusy}
                          title="Dry-run"
                        >
                          <Play size={11} /> Dry-run
                        </button>
                      )}
                      {/* 활성화: draft / disabled — draft는 dry-run 완료 후에만 가능 */}
                      {(rule.status === "draft" || rule.status === "disabled") && (() => {
                        const needsDryRun = rule.status === "draft" && !rule.dry_run_result;
                        return (
                          <button
                            className="btn btn-sm"
                            style={{
                              background: needsDryRun ? "#f3f4f6" : "#d1fae5",
                              color: needsDryRun ? "#9ca3af" : "#065f46",
                              border: `1px solid ${needsDryRun ? "#e5e7eb" : "#6ee7b7"}`,
                              cursor: needsDryRun ? "not-allowed" : "pointer",
                            }}
                            onClick={() => handleActivate(rule.rule_id)}
                            disabled={isBusy || needsDryRun}
                            title={needsDryRun ? "먼저 Dry-run을 실행해야 활성화할 수 있습니다" : "활성화"}
                          >
                            <CheckCircle2 size={11} /> 활성화
                          </button>
                        );
                      })()}
                      {/* 비활성화: active */}
                      {rule.status === "active" && (
                        <button
                          className="btn btn-sm"
                          style={{ background: "#fee2e2", color: "#991b1b", border: "1px solid #fca5a5" }}
                          onClick={() => handleDisable(rule.rule_id)}
                          disabled={isBusy}
                          title="비활성화"
                        >
                          <XCircle size={11} /> 비활성화
                        </button>
                      )}
                      {/* 롤백: version > 1 */}
                      {rule.version && rule.version > 1 && (
                        <button
                          className="btn btn-sm"
                          onClick={() => handleRollback(rule.rule_id)}
                          disabled={isBusy}
                          title="이전 버전으로 롤백"
                        >
                          <RotateCcw size={11} /> 롤백
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {rules.length === 0 && !loading && (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", color: "var(--text-3)", padding: "40px" }}>
                  등록된 룰이 없습니다. 새 룰을 추가하세요.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
