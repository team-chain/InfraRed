/**
 * SIGMA 룰 마켓플레이스 — v4 §Q2 Phase 2-B
 *
 * 기능:
 *  - 커뮤니티 SIGMA 룰 탐색 (카테고리 / 심각도 / 키워드 필터)
 *  - 로컬 파싱 결과(IR 변환 룰) 미리보기
 *  - 한 클릭으로 InfraRed 룰 엔진에 활성화
 *  - 동기화 상태 및 마지막 업데이트 표시
 */

import { useEffect, useState, useCallback } from "react";
import {
  Search, Download, RefreshCw, AlertTriangle,
  Filter, Eye, Zap, Shield, Globe, Lock, CheckCircle2
} from "lucide-react";

// ─── API 타입 ──────────────────────────────────────────────────────────────

interface SigmaRule {
  id: string;
  sigma_rule_id: string;       // UUID from sigma-rules repo
  title: string;
  description: string;
  status: "stable" | "experimental" | "test" | "deprecated";
  level: "informational" | "low" | "medium" | "high" | "critical";
  category: string;            // process_creation, network_connection, etc.
  product: string;             // windows, linux, macos, generic
  service: string;
  tags: string[];              // MITRE ATT&CK tags
  author: string;
  date: string;
  ir_rule_id: string | null;   // InfraRed 변환 완료 시 IR 룰 ID
  is_activated: boolean;
  last_synced: string;
}

interface SyncStatus {
  last_sync: string | null;
  total_rules: number;
  activated_rules: number;
  sync_in_progress: boolean;
  next_scheduled_sync: string | null;
}

// ─── API 호출 ──────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

async function fetchSigmaRules(params: {
  category?: string;
  level?: string;
  product?: string;
  keyword?: string;
  page?: number;
}): Promise<{ rules: SigmaRule[]; total: number; page: number; pages: number }> {
  const token = localStorage.getItem("ir_token") ?? "";
  const qs = new URLSearchParams();
  if (params.category) qs.set("category", params.category);
  if (params.level) qs.set("level", params.level);
  if (params.product) qs.set("product", params.product);
  if (params.keyword) qs.set("keyword", params.keyword);
  if (params.page) qs.set("page", String(params.page));
  qs.set("page_size", "20");

  const resp = await fetch(`${API_BASE}/api/v1/sigma/marketplace?${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function fetchSyncStatus(): Promise<SyncStatus> {
  const token = localStorage.getItem("ir_token") ?? "";
  const resp = await fetch(`${API_BASE}/api/v1/sigma/sync/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function triggerSync(): Promise<{ ok: boolean; message: string }> {
  const token = localStorage.getItem("ir_token") ?? "";
  const resp = await fetch(`${API_BASE}/api/v1/sigma/sync`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function activateSigmaRule(sigmaRuleId: string): Promise<{ ok: boolean; ir_rule_id: string }> {
  const token = localStorage.getItem("ir_token") ?? "";
  const resp = await fetch(`${API_BASE}/api/v1/sigma/activate/${sigmaRuleId}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function deactivateSigmaRule(sigmaRuleId: string): Promise<{ ok: boolean }> {
  const token = localStorage.getItem("ir_token") ?? "";
  const resp = await fetch(`${API_BASE}/api/v1/sigma/deactivate/${sigmaRuleId}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function previewSigmaRule(sigmaRuleId: string): Promise<{ ir_rule: object; yaml: string }> {
  const token = localStorage.getItem("ir_token") ?? "";
  const resp = await fetch(`${API_BASE}/api/v1/sigma/preview/${sigmaRuleId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// ─── 색상 헬퍼 ────────────────────────────────────────────────────────────

const LEVEL_COLOR: Record<string, string> = {
  informational: "#6b7280",
  low: "#10b981",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
};

const STATUS_COLOR: Record<string, string> = {
  stable: "#10b981",
  experimental: "#f59e0b",
  test: "#3b82f6",
  deprecated: "#6b7280",
};

const PRODUCT_ICON: Record<string, React.ReactNode> = {
  windows: <Shield size={12} />,
  linux: <Lock size={12} />,
  macos: <Globe size={12} />,
  generic: <Zap size={12} />,
};

// ─── 미리보기 모달 ─────────────────────────────────────────────────────────

function PreviewModal({
  rule,
  onClose,
  onActivate,
}: {
  rule: SigmaRule;
  onClose: () => void;
  onActivate: () => void;
}) {
  const [preview, setPreview] = useState<{ ir_rule: object; yaml: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    previewSigmaRule(rule.sigma_rule_id)
      .then(setPreview)
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  }, [rule.sigma_rule_id]);

  return (
    <div
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 1000,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div style={{
        background: "var(--bg-2)", borderRadius: 12, padding: 28, width: 700,
        maxHeight: "80vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
        border: "1px solid var(--border)",
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <div>
            <h3 style={{ margin: 0, color: "var(--text-1)", fontSize: 18 }}>{rule.title}</h3>
            <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 4 }}>
              {rule.author} · {rule.date}
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)", fontSize: 20 }}>×</button>
        </div>

        <p style={{ color: "var(--text-2)", fontSize: 13, lineHeight: 1.6, marginBottom: 16 }}>{rule.description}</p>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
          {rule.tags.map((tag) => (
            <span key={tag} style={{
              background: "var(--bg-3)", borderRadius: 4, padding: "2px 8px",
              fontSize: 11, color: "var(--text-2)",
            }}>{tag}</span>
          ))}
        </div>

        {loading && <div style={{ color: "var(--text-3)", textAlign: "center", padding: 40 }}>변환 미리보기 로딩 중...</div>}
        {err && <div style={{ color: "#ef4444", fontSize: 13 }}>{err}</div>}
        {preview && (
          <>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-3)", marginBottom: 6, textTransform: "uppercase" }}>
                SIGMA YAML 원본
              </div>
              <pre style={{
                background: "var(--bg-1)", borderRadius: 6, padding: 12,
                fontSize: 11, color: "var(--text-2)", overflow: "auto", maxHeight: 200,
                border: "1px solid var(--border)",
              }}>{preview.yaml}</pre>
            </div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-3)", marginBottom: 6, textTransform: "uppercase" }}>
                InfraRed 변환 결과 (JSON)
              </div>
              <pre style={{
                background: "var(--bg-1)", borderRadius: 6, padding: 12,
                fontSize: 11, color: "var(--text-2)", overflow: "auto", maxHeight: 200,
                border: "1px solid var(--border)",
              }}>{JSON.stringify(preview.ir_rule, null, 2)}</pre>
            </div>
          </>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
          <button onClick={onClose} style={{
            background: "var(--bg-3)", border: "1px solid var(--border)",
            borderRadius: 8, padding: "8px 16px", cursor: "pointer", color: "var(--text-2)",
          }}>닫기</button>
          {!rule.is_activated && (
            <button onClick={onActivate} style={{
              background: "#7c3aed", border: "none", borderRadius: 8,
              padding: "8px 16px", cursor: "pointer", color: "#fff", fontWeight: 600,
              display: "flex", alignItems: "center", gap: 6,
            }}>
              <Download size={14} /> 활성화
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── 메인 페이지 ──────────────────────────────────────────────────────────

const CATEGORIES = [
  "전체", "process_creation", "network_connection", "file_event",
  "registry_event", "dns_query", "webserver", "pipe_created",
];
const LEVELS = ["전체", "critical", "high", "medium", "low", "informational"];
const PRODUCTS = ["전체", "windows", "linux", "macos", "generic"];

export function SigmaMarketplacePage() {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const [keyword, setKeyword] = useState("");
  const [category, setCategory] = useState("전체");
  const [level, setLevel] = useState("전체");
  const [product, setProduct] = useState("전체");

  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [previewRule, setPreviewRule] = useState<SigmaRule | null>(null);
  const [activatingId, setActivatingId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async (pg = 1) => {
    setLoading(true);
    setErr("");
    try {
      const res = await fetchSigmaRules({
        category: category === "전체" ? undefined : category,
        level: level === "전체" ? undefined : level,
        product: product === "전체" ? undefined : product,
        keyword: keyword || undefined,
        page: pg,
      });
      setRules(res.rules);
      setTotal(res.total);
      setPage(res.page);
      setPages(res.pages);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }, [category, level, product, keyword]);

  useEffect(() => { load(1); }, [load]);

  useEffect(() => {
    fetchSyncStatus().then(setSyncStatus).catch(() => {});
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const res = await triggerSync();
      showToast(res.message, res.ok);
      fetchSyncStatus().then(setSyncStatus).catch(() => {});
      load(1);
    } catch (e) {
      showToast(String(e), false);
    } finally {
      setSyncing(false);
    }
  };

  const handleActivate = async (rule: SigmaRule) => {
    setActivatingId(rule.sigma_rule_id);
    try {
      const res = await activateSigmaRule(rule.sigma_rule_id);
      showToast(`활성화 완료: ${res.ir_rule_id}`);
      setRules((prev) =>
        prev.map((r) =>
          r.sigma_rule_id === rule.sigma_rule_id
            ? { ...r, is_activated: true, ir_rule_id: res.ir_rule_id }
            : r
        )
      );
      setPreviewRule(null);
    } catch (e) {
      showToast(String(e), false);
    } finally {
      setActivatingId(null);
    }
  };

  const handleDeactivate = async (rule: SigmaRule) => {
    setActivatingId(rule.sigma_rule_id);
    try {
      await deactivateSigmaRule(rule.sigma_rule_id);
      showToast("비활성화 완료");
      setRules((prev) =>
        prev.map((r) =>
          r.sigma_rule_id === rule.sigma_rule_id
            ? { ...r, is_activated: false, ir_rule_id: null }
            : r
        )
      );
    } catch (e) {
      showToast(String(e), false);
    } finally {
      setActivatingId(null);
    }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
      {/* 헤더 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, color: "var(--text-1)", fontSize: 22, fontWeight: 700 }}>
            SIGMA 룰 마켓플레이스
          </h2>
          <p style={{ margin: "4px 0 0", color: "var(--text-3)", fontSize: 13 }}>
            커뮤니티 SIGMA 룰을 탐색하고 InfraRed 탐지 엔진에 활성화하세요
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          {syncStatus && (
            <div style={{ fontSize: 12, color: "var(--text-3)", textAlign: "right" }}>
              <div>전체 {syncStatus.total_rules}개 · 활성 {syncStatus.activated_rules}개</div>
              <div>마지막 동기화: {syncStatus.last_sync
                ? new Date(syncStatus.last_sync).toLocaleString("ko-KR")
                : "미동기화"}
              </div>
            </div>
          )}
          <button
            onClick={handleSync}
            disabled={syncing}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "#7c3aed", color: "#fff", border: "none",
              borderRadius: 8, padding: "8px 14px", cursor: "pointer",
              fontWeight: 600, fontSize: 13, opacity: syncing ? 0.7 : 1,
            }}
          >
            <RefreshCw size={14} className={syncing ? "spin" : ""} />
            {syncing ? "동기화 중..." : "커뮤니티 동기화"}
          </button>
        </div>
      </div>

      {/* 필터 바 */}
      <div style={{
        display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap",
        background: "var(--bg-2)", borderRadius: 10, padding: 14,
        border: "1px solid var(--border)",
      }}>
        <div style={{ position: "relative", flex: "1 1 220px" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-3)" }} />
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load(1)}
            placeholder="룰 제목 / 설명 검색..."
            style={{
              width: "100%", paddingLeft: 32, paddingRight: 10, height: 36,
              background: "var(--bg-1)", border: "1px solid var(--border)",
              borderRadius: 8, color: "var(--text-1)", fontSize: 13, boxSizing: "border-box",
            }}
          />
        </div>

        {[
          { label: "카테고리", value: category, options: CATEGORIES, set: setCategory },
          { label: "심각도", value: level, options: LEVELS, set: setLevel },
          { label: "플랫폼", value: product, options: PRODUCTS, set: setProduct },
        ].map(({ label, value, options, set }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Filter size={12} style={{ color: "var(--text-3)" }} />
            <select
              value={value}
              onChange={(e) => set(e.target.value)}
              style={{
                background: "var(--bg-1)", border: "1px solid var(--border)",
                borderRadius: 8, padding: "4px 8px", color: "var(--text-1)",
                fontSize: 13, height: 36, cursor: "pointer",
              }}
            >
              {options.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        ))}

        <button
          onClick={() => load(1)}
          style={{
            background: "var(--bg-3)", border: "1px solid var(--border)",
            borderRadius: 8, padding: "0 14px", cursor: "pointer",
            color: "var(--text-1)", fontWeight: 600, fontSize: 13, height: 36,
          }}
        >검색</button>
      </div>

      {/* 결과 요약 */}
      <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 12 }}>
        총 {total}개 룰 {loading && "· 로딩 중..."}
      </div>

      {err && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "12px 16px",
          background: "#fef2f2", border: "1px solid #fecaca", borderRadius: 8,
          color: "#dc2626", marginBottom: 16, fontSize: 13,
        }}>
          <AlertTriangle size={14} /> {err}
        </div>
      )}

      {/* 룰 목록 */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {rules.map((rule) => (
          <div
            key={rule.sigma_rule_id}
            style={{
              background: "var(--bg-2)", borderRadius: 10, padding: "14px 16px",
              border: `1px solid ${rule.is_activated ? "#7c3aed33" : "var(--border)"}`,
              transition: "border-color 0.2s",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
              {/* 왼쪽: 룰 정보 */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ color: "var(--text-1)", fontWeight: 600, fontSize: 14 }}>
                    {rule.title}
                  </span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                    background: LEVEL_COLOR[rule.level] + "22",
                    color: LEVEL_COLOR[rule.level], textTransform: "uppercase",
                  }}>{rule.level}</span>
                  <span style={{
                    fontSize: 10, padding: "2px 6px", borderRadius: 4,
                    background: STATUS_COLOR[rule.status] + "22",
                    color: STATUS_COLOR[rule.status], textTransform: "uppercase",
                  }}>{rule.status}</span>
                  {rule.is_activated && (
                    <span style={{
                      fontSize: 10, padding: "2px 6px", borderRadius: 4,
                      background: "#7c3aed22", color: "#7c3aed", fontWeight: 700,
                    }}>✓ 활성</span>
                  )}
                </div>
                <p style={{ margin: "0 0 8px", color: "var(--text-2)", fontSize: 12, lineHeight: 1.5 }}>
                  {rule.description.slice(0, 160)}{rule.description.length > 160 ? "..." : ""}
                </p>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-3)" }}>
                    {PRODUCT_ICON[rule.product] ?? <Globe size={12} />}
                    {rule.product}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                    {rule.category}
                  </span>
                  {rule.tags.slice(0, 3).map((tag) => (
                    <span key={tag} style={{
                      background: "var(--bg-3)", borderRadius: 4, padding: "1px 6px",
                      fontSize: 10, color: "var(--text-3)",
                    }}>{tag}</span>
                  ))}
                  {rule.tags.length > 3 && (
                    <span style={{ fontSize: 10, color: "var(--text-3)" }}>+{rule.tags.length - 3}</span>
                  )}
                </div>
              </div>

              {/* 오른쪽: 버튼 */}
              <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 100 }}>
                <button
                  onClick={() => setPreviewRule(rule)}
                  style={{
                    display: "flex", alignItems: "center", gap: 5, justifyContent: "center",
                    background: "var(--bg-3)", border: "1px solid var(--border)",
                    borderRadius: 6, padding: "6px 10px", cursor: "pointer",
                    color: "var(--text-2)", fontSize: 12,
                  }}
                >
                  <Eye size={12} /> 미리보기
                </button>
                {rule.is_activated ? (
                  <button
                    onClick={() => handleDeactivate(rule)}
                    disabled={activatingId === rule.sigma_rule_id}
                    style={{
                      display: "flex", alignItems: "center", gap: 5, justifyContent: "center",
                      background: "#fef2f2", border: "1px solid #fecaca",
                      borderRadius: 6, padding: "6px 10px", cursor: "pointer",
                      color: "#dc2626", fontSize: 12,
                      opacity: activatingId === rule.sigma_rule_id ? 0.6 : 1,
                    }}
                  >
                    <XCircle size={12} /> 비활성화
                  </button>
                ) : (
                  <button
                    onClick={() => handleActivate(rule)}
                    disabled={activatingId === rule.sigma_rule_id}
                    style={{
                      display: "flex", alignItems: "center", gap: 5, justifyContent: "center",
                      background: "#7c3aed", border: "none",
                      borderRadius: 6, padding: "6px 10px", cursor: "pointer",
                      color: "#fff", fontSize: 12, fontWeight: 600,
                      opacity: activatingId === rule.sigma_rule_id ? 0.6 : 1,
                    }}
                  >
                    <Download size={12} /> 활성화
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}

        {!loading && rules.length === 0 && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-3)" }}>
            <Shield size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
            <div>검색 결과가 없습니다. 커뮤니티 동기화 후 다시 시도해보세요.</div>
          </div>
        )}
      </div>

      {/* 페이지네이션 */}
      {pages > 1 && (
        <div style={{ display: "flex", justifyContent: "center", gap: 6, marginTop: 20 }}>
          {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
            <button
              key={p}
              onClick={() => load(p)}
              style={{
                width: 32, height: 32, borderRadius: 6, border: "1px solid var(--border)",
                background: p === page ? "#7c3aed" : "var(--bg-2)",
                color: p === page ? "#fff" : "var(--text-2)",
                cursor: "pointer", fontWeight: p === page ? 700 : 400,
              }}
            >{p}</button>
          ))}
        </div>
      )}

      {/* 미리보기 모달 */}
      {previewRule && (
        <PreviewModal
          rule={previewRule}
          onClose={() => setPreviewRule(null)}
          onActivate={() => handleActivate(previewRule)}
        />
      )}

      {/* 토스트 */}
      {toast && (
        <div style={{
          position: "fixed", bottom: 24, right: 24, zIndex: 2000,
          background: toast.ok ? "#10b981" : "#ef4444",
          color: "#fff", borderRadius: 8, padding: "12px 18px",
          fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", gap: 8,
          boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
        }}>
          {toast.ok ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}

// helper — XCircle (로컬 fallback. CheckCircle2는 lucide-react에서 import.)
function XCircle({ size }: { size: number }) {
  return <span style={{ fontSize: size, lineHeight: 1 }}>✕</span>;
}
