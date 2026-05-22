/**
 * Threat Hunting 인터페이스 (설계서 v4 §로드맵 Q2)
 * - 이벤트 탐색기: 최근 시그널 조회 + 룰 ID / 자산 필터
 * - CTI 조회: 의심 IP에 대한 AlienVault OTX 위협 인텔리전스
 * - 이벤트 재생: BAS 시나리오 수동 주입 (dev/staging 전용)
 */
import { useState } from "react";
import { Search, Shield, Play, RefreshCw, AlertTriangle, CheckCircle, Info, Database, Wifi, AlertOctagon, ShieldCheck } from "lucide-react";

/* ─── API 호출 헬퍼 ───────────────────────────────────────────────────── */

function getToken(): string {
  return (typeof window !== "undefined" ? localStorage.getItem("ir_token") : null) ?? "";
}

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`,
      ...(opts?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json();
}

/* ─── 타입 ─────────────────────────────────────────────────────────────── */

interface Signal {
  id: string;
  rule_id: string;
  severity: string;
  source_ip: string;
  asset_id: string;
  created_at: string;
  novelty_score?: number;
  cti_result?: { abuse_score?: number; country?: string };
}

interface CtiResult {
  ip: string;
  is_known_malicious: boolean;
  pulse_count: number;
  abuse_score: number;
  country: string | null;
  is_tor_exit_node: boolean;
  tags: string[];
  cache_hit: boolean;
  lookup_failed: boolean;
  error?: string;
}

/* ─── 색상 헬퍼 ─────────────────────────────────────────────────────────── */

function sevColor(sev: string) {
  const s = sev.toLowerCase();
  if (s === "critical") return "var(--c-red-500)";
  if (s === "high") return "var(--c-orange-500)";
  if (s === "medium") return "var(--c-amber-500)";
  return "var(--c-blue-500)";
}

/* ─── 탭 타입 ──────────────────────────────────────────────────────────── */

type Tab = "signals" | "cti" | "replay";

/* ═══════════════════════════════════════════════════════════════════════
   메인 페이지
   ═══════════════════════════════════════════════════════════════════════ */

export function ThreatHuntingPage() {
  const [tab, setTab] = useState<Tab>("signals");

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div>
          <h2 className="page-title">Threat Hunting</h2>
          <p className="page-subtitle">시그널 탐색 · CTI 조회 · 이벤트 재생</p>
        </div>
      </div>

      {/* 탭 */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24,
                    borderBottom: "1px solid var(--border)", paddingBottom: 0 }}>
        {(
          [
            { id: "signals" as Tab, icon: Search,  label: "시그널 탐색기" },
            { id: "cti"     as Tab, icon: Shield,  label: "CTI IP 조회" },
            { id: "replay"  as Tab, icon: Play,    label: "이벤트 재생" },
          ] as const
        ).map(({ id, icon: Icon, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "8px 16px", border: "none", background: "transparent",
              cursor: "pointer", fontSize: 13, fontWeight: 500,
              color: tab === id ? "var(--text-1)" : "var(--text-3)",
              borderBottom: tab === id
                ? "2px solid var(--c-indigo-500)" : "2px solid transparent",
              marginBottom: -1,
            }}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {tab === "signals" && <SignalExplorer />}
      {tab === "cti"     && <CtiLookup />}
      {tab === "replay"  && <EventReplay />}
    </div>
  );
}

/* ─── 시그널 탐색기 ─────────────────────────────────────────────────────── */

function SignalExplorer() {
  const [ruleId, setRuleId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [signals, setSignals] = useState<Signal[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [searched, setSearched] = useState(false);

  async function search() {
    setLoading(true);
    setError(undefined);
    try {
      const qs = new URLSearchParams({ limit: "100" });
      if (ruleId.trim())  qs.set("rule_id",  ruleId.trim());
      if (assetId.trim()) qs.set("asset_id", assetId.trim());
      const data = await apiFetch<{ signals: Signal[] }>(`/api/v1/debug/signals?${qs}`);
      setSignals(data.signals ?? []);
      setSearched(true);
    } catch (e: any) {
      setError(e.message ?? "조회 실패");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <input
          className="input"
          placeholder="룰 ID (예: AUTH-001, PERSIST-001)"
          value={ruleId}
          onChange={(e) => setRuleId(e.target.value)}
          style={{ width: 240 }}
          onKeyDown={(e) => e.key === "Enter" && search()}
        />
        <input
          className="input"
          placeholder="자산 ID"
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          style={{ width: 200 }}
          onKeyDown={(e) => e.key === "Enter" && search()}
        />
        <button
          className="btn btn-primary"
          onClick={search}
          disabled={loading}
          style={{ display: "flex", alignItems: "center", gap: 6 }}
        >
          {loading ? <RefreshCw size={14} className="spin" /> : <Search size={14} />}
          조회
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 16 }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {searched && signals.length === 0 && !loading && (
        <div style={{ textAlign: "center", color: "var(--text-3)", padding: "40px 0", fontSize: 13 }}>
          조건에 맞는 시그널이 없습니다.
        </div>
      )}

      {signals.length > 0 && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>시각</th>
                <th>룰 ID</th>
                <th>심각도</th>
                <th>소스 IP</th>
                <th>자산</th>
                <th>신규성</th>
                <th>CTI</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "nowrap" }}>
                    {new Date(s.created_at).toLocaleString("ko-KR")}
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12,
                                   background: "var(--c-gray-100)", border: "1px solid var(--border)",
                                   borderRadius: 4, padding: "1px 6px" }}>
                      {s.rule_id}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, fontSize: 12, color: sevColor(s.severity) }}>
                      {s.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{s.source_ip || "—"}</td>
                  <td style={{ fontSize: 12 }}>{s.asset_id}</td>
                  <td style={{ textAlign: "center" }}>
                    {s.novelty_score != null
                      ? <span style={{ fontSize: 12, color: s.novelty_score > 0.05 ? "var(--c-orange-500)" : "var(--text-3)" }}>
                          {(s.novelty_score * 100).toFixed(0)}%
                        </span>
                      : "—"}
                  </td>
                  <td style={{ textAlign: "center" }}>
                    {s.cti_result?.abuse_score
                      ? <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 12, fontWeight: 600, color: "var(--c-red-500)" }}>
                          <AlertOctagon size={12} /> {s.cti_result.abuse_score}
                        </span>
                      : <span style={{ fontSize: 12, color: "var(--text-4)" }}>—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ─── CTI IP 조회 ───────────────────────────────────────────────────────── */

function CtiLookup() {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<CtiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  async function lookup() {
    if (!ip.trim()) return;
    setLoading(true);
    setError(undefined);
    setResult(null);
    try {
      const data = await apiFetch<CtiResult>(`/api/v1/cti/ip/${ip.trim()}`);
      setResult(data);
    } catch (e: any) {
      setError(e.message ?? "CTI 조회 실패");
    } finally {
      setLoading(false);
    }
  }

  async function invalidateCache() {
    if (!ip.trim()) return;
    try {
      await apiFetch(`/api/v1/cti/ip/${ip.trim()}/cache`, { method: "DELETE" });
      await lookup();
    } catch (e: any) {
      setError(e.message ?? "캐시 만료 실패");
    }
  }

  return (
    <div style={{ maxWidth: 560 }}>
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        <input
          className="input"
          placeholder="IP 주소 (예: 45.33.100.1)"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{ flex: 1 }}
          onKeyDown={(e) => e.key === "Enter" && lookup()}
        />
        <button
          className="btn btn-primary"
          onClick={lookup}
          disabled={loading || !ip.trim()}
          style={{ display: "flex", alignItems: "center", gap: 6 }}
        >
          {loading ? <RefreshCw size={14} className="spin" /> : <Shield size={14} />}
          OTX 조회
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 16 }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {result && (
        <div className="card" style={{ padding: 20 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              {result.lookup_failed ? (
                <AlertTriangle size={20} color="var(--c-amber-500)" />
              ) : result.is_known_malicious ? (
                <AlertTriangle size={20} color="var(--c-red-500)" />
              ) : (
                <CheckCircle size={20} color="var(--c-green-500)" />
              )}
              <div>
                <div style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 16 }}>{result.ip}</div>
                <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 2, display: "inline-flex", alignItems: "center", gap: 4 }}>
                  {result.cache_hit ? <><Database size={11} /> 캐시에서 반환됨</> : <><Search size={11} /> OTX 실시간 조회</>}
                </div>
              </div>
            </div>
            <button
              className="btn"
              onClick={invalidateCache}
              style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 4 }}
            >
              <RefreshCw size={12} /> 캐시 초기화
            </button>
          </div>

          {result.error && (
            <div className="alert alert-warning" style={{ marginBottom: 12, fontSize: 13 }}>
              {result.error}
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[
              { label: "위협 여부",  value: result.is_known_malicious ? "알려진 악성 IP" : "위협 미탐지",
                color: result.is_known_malicious ? "var(--c-red-500)" : "var(--c-green-500)",
                icon: result.is_known_malicious ? <AlertOctagon size={13} /> : <ShieldCheck size={13} /> },
              { label: "남용 점수", value: `${result.abuse_score} / 100` },
              { label: "OTX Pulse", value: `${result.pulse_count}개` },
              { label: "국가",      value: result.country ?? "—" },
              { label: "Tor 출구",  value: result.is_tor_exit_node ? "Tor Exit Node" : "아니오",
                icon: result.is_tor_exit_node ? <Wifi size={13} /> : undefined },
              { label: "태그",      value: result.tags.length > 0 ? result.tags.join(", ") : "—" },
            ].map((it: { label: string; value: string; color?: string; icon?: React.ReactNode }) => (
              <div key={it.label} style={{ background: "var(--c-gray-50)", borderRadius: 8,
                                        border: "1px solid var(--border)", padding: "10px 14px" }}>
                <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>{it.label}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: it.color ?? "var(--text-1)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                  {it.icon}{it.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── 이벤트 재생 (dev/staging 전용) ───────────────────────────────────── */

const PRESET_SCENARIOS = [
  {
    label: "SSH 브루트포스 (AUTH-001 × 10)",
    events: Array.from({ length: 10 }, (_, i) => ({
      event_type: "ssh_login_failed",
      source_ip: "45.33.100.1",
      user: "root",
      asset_id: "asset-prod-web-01",
      data: { attempt: i + 1 },
    })),
  },
  {
    label: "SSH 계정 탈취 체인 (AUTH-001+004+PERSIST-001)",
    events: [
      ...Array.from({ length: 5 }, (_, i) => ({
        event_type: "ssh_login_failed",
        source_ip: "45.33.100.1",
        user: "deploy",
        asset_id: "asset-prod-web-01",
        data: { attempt: i + 1 },
      })),
      {
        event_type: "ssh_login_success",
        source_ip: "45.33.100.1",
        user: "deploy",
        asset_id: "asset-prod-web-01",
        data: {},
      },
      {
        event_type: "authorized_keys_modified",
        source_ip: "45.33.100.1",
        user: "deploy",
        asset_id: "asset-prod-web-01",
        data: { path: "/home/deploy/.ssh/authorized_keys", action: "key_added" },
      },
    ],
  },
  {
    label: "Honeypot 경로 탐색 (WEB-HNY-001)",
    events: [
      { event_type: "web_request", source_ip: "1.2.3.4", asset_id: "asset-prod-web-01",
        data: { path: "/.env", status_code: 200 } },
      { event_type: "web_request", source_ip: "1.2.3.4", asset_id: "asset-prod-web-01",
        data: { path: "/wp-admin", status_code: 200 } },
      { event_type: "web_request", source_ip: "1.2.3.4", asset_id: "asset-prod-web-01",
        data: { path: "/phpmyadmin", status_code: 200 } },
    ],
  },
];

function EventReplay() {
  const [selectedPreset, setSelectedPreset] = useState<number | null>(null);
  const [dryRun, setDryRun] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ replayed: number; dry_run: boolean; event_ids: string[] } | null>(null);
  const [error, setError] = useState<string>();

  async function replay() {
    if (selectedPreset === null) return;
    setLoading(true);
    setError(undefined);
    setResult(null);
    try {
      const scenario = PRESET_SCENARIOS[selectedPreset];
      const data = await apiFetch<typeof result>("/api/v1/debug/replay-events", {
        method: "POST",
        body: JSON.stringify({ events: scenario.events, dry_run: dryRun }),
      });
      setResult(data);
    } catch (e: any) {
      setError(e.message ?? "재생 실패");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 600 }}>
      <div className="alert" style={{
        background: "var(--c-amber-50)", border: "1px solid var(--c-amber-200)",
        borderRadius: 8, padding: "10px 14px", marginBottom: 20, fontSize: 13,
        display: "flex", gap: 8, alignItems: "flex-start",
      }}>
        <Info size={16} style={{ marginTop: 1, flexShrink: 0, color: "var(--c-amber-600)" }} />
        <div>
          <strong>개발/스테이징 전용</strong><br />
          이벤트 재생은 탐지 파이프라인 E2E 검증 용도입니다.
          운영(prod) 환경에서는 403을 반환합니다.
          <strong>Dry Run 모드</strong>를 먼저 사용해 결과를 확인하세요.
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 20 }}>
        {PRESET_SCENARIOS.map((s, i) => (
          <label key={i} style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "12px 16px", border: "1px solid var(--border)",
            borderRadius: 8, cursor: "pointer",
            background: selectedPreset === i ? "var(--c-indigo-50)" : "transparent",
            borderColor: selectedPreset === i ? "var(--c-indigo-300)" : "var(--border)",
          }}>
            <input
              type="radio"
              name="preset"
              checked={selectedPreset === i}
              onChange={() => setSelectedPreset(i)}
            />
            <div>
              <div style={{ fontWeight: 600, fontSize: 13 }}>{s.label}</div>
              <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 2 }}>
                {s.events.length}개 이벤트
              </div>
            </div>
          </label>
        ))}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(e) => setDryRun(e.target.checked)}
          />
          <strong>Dry Run</strong> (Redis 미적재, 결과만 확인)
        </label>
      </div>

      <button
        className="btn btn-primary"
        onClick={replay}
        disabled={loading || selectedPreset === null}
        style={{ display: "flex", alignItems: "center", gap: 6 }}
      >
        {loading ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
        {dryRun ? "Dry Run 실행" : "실제 재생"}
      </button>

      {error && (
        <div className="alert alert-error" style={{ marginTop: 16 }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {result && (
        <div className="card" style={{ marginTop: 16, padding: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <CheckCircle size={16} color="var(--c-green-500)" />
            <strong style={{ fontSize: 14 }}>
              {result.dry_run ? "Dry Run 완료" : "재생 완료"}
            </strong>
          </div>
          <div style={{ fontSize: 13, color: "var(--text-2)" }}>
            이벤트 <strong>{result.replayed}개</strong> {result.dry_run ? "검증됨" : "주입됨"}
          </div>
          {!result.dry_run && result.event_ids.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>이벤트 ID</div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)" }}>
                {result.event_ids.slice(0, 3).join(", ")}
                {result.event_ids.length > 3 && ` 외 ${result.event_ids.length - 3}개`}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
