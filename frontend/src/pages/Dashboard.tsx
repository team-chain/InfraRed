import { useEffect, useRef, useState } from "react";
import {
  Activity, AlertTriangle, Bell, BrainCircuit, CheckCircle2,
  ChevronLeft, ChevronRight, ClipboardList, Cog, Globe, LogOut, Monitor,
  RefreshCw, Shield, ShieldAlert, Siren, UserPlus,
} from "lucide-react";
import { SettingsPage } from "./SettingsPage";
import { AssetsPage } from "./AssetsPage";
import { IncidentDetailPage } from "./IncidentDetailPage";
import {
  analyzeIncident, dispatchIncident, fetchAuditLogs,
  fetchDetectionRules, fetchIncident, fetchIncidents,
  updateIncidentStatus,
  type AuditLog, type AuthUser, type DetectionRule,
  type IncidentContract, type IncidentListItem,
} from "../lib/api";

type Props = { user: AuthUser; onLogout: () => void; onOpenOnboarding: () => void };
type Tab = "incidents" | "assets" | "rules" | "audit" | "settings";

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, info: 1 };
const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL ?? "http://localhost:8000";

function flag(code: string) {
  return String.fromCodePoint(...[...code].map(c => 0x1F1A5 + c.charCodeAt(0)));
}

function relTime(iso: string) {
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) return "방금";
  if (m < 60) return `${m}분 전`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}시간 전`;
  return `${Math.floor(h / 24)}일 전`;
}

function abuseColor(n: number) {
  if (n >= 70) return "var(--c-red-500)";
  if (n >= 40) return "var(--c-orange-500)";
  return "var(--c-green-500)";
}

/** LLM 분석 상태 배지 — Gray: 미분석 / Orange: 분석 중 / Green: 완료 */
function LlmBadge({ hasSummary, isAnalyzing }: {
  hasSummary: boolean;
  isAnalyzing: boolean;
}) {
  if (isAnalyzing) {
    return (
      <span className="llm-badge llm-badge-orange">
        <BrainCircuit size={10} className="spin" style={{flexShrink:0}} />
        분석 중
      </span>
    );
  }
  if (hasSummary) {
    return (
      <span className="llm-badge llm-badge-green">
        <BrainCircuit size={10} style={{flexShrink:0}} />
        AI 완료
      </span>
    );
  }
  return (
    <span className="llm-badge llm-badge-gray">
      <BrainCircuit size={10} style={{flexShrink:0}} />
      미분석
    </span>
  );
}

export function Dashboard({ user, onLogout, onOpenOnboarding }: Props) {
  const [tab, setTab] = useState<Tab>("incidents");
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  // Honeypot /demo 방문자 실시간 카드 (SSE demo_visitor 이벤트로 추가)
  const [demoVisitors, setDemoVisitors] = useState<{ demo_signal_id: string; source_ip_masked: string | null; path: string; detected_at: string }[]>([]);
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [analyzingIds, setAnalyzingIds] = useState<Set<string>>(new Set());
  const [sseConnected, setSseConnected] = useState(false);
  const [listOpen, setListOpen] = useState(true);

  const esRef = useRef<EventSource | null>(null);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  async function load() {
    setLoading(true); setError(undefined);
    try {
      const items = await fetchIncidents();
      setIncidents(items);
      if (items.length) {
        const id = selectedRef.current?.incident.incident_id ?? items[0].incident_id;
        setSelected(await fetchIncident(id));
      } else setSelected(undefined);
    } catch (e) { setError(e instanceof Error ? e.message : "오류 발생"); }
    finally { setLoading(false); }
  }

  async function selectInc(inc: IncidentListItem) {
    setError(undefined); setNotice(undefined);
    try { setSelected(await fetchIncident(inc.incident_id)); }
    catch (e) { setError(e instanceof Error ? e.message : "오류 발생"); }
  }

  async function runAnalysis(refresh = false) {
    if (!selectedRef.current) return;
    const id = selectedRef.current.incident.incident_id;
    setBusy("analysis"); setError(undefined); setNotice(undefined);
    setAnalyzingIds(prev => new Set([...prev, id]));
    try {
      await analyzeIncident(id, refresh);
      setSelected(await fetchIncident(id));
      await load();
      setNotice("AI 분석이 완료됐습니다.");
    } catch (e) { setError(e instanceof Error ? e.message : "분석 실패"); }
    finally {
      setBusy(undefined);
      setAnalyzingIds(prev => { const next = new Set(prev); next.delete(id); return next; });
    }
  }

  async function sendAlert() {
    if (!selectedRef.current) return;
    setBusy("dispatch"); setError(undefined); setNotice(undefined);
    try {
      const r = await dispatchIncident(selectedRef.current.incident.incident_id);
      const ch = [r.discord_sent && "Discord", r.email_sent && "Email"].filter(Boolean);
      setNotice(ch.length ? `${ch.join(", ")} 알림을 발송했습니다.` : "설정된 알림 채널이 없습니다.");
    } catch (e) { setError(e instanceof Error ? e.message : "발송 실패"); }
    finally { setBusy(undefined); }
  }

  async function changeStatus(status: string) {
    if (!selectedRef.current) return;
    setBusy("status"); setError(undefined); setNotice(undefined);
    try {
      await updateIncidentStatus(selectedRef.current.incident.incident_id, status);
      setSelected(await fetchIncident(selectedRef.current.incident.incident_id));
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "상태 변경 실패"); }
    finally { setBusy(undefined); }
  }

  // 초기 로드 + 30초 폴링
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  // SSE 실시간 연결
  useEffect(() => {
    const connect = () => {
      const es = new EventSource(`${API_BASE_URL}/api/events/stream`, { withCredentials: true });
      esRef.current = es;

      es.onopen = () => setSseConnected(true);

      es.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data.event === "incident.new" || data.event === "incident.updated") {
            fetchIncidents().then(items => {
              setIncidents(items);
              if (selectedRef.current && data.incident_id === selectedRef.current.incident.incident_id) {
                fetchIncident(data.incident_id).then(setSelected).catch(() => {});
              }
            }).catch(() => {});
          }
          // Honeypot /demo 방문자 실시간 카드 추가 (설계서 성공 기준 1번)
          if (data.event === "demo_visitor") {
            setDemoVisitors(prev => [
              { demo_signal_id: data.demo_signal_id, source_ip_masked: data.source_ip_masked ?? null, path: data.path ?? "/demo", detected_at: data.detected_at },
              ...prev,
            ].slice(0, 50)); // 최대 50개 유지
          }
        } catch (_) {}
      };

      es.onerror = () => {
        setSseConnected(false);
        // EventSource 자동 재연결 — 별도 처리 없음
      };
    };

    connect();
    return () => { esRef.current?.close(); esRef.current = null; setSseConnected(false); };
  }, []);

  useEffect(() => {
    if (tab === "rules" && !rules.length) fetchDetectionRules().then(setRules).catch(() => {});
    if (tab === "audit") { setAuditLoading(true); fetchAuditLogs().then(setAuditLogs).catch(() => {}).finally(() => setAuditLoading(false)); }
  }, [tab]);

  const inc = selected?.incident;
  const openN     = incidents.filter(i => i.status === "open").length;
  const critN     = incidents.filter(i => i.severity === "critical").length;
  const highN     = incidents.filter(i => i.severity === "high").length;
  const doneN     = incidents.filter(i => i.status === "resolved").length;
  // Honeypot 방문자: SSE demo_visitor 실시간 누적 + 인시던트 중 Reconnaissance 포함
  const honeypotN = demoVisitors.length + incidents.filter(i =>
    i.asset_id?.startsWith("sdk-web") || i.mitre_tactic === "Reconnaissance"
  ).length;

  const initials = (user.email ?? user.role ?? "U").slice(0, 2).toUpperCase();

  return (
    <div className="shell">
      {/* ── Top bar ──────────────────────────────────────────── */}
      <header className="topbar">
        <div className="brand">
          <div className="brand-logo"><ShieldAlert size={18} /></div>
          <span className="brand-name">InfraRed SOC</span>
          <span className="brand-badge">Beta</span>
        </div>
        <div className="top-actions">
          {/* SSE 실시간 연결 표시 */}
          <span
            className={`sse-dot ${sseConnected ? "sse-dot-on" : "sse-dot-off"}`}
            title={sseConnected ? "실시간 연결됨" : "연결 중…"}
          />
          <div className="user-chip">
            <div className="user-avatar">{initials}</div>
            <span className="user-email">{user.email ?? user.role}</span>
          </div>
          <button className="icon-btn" onClick={load} disabled={loading} title="새로고침">
            <RefreshCw size={15} className={loading ? "spin" : ""} />
          </button>
          <button className="icon-btn" onClick={onOpenOnboarding} title="에이전트 연결">
            <UserPlus size={15} />
          </button>
          <button className="icon-btn danger" onClick={onLogout} title="로그아웃">
            <LogOut size={15} />
          </button>
        </div>
      </header>

      {/* ── Tab nav ──────────────────────────────────────────── */}
      <nav className="tab-nav">
        {([
          { key: "incidents", icon: <Siren size={15}/>, name: "인시던트", desc: "탐지된 보안 위협", badge: openN || null },
          { key: "assets",   icon: <Monitor size={15}/>, name: "자산 현황", desc: "서버 및 에이전트" },
          { key: "rules",    icon: <Shield size={15}/>,  name: "탐지 룰",  desc: "공격 패턴 설정" },
          { key: "audit",    icon: <ClipboardList size={15}/>, name: "감사 로그", desc: "활동 기록" },
          { key: "settings", icon: <Cog size={15}/>,     name: "설정",     desc: "알림 및 대응 정책" },
        ] as const).map(({ key, icon, name, desc, badge }: { key: Tab; icon: React.ReactNode; name: string; desc: string; badge?: number | null }) => (
          <button key={key} className={`tab-btn${tab === key ? " tab-active" : ""}`} onClick={() => setTab(key)}>
            {icon}
            <span className="tab-text">
              <span className="tab-name">{name}</span>
              <span className="tab-desc">{desc}</span>
            </span>
            {badge ? <span className="tab-badge">{badge}</span> : null}
          </button>
        ))}
      </nav>

      {/* ── Notification bars ────────────────────────────────── */}
      {error  && <div className="alert">⚠ {error}</div>}
      {notice && <div className="notice">✓ {notice}</div>}

      {/* ══════════════════════════════════════════════════════
          INCIDENTS
      ══════════════════════════════════════════════════════ */}
      {tab === "incidents" && (
        <>
          {/* Stats */}
          <div className="stats-bar">
            {[
              { icon: <Activity size={16}/>,      cls: "blue",   val: incidents.length, label: "전체 인시던트" },
              { icon: <AlertTriangle size={16}/>,  cls: "red",    val: critN,  label: "Critical" },
              { icon: <AlertTriangle size={16}/>,  cls: "orange", val: highN,  label: "High" },
              { icon: <Siren size={16}/>,           cls: "amber",  val: openN,  label: "미해결 (Open)" },
              { icon: <CheckCircle2 size={16}/>,    cls: "green",  val: doneN,  label: "해결 완료" },
            ].map(({ icon, cls, val, label }) => (
              <div key={label} className="stat-card">
                <div className={`stat-icon ${cls}`}>{icon}</div>
                <div>
                  <div className="stat-value">{val}</div>
                  <div className="stat-label">{label}</div>
                </div>
              </div>
            ))}

            {/* ── Honeypot 방문자 파란 카드 ── */}
            <div className="stat-card stat-card-honeypot">
              <div className="stat-icon blue" style={{position:"relative"}}>
                <Globe size={16} />
                <span className="honeypot-pulse-ring" />
              </div>
              <div>
                <div className="stat-value">{honeypotN}</div>
                <div className="stat-label">허니팟 방문자</div>
              </div>
              <span className="honeypot-sdk-badge">SDK</span>
            </div>
          </div>

          <div className="layout">
            {/* Left: list */}
            <div className={`left-pane${listOpen ? "" : " left-pane-collapsed"}`}>
              <div className="pane-header">
                {listOpen && <>
                  <span className="pane-header-title">인시던트 목록</span>
                  <span className="pane-header-count">{incidents.length}</span>
                </>}
                <button
                  className="icon-btn list-toggle-btn"
                  onClick={() => setListOpen(v => !v)}
                  title={listOpen ? "목록 숨기기" : "목록 보기"}
                >
                  {listOpen ? <ChevronLeft size={15} /> : <ChevronRight size={15} />}
                </button>
              </div>
              <div className="incident-list" style={listOpen ? {} : { display: "none" }}>
                {[...incidents]
                  .sort((a, b) =>
                    (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) ||
                    new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
                  )
                  .map(item => (
                    <button key={item.incident_id}
                      className={`incident-card${item.incident_id === inc?.incident_id ? " selected" : ""}`}
                      onClick={() => selectInc(item)}
                    >
                      <div className={`inc-sev-dot ${item.severity}`} />
                      <div className="inc-card-body">
                        <div className="inc-card-top">
                          <span className={`pill pill-sm sev-${item.severity}`}>{item.severity.toUpperCase()}</span>
                          <LlmBadge
                            hasSummary={!!item.llm_summary}
                            isAnalyzing={analyzingIds.has(item.incident_id)}
                          />
                          <span className="inc-card-time">{relTime(item.created_at)}</span>
                        </div>
                        <div className="inc-card-id">{item.incident_id}</div>
                        <div className="inc-card-rule">{item.mitre_tactic}</div>
                        <div className="inc-card-meta">
                          {item.source_ip && (
                            <span style={{fontFamily:"var(--mono)", fontSize:11, color:"var(--text-3)"}}>
                              {item.source_ip}
                            </span>
                          )}
                          <span style={{fontSize:11, color:"var(--text-3)"}}>·</span>
                          <span className={`inc-status-chip status-${item.status.replace(" ","_")}`}>
                            {{ open:"미해결", acknowledged:"확인됨", resolved:"해결됨", false_positive:"오탐" }[item.status] ?? item.status}
                          </span>
                        </div>
                        {item.llm_summary && (
                          <div className="inc-card-preview">{item.llm_summary}</div>
                        )}
                      </div>
                    </button>
                  ))}
                {!incidents.length && (
                  <div style={{padding:"48px 24px", textAlign:"center", color:"var(--text-3)", fontSize:13.5}}>
                    탐지된 인시던트가 없습니다
                  </div>
                )}
              </div>
            </div>

            {/* Right: 인시던트 상세 페이지 */}
            <div className="right-pane">
              <IncidentDetailPage
                selected={selected}
                busy={busy}
                onRunAnalysis={runAnalysis}
                onSendAlert={sendAlert}
                onChangeStatus={changeStatus}
                analyzingIds={analyzingIds}
              />
            </div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════════════════════
          ASSETS
      ══════════════════════════════════════════════════════ */}
      {tab === "assets" && <AssetsPage />}

      {/* ══════════════════════════════════════════════════════
          RULES
      ══════════════════════════════════════════════════════ */}
      {tab === "rules" && (
        <div className="page-wrap">
          <div className="page-header">
            <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between"}}>
              <div>
                <h2 className="page-title">탐지 룰</h2>
                <p className="page-subtitle">활성화된 보안 탐지 패턴과 MITRE ATT&CK 매핑 현황</p>
              </div>
              <span className="pill sev-info" style={{marginTop:4}}>
                {rules.filter(r => r.enabled).length} / {rules.length} 활성
              </span>
            </div>
          </div>
          {rulesLoading ? (
            <p style={{color:"var(--text-3)", fontSize:14}}>룰 목록 로딩 중…</p>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr><th>Rule ID</th><th>룰 이름</th><th>MITRE 전술</th><th>기술 ID</th><th>상태</th></tr>
                </thead>
                <tbody>
                  {rules.map(rule => (
                    <tr key={rule.rule_id}>
                      <td><code>{rule.rule_id}</code></td>
                      <td><strong>{rule.name}</strong></td>
                      <td>{rule.mitre_tactic ?? "-"}</td>
                      <td><code>{rule.mitre_technique ?? "-"}</code></td>
                      <td>
                        {rule.enabled
                          ? <span className="pill pill-sm sev-info">✓ 활성</span>
                          : <span className="pill pill-sm" style={{background:"var(--c-gray-100)", color:"var(--text-3)", border:"1px solid var(--border)"}}>비활성</span>
                        }
                      </td>
                    </tr>
                  ))}
                  {!rules.length && (
                    <tr><td colSpan={5} style={{textAlign:"center", color:"var(--text-3)", padding:"32px"}}>룰 없음</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          AUDIT
      ══════════════════════════════════════════════════════ */}
      {tab === "audit" && (
        <div className="page-wrap">
          <div className="page-header">
            <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between"}}>
              <div>
                <h2 className="page-title">감사 로그</h2>
                <p className="page-subtitle">모든 사용자 활동과 시스템 액션의 불변 기록</p>
              </div>
              <button className="btn btn-sm" onClick={() => {
                setAuditLoading(true);
                fetchAuditLogs().then(setAuditLogs).catch(()=>{}).finally(()=>setAuditLoading(false));
              }} disabled={auditLoading}>
                <RefreshCw size={13} className={auditLoading ? "spin" : ""} /> 새로고침
              </button>
            </div>
          </div>
          {auditLoading ? <p style={{color:"var(--text-3)", fontSize:14}}>로딩 중…</p> : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead><tr><th>시간</th><th>실행자</th><th>액션</th><th>대상</th><th>IP</th></tr></thead>
                <tbody>
                  {auditLogs.map(log => (
                    <tr key={log.id}>
                      <td style={{fontFamily:"var(--mono)", fontSize:12}}>{new Date(log.timestamp).toLocaleString("ko-KR")}</td>
                      <td><strong>{log.actor}</strong></td>
                      <td><code>{log.action}</code></td>
                      <td>{log.resource ?? "-"}</td>
                      <td style={{fontFamily:"var(--mono)", fontSize:12}}>{log.ip ?? "-"}</td>
                    </tr>
                  ))}
                  {!auditLogs.length && (
                    <tr><td colSpan={5} style={{textAlign:"center", color:"var(--text-3)", padding:"32px"}}>감사 로그 없음</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════
          SETTINGS
      ══════════════════════════════════════════════════════ */}
      {tab === "settings" && <SettingsPage />}
    </div>
  );
}
