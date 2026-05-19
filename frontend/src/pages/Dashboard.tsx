import { useEffect, useState } from "react";
import {
  Activity, AlertTriangle, Bell, BrainCircuit, CheckCircle2,
  ClipboardList, Cog, GitCommitVertical, LogOut, Monitor,
  RefreshCw, Shield, ShieldAlert, Siren, UserPlus,
  Heart, BookOpen, VolumeX, Users, FileText, Search,
  Lock, Unlock, Clock, Target,
} from "lucide-react";
import { SettingsPage } from "./SettingsPage";
import { AssetsPage } from "./AssetsPage";
import { HealthDashboardPage } from "./HealthDashboardPage";
import { RuleManagementPage } from "./RuleManagementPage";
import { SuppressionPage } from "./SuppressionPage";
import { MembersPage } from "./MembersPage";
import { ReportsPage } from "./ReportsPage";
import { NaturalSearchPage } from "./NaturalSearchPage";
import { CampaignsPage } from "./CampaignsPage";
import { ThreatHuntingPage } from "./ThreatHuntingPage";
import { SigmaMarketplacePage } from "./SigmaMarketplacePage";
import { IncidentWorkflow } from "../components/IncidentWorkflow";
import {
  analyzeIncident, approveBlock, rejectBlock, extendBlock,
  dispatchIncident, fetchAuditLogs,
  fetchDetectionRules, fetchIncident, fetchIncidents,
  updateIncidentStatus,
  type AuditLog, type AuthUser, type DetectionRule,
  type IncidentContract, type IncidentListItem,
} from "../lib/api";

type Props = { user: AuthUser; onLogout: () => void; onOpenOnboarding: () => void };
type Tab =
  | "incidents" | "assets" | "rules" | "audit" | "settings"
  | "health" | "rule_mgmt" | "suppression" | "members" | "reports" | "search" | "campaigns"
  | "threat_hunting"
  | "sigma_marketplace";

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, info: 1 };

const PRIORITY_KO: Record<string, string> = { critical: "긴급", high: "높음", medium: "보통", low: "낮음" };
const CONF_KO: Record<string, string>     = { high: "높음", medium: "보통", low: "낮음" };
const MODEL_KO: Record<string, string>    = {
  "static-playbook": "정적 플레이북",
  "bedrock": "AI (Bedrock)",
  "anthropic": "AI (Claude)",
};
const TACTIC_KO: Record<string, string> = {
  "Initial Access": "초기 침투",
  "Execution": "실행",
  "Persistence": "지속성",
  "Privilege Escalation": "권한 상승",
  "Defense Evasion": "방어 우회",
  "Credential Access": "자격증명 탈취",
  "Discovery": "정찰·탐색",
  "Lateral Movement": "내부 이동",
  "Collection": "정보 수집",
  "Command and Control": "명령 제어",
  "Exfiltration": "데이터 유출",
  "Impact": "피해·영향",
  "Reconnaissance": "사전 정찰",
  "Resource Development": "자원 개발",
};
function tacticLabel(t: string) { return TACTIC_KO[t] ? `${TACTIC_KO[t]} (${t})` : t; }

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

function TtlCountdown({ expiresAt }: { expiresAt: string }) {
  const [remaining, setRemaining] = useState<string>("");
  useEffect(() => {
    function update() {
      const ms = new Date(expiresAt).getTime() - Date.now();
      if (ms <= 0) { setRemaining("만료됨"); return; }
      const h = Math.floor(ms / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      setRemaining(h > 0 ? `${h}시간 ${m}분 남음` : m > 0 ? `${m}분 ${s}초 남음` : `${s}초 남음`);
    }
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, [expiresAt]);
  return (
    <span className="card-head-sub" style={{display:"flex", alignItems:"center", gap:4, color: remaining === "만료됨" ? "var(--c-red-500)" : "var(--text-3)"}}>
      <Clock size={11} /> {remaining}
    </span>
  );
}

export function Dashboard({ user, onLogout, onOpenOnboarding }: Props) {
  const [tab, setTab] = useState<Tab>("incidents");
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [showWorkflow, setShowWorkflow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  const [blockBusy, setBlockBusy] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  async function load() {
    setLoading(true); setError(undefined);
    try {
      const items = await fetchIncidents();
      setIncidents(items);
      if (items.length) {
        const id = selected?.incident.incident_id ?? items[0].incident_id;
        setSelected(await fetchIncident(id));
      } else setSelected(undefined);
    } catch (e) { setError(e instanceof Error ? e.message : "오류 발생"); }
    finally { setLoading(false); }
  }

  async function selectInc(inc: IncidentListItem) {
    setError(undefined); setNotice(undefined);
    setShowWorkflow(false);
    try { setSelected(await fetchIncident(inc.incident_id)); }
    catch (e) { setError(e instanceof Error ? e.message : "오류 발생"); }
  }

  async function runAnalysis(refresh = false) {
    if (!selected) return;
    setBusy("analysis"); setError(undefined); setNotice(undefined);
    try {
      await analyzeIncident(selected.incident.incident_id, refresh);
      setSelected(await fetchIncident(selected.incident.incident_id));
      await load();
      setNotice("AI 분석이 완료됐습니다.");
    } catch (e) { setError(e instanceof Error ? e.message : "분석 실패"); }
    finally { setBusy(undefined); }
  }

  async function sendAlert() {
    if (!selected) return;
    setBusy("dispatch"); setError(undefined); setNotice(undefined);
    try {
      const r = await dispatchIncident(selected.incident.incident_id);
      const ch = [r.discord_sent && "Discord", r.email_sent && "Email"].filter(Boolean);
      setNotice(ch.length ? `${ch.join(", ")} 알림을 발송했습니다.` : "설정된 알림 채널이 없습니다.");
    } catch (e) { setError(e instanceof Error ? e.message : "발송 실패"); }
    finally { setBusy(undefined); }
  }

  async function changeStatus(status: string) {
    if (!selected) return;
    setBusy("status"); setError(undefined); setNotice(undefined);
    try {
      await updateIncidentStatus(selected.incident.incident_id, status);
      setSelected(await fetchIncident(selected.incident.incident_id));
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "상태 변경 실패"); }
    finally { setBusy(undefined); }
  }

  // Auto-dismiss notice after 4 seconds
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(undefined), 4000);
    return () => clearTimeout(t);
  }, [notice]);

  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, []);
  useEffect(() => {
    if (tab === "rules" && !rules.length) { setRulesLoading(true); fetchDetectionRules().then(setRules).catch(() => {}).finally(() => setRulesLoading(false)); }
    if (tab === "audit") { setAuditLoading(true); fetchAuditLogs().then(setAuditLogs).catch(() => {}).finally(() => setAuditLoading(false)); }
  }, [tab]);

  // SSE 실시간 Push
  useEffect(() => {
    // 개발 모드에서는 Vite 프록시를 통해 상대 경로 사용 (CORS 우회)
    const apiBase = import.meta.env.DEV
      ? ""
      : (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");
    const es = new EventSource(`${apiBase}/events/stream`, { withCredentials: true });
    es.addEventListener("incident_created", () => { load(); });
    es.addEventListener("incident_updated", () => { load(); });
    es.addEventListener("llm_completed", () => {
      if (selected) fetchIncident(selected.incident.incident_id).then(setSelected).catch(() => {});
    });
    return () => es.close();
  }, []);

  const llm = selected?.llm_result;
  const inc = selected?.incident;
  const cti = inc?.cti_enrichment;
  const confidenceBreakdown = (inc as any)?.confidence_breakdown;
  const pendingBlock = (inc as any)?.pending_block;
  const scenarioId = (inc as any)?.scenario_id;
  const openN  = incidents.filter(i => i.status === "open").length;
  const critN  = incidents.filter(i => i.severity === "critical").length;
  const highN  = incidents.filter(i => i.severity === "high").length;
  const doneN  = incidents.filter(i => i.status === "resolved").length;
  const initials = (user.email ?? user.role ?? "U").slice(0, 2).toUpperCase();

  // 탭 그룹
  const primaryTabs = [
    { key: "incidents", icon: <Siren size={15}/>, name: "인시던트", desc: "보안 위협", badge: openN || null },
    { key: "assets",   icon: <Monitor size={15}/>, name: "자산", desc: "서버·에이전트" },
    { key: "search",   icon: <Search size={15}/>,  name: "분석", desc: "검색·통계" },
  ] as const;

  const operationTabs = [
    { key: "rule_mgmt",     icon: <BookOpen size={15}/>, name: "룰 관리",   desc: "라이프사이클" },
    { key: "suppression",   icon: <VolumeX size={15}/>,  name: "억제",      desc: "Allowlist·점검창" },
    { key: "health",        icon: <Heart size={15}/>,    name: "헬스체크",  desc: "시스템 상태" },
    { key: "campaigns",     icon: <Target size={15}/>,   name: "캠페인",    desc: "공격 캠페인 뷰" },
    { key: "threat_hunting", icon: <Search size={15}/>,  name: "위협 헌팅", desc: "시그널·CTI·재생" },
    { key: "sigma_marketplace", icon: <Shield size={15}/>,  name: "SIGMA 마켓", desc: "커뮤니티 룰 탐색·활성화" },
  ] as const;

  const adminTabs = [
    { key: "members",  icon: <Users size={15}/>,       name: "멤버", desc: "RBAC 관리" },
    { key: "reports",  icon: <FileText size={15}/>,    name: "보고서", desc: "주간·월간" },
    { key: "rules",    icon: <Shield size={15}/>,      name: "룰 목록", desc: "탐지 패턴" },
    { key: "audit",    icon: <ClipboardList size={15}/>, name: "감사 로그", desc: "활동 기록" },
    { key: "settings", icon: <Cog size={15}/>,         name: "설정", desc: "알림·정책" },
  ] as const;

  function renderTabGroup(
    label: string,
    tabs: readonly { key: Tab; icon: React.ReactNode; name: string; desc: string; badge?: number | null }[]
  ) {
    return (
      <div style={{ marginBottom: 2 }}>
        <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-3)", padding: "6px 12px 2px" }}>
          {label}
        </div>
        {tabs.map(({ key, icon, name, desc, badge }) => (
          <button key={key}
            className={`tab-btn${tab === key ? " tab-active" : ""}`}
            onClick={() => setTab(key)}
          >
            {icon}
            <span className="tab-text">
              <span className="tab-name">{name}</span>
              <span className="tab-desc">{desc}</span>
            </span>
            {badge ? <span className="tab-badge">{badge}</span> : null}
          </button>
        ))}
      </div>
    );
  }

  return (
    <div className="shell">
      {/* ── Top bar ── */}
      <header className="topbar">
        <div className="brand">
          <div className="brand-logo"><ShieldAlert size={18} /></div>
          <span className="brand-name">InfraRed SOC</span>
          <span className="brand-badge">Beta</span>
        </div>
        <div className="top-actions">
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

      {/* ── Tab nav ── */}
      <nav className="tab-nav" style={{ overflowY: "auto" }}>
        {renderTabGroup("메인", primaryTabs)}
        {renderTabGroup("운영", operationTabs)}
        {renderTabGroup("관리", adminTabs)}
      </nav>

      <main className="main-area">
      {/* ── Notification bars ── */}
      {error  && <div className="alert">{error} <button onClick={() => setError(undefined)} style={{float:"right",background:"none",border:"none",cursor:"pointer",fontWeight:700}}>×</button></div>}
      {notice && <div className="notice">{notice} <button onClick={() => setNotice(undefined)} style={{float:"right",background:"none",border:"none",cursor:"pointer",fontWeight:700}}>×</button></div>}

      {/* ══ INCIDENTS ══ */}
      {tab === "incidents" && (
        <>
          <div className="stats-bar">
            {[
              { icon: <Activity size={16}/>,      cls: "blue",   val: incidents.length, label: "전체 인시던트" },
              { icon: <AlertTriangle size={16}/>,  cls: "red",    val: critN,  label: "Critical" },
              { icon: <AlertTriangle size={16}/>,  cls: "orange", val: highN,  label: "High" },
              { icon: <Siren size={16}/>,          cls: "amber",  val: openN,  label: "미해결 (Open)" },
              { icon: <CheckCircle2 size={16}/>,   cls: "green",  val: doneN,  label: "해결 완료" },
            ].map(({ icon, cls, val, label }) => (
              <div key={label} className="stat-card">
                <div className={`stat-icon ${cls}`}>{icon}</div>
                <div>
                  <div className="stat-value">{val}</div>
                  <div className="stat-label">{label}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="layout">
            {/* Left: list */}
            <div className="left-pane">
              <div className="pane-header">
                <span className="pane-header-title">인시던트 목록</span>
                <span className="pane-header-count">{incidents.length}</span>
              </div>
              <div className="incident-list">
                {[...incidents]
                  .sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) || new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
                  .map(item => (
                    <button key={item.incident_id}
                      className={`incident-card${item.incident_id === inc?.incident_id ? " selected" : ""}`}
                      onClick={() => selectInc(item)}
                    >
                      <div className={`inc-sev-dot ${item.severity}`} />
                      <div className="inc-card-body">
                        <div className="inc-card-top">
                          <span className={`pill pill-sm sev-${item.severity}`}>{item.severity}</span>
                          <span className="inc-card-time">{relTime(item.created_at)}</span>
                        </div>
                        <div className="inc-card-id">{item.incident_id}</div>
                        <div className="inc-card-rule">{TACTIC_KO[item.mitre_tactic] ?? item.mitre_tactic}</div>
                        <div className="inc-card-meta">
                          {item.source_ip && <span style={{fontFamily:"var(--mono)", fontSize:11, color:"var(--text-3)"}}>{item.source_ip}</span>}
                          <span style={{fontSize:11, color:"var(--text-3)"}}>·</span>
                          <span style={{fontSize:11, color:"var(--text-3)"}}>{item.status}</span>
                        </div>
                        {item.llm_summary && <div className="inc-card-preview">{item.llm_summary}</div>}
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

            {/* Right: detail */}
            <div className="right-pane">
              {!inc ? (
                <div className="empty-state">
                  <div className="empty-icon"><ShieldAlert size={26} /></div>
                  <h3>인시던트를 선택하세요</h3>
                  <p>왼쪽 목록에서 인시던트를 클릭하면 AI 분석, 권장 조치, 위협 정보를 확인할 수 있습니다.</p>
                </div>
              ) : (
                <>
                  {/* Header */}
                  <div className="detail-header">
                    <div>
                      <div className="detail-id">{inc.incident_id}</div>
                      <div className="detail-title-row">
                        <span className={`pill sev-${inc.severity}`}><AlertTriangle size={11}/> {inc.severity.toUpperCase()}</span>
                        <span className={`pill status-pill-${inc.status.replace(" ","_")}`}>{
                          {open:"미해결", acknowledged:"확인됨", in_progress:"처리 중", contained:"격리됨", resolved:"해결됨", closed:"종결", false_positive:"오탐"}[inc.status] ?? inc.status
                        }</span>
                      </div>
                      <div className="detail-meta-row">
                        <Shield size={12} />
                        <span>{tacticLabel(inc.mitre_tactic)}</span>
                        <code>{inc.mitre_technique}</code>
                        <span className="detail-meta-sep">·</span>
                        <span>{TACTIC_KO[inc.kill_chain_stage] ?? inc.kill_chain_stage}</span>
                        <span className="detail-meta-sep">·</span>
                        <span>우선순위: <strong>{PRIORITY_KO[inc.priority] ?? inc.priority}</strong></span>
                        <span className="detail-meta-sep">·</span>
                        <span>신뢰도: <strong>{CONF_KO[inc.confidence] ?? inc.confidence}</strong></span>
                      </div>
                    </div>
                    <div className="detail-actions">
                      <button
                        className="btn btn-sm"
                        style={{ borderColor: "#7c3aed", color: "#7c3aed" }}
                        onClick={() => setShowWorkflow(!showWorkflow)}
                        title="워크플로우"
                      >
                        {showWorkflow ? "← 상세 보기" : "워크플로우"}
                      </button>
                      <button className="btn btn-primary" disabled={busy === "analysis"} onClick={() => runAnalysis(true)}>
                        <BrainCircuit size={14} />
                        {busy === "analysis" ? "분석 중…" : "AI 재분석"}
                      </button>
                      <button className="btn" disabled={busy === "dispatch"} onClick={sendAlert}>
                        <Bell size={14} />
                        {busy === "dispatch" ? "발송 중…" : "알림 발송"}
                      </button>
                      <select className="status-select" value={inc.status} disabled={busy === "status"} onChange={e => changeStatus(e.target.value)}>
                        <option value="open">미해결 (Open)</option>
                        <option value="acknowledged">확인됨</option>
                        <option value="in_progress">처리 중</option>
                        <option value="contained">격리됨</option>
                        <option value="resolved">해결됨</option>
                        <option value="closed">종결</option>
                      </select>
                    </div>
                  </div>

                  {/* 워크플로우 뷰 */}
                  {showWorkflow ? (
                    <div style={{ padding: "16px 20px" }}>
                      <IncidentWorkflow
                        incidentId={inc.incident_id}
                        currentStatus={inc.status as any}
                        userRole={user.role}
                        onStatusChange={(newStatus) => {
                          changeStatus(newStatus);
                        }}
                      />
                    </div>
                  ) : (
                    <div className="cards-stack">

                      {/* ① 문제 */}
                      <div className="card">
                        <div className="card-head">
                          <div className="card-head-icon red"><AlertTriangle size={14} /></div>
                          <span className="card-head-title">문제 — 무슨 일이 발생했나요?</span>
                          <span className="card-head-sub">{new Date(inc.created_at).toLocaleString("ko-KR")}</span>
                        </div>
                        <div className="card-body">
                          <p className="summary-text">
                            {llm?.plain_summary ?? "AI 분석 결과가 아직 없습니다. 상단의 'AI 재분석' 버튼으로 분석을 시작하세요."}
                          </p>

                          {llm?.attack_intent && (
                            <div className="analysis-section">
                              <div className="analysis-label">공격 의도</div>
                              <p className="analysis-text">{llm.attack_intent}</p>
                            </div>
                          )}
                          {llm?.kill_chain_analysis && (
                            <div className="analysis-section">
                              <div className="analysis-label">Kill Chain 분석</div>
                              <p className="analysis-text">{llm.kill_chain_analysis}</p>
                            </div>
                          )}
                          {llm && (
                            <div className="llm-meta">
                              <span className="llm-model-badge">{MODEL_KO[llm.model] ?? llm.model}</span>
                              {llm.cached && <span className="cached-badge">캐시됨</span>}
                              <span style={{marginLeft:"auto"}}>{new Date(llm.generated_at).toLocaleString("ko-KR")}</span>
                            </div>
                          )}

                          <div className="meta-grid">
                            {[
                              { label: "Source IP", value: inc.source_ip, mono: true },
                              inc.username && { label: "계정", value: inc.username },
                              (cti?.country || cti?.city) && { label: "IP 위치", value: `${cti!.country ? flag(cti!.country) + " " : ""}${[cti!.country, cti!.city].filter(Boolean).join(" / ")}` },
                              cti?.asn_org && { label: "AS 기관", value: cti.asn_org },
                              cti?.abuse_score != null && { label: "Abuse Score", value: `${cti!.abuse_score} / 100`, color: abuseColor(cti!.abuse_score) },
                              { label: "MITRE", value: `${inc.mitre_tactic} · ${inc.mitre_technique}` },
                            ].filter(Boolean).map((item: any) => (
                              <div key={item.label} className="meta-cell">
                                <div className="meta-cell-label">{item.label}</div>
                                <div className="meta-cell-value" style={{
                                  fontFamily: item.mono ? "var(--mono)" : undefined,
                                  color: item.color ?? "var(--text)",
                                }}>{item.value ?? "-"}</div>
                              </div>
                            ))}
                          </div>

                          {cti?.user_agent && (
                            <div style={{marginTop:14}}>
                              <div style={{fontSize:11, fontWeight:700, textTransform:"uppercase", letterSpacing:".05em", color:"var(--text-3)", marginBottom:6}}>기기 정보 (User-Agent)</div>
                              <div className="ua-box">{cti.user_agent}</div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* ② 권장 조치 */}
                      <div className="card">
                        <div className="card-head">
                          <div className="card-head-icon green"><CheckCircle2 size={14} /></div>
                          <span className="card-head-title">권장 조치 — 어떻게 대응해야 하나요?</span>
                          <span className="card-head-sub">AI 분석 기반 권고</span>
                        </div>
                        <div className="card-body">
                          {llm?.recommended_actions?.length ? (
                            <div className="action-list">
                              {llm.recommended_actions.map((a, i) => (
                                <div key={a} className="action-item">
                                  <span className="action-num">{i + 1}</span>
                                  <span className="action-text">{a}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div style={{display:"flex", alignItems:"center", gap:10, color:"var(--text-3)", fontSize:13.5, padding:"8px 0"}}>
                              <BrainCircuit size={16} /> AI 분석 후 권장 조치가 표시됩니다.
                            </div>
                          )}
                          {llm?.confidence_note && (
                            <div className="confidence-note">{llm.confidence_note}</div>
                          )}
                        </div>
                      </div>

                      {/* ③ 대응 현황 */}
                      <div className="card">
                        <div className="card-head">
                          <div className="card-head-icon blue"><Shield size={14} /></div>
                          <span className="card-head-title">대응 현황 — 증거 타임라인</span>
                          <span className="card-head-sub">{selected?.evidence_timeline.length ?? 0}개 이벤트</span>
                        </div>
                        <div className="card-body">
                          <div className="response-grid">
                            <ol className="timeline">
                              {(selected?.evidence_timeline ?? []).map((item, idx) => (
                                <li key={`${item.timestamp}-${idx}`} className="timeline-item">
                                  <div className="tl-dot"><GitCommitVertical size={11} /></div>
                                  <div className="tl-body">
                                    <div className="tl-time">{new Date(item.timestamp).toLocaleString("ko-KR")}</div>
                                    <div className="tl-desc">{item.description}</div>
                                    {(item.rule_id || item.signal_id) && (
                                      <span className="tl-rule">{item.rule_id ?? item.signal_id}</span>
                                    )}
                                  </div>
                                </li>
                              ))}
                              {!selected?.evidence_timeline.length && (
                                <li style={{color:"var(--text-3)", fontSize:13.5}}>증거 없음</li>
                              )}
                            </ol>

                            {/* CTI */}
                            <div className="cti-panel">
                              <div className="cti-panel-title">위협 인텔리전스 (CTI)</div>
                              {cti ? (
                                <>
                                  {cti.abuse_score != null && (
                                    <div className="cti-row">
                                      <span className="cti-key">Abuse Score</span>
                                      <div className="abuse-wrap">
                                        <span className="cti-val" style={{color: abuseColor(cti.abuse_score)}}>{cti.abuse_score}/100</span>
                                        <div className="abuse-bar">
                                          <div className="abuse-fill" style={{width:`${cti.abuse_score}%`, background: abuseColor(cti.abuse_score)}} />
                                        </div>
                                      </div>
                                    </div>
                                  )}
                                  {cti.country && (
                                    <div className="cti-row">
                                      <span className="cti-key">국가</span>
                                      <span className="cti-val">{flag(cti.country)} {cti.country}{cti.city ? ` / ${cti.city}` : ""}</span>
                                    </div>
                                  )}
                                  {cti.asn_org && (
                                    <div className="cti-row">
                                      <span className="cti-key">AS 기관</span>
                                      <span className="cti-val">{cti.asn_org}</span>
                                    </div>
                                  )}
                                  {(cti.tags?.length ?? 0) > 0 && (
                                    <div className="cti-row" style={{alignItems:"flex-start"}}>
                                      <span className="cti-key">태그</span>
                                      <div className="cti-tags">{(cti.tags ?? []).map(t => <span key={t} className="cti-tag">{t}</span>)}</div>
                                    </div>
                                  )}
                                  {(cti.sources?.length ?? 0) > 0 && (
                                    <div className="cti-row" style={{alignItems:"flex-start"}}>
                                      <span className="cti-key">출처</span>
                                      <div className="cti-tags">{(cti.sources ?? []).map(s => <span key={s} className="cti-tag">{s}</span>)}</div>
                                    </div>
                                  )}
                                </>
                              ) : <p style={{color:"var(--text-3)", fontSize:13}}>CTI 데이터 없음</p>}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* ④ Detection Confidence 시각화 */}
                      {confidenceBreakdown && (
                        <div className="card">
                          <div className="card-head">
                            <div className="card-head-icon" style={{background:"var(--c-purple-100, #ede9fe)", color:"#7c3aed"}}><BrainCircuit size={14} /></div>
                            <span className="card-head-title">탐지 신뢰도 분석 — 왜 이 등급인가?</span>
                            <span className="card-head-sub">
                              최종 점수: <strong style={{color: confidenceBreakdown.final_score >= 0.7 ? "var(--c-red-500)" : confidenceBreakdown.final_score >= 0.4 ? "var(--c-orange-500)" : "var(--c-green-500)"}}>
                                {Math.round(confidenceBreakdown.final_score * 100)}%
                              </strong>
                            </span>
                          </div>
                          <div className="card-body">
                            {scenarioId && (
                              <div style={{marginBottom:12, padding:"8px 12px", background:"var(--c-purple-50,#faf5ff)", border:"1px solid #ddd6fe", borderRadius:6, fontSize:13}}>
                                <strong>공격 시나리오:</strong> <code style={{fontSize:12}}>{scenarioId}</code>
                              </div>
                            )}
                            <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:8}}>
                              {[
                                { key: "base_score", label: "기본 룰 점수" },
                                { key: "asset_multiplier", label: "자산 중요도 배수" },
                                { key: "cti_bonus", label: "CTI 위협 인텔리전스 보너스" },
                                { key: "exception_penalty", label: "예외 패널티" },
                                { key: "final_score", label: "최종 신뢰도 점수", highlight: true },
                              ].map(({ key, label, highlight }) => {
                                const val = confidenceBreakdown[key];
                                if (val === undefined) return null;
                                const pct = Math.round(val * 100);
                                const color = key === "exception_penalty"
                                  ? "var(--c-red-500)"
                                  : pct >= 70 ? "var(--c-red-500)"
                                  : pct >= 40 ? "var(--c-orange-500)"
                                  : "var(--c-green-500)";
                                return (
                                  <div key={key} style={{
                                    padding:"10px 12px",
                                    background: highlight ? "var(--surface-2,#f8fafc)" : "var(--surface,#fff)",
                                    border:`1px solid ${highlight ? "#cbd5e1" : "var(--border)"}`,
                                    borderRadius:6,
                                  }}>
                                    <div style={{fontSize:11, color:"var(--text-3)", marginBottom:4}}>{label}</div>
                                    <div style={{display:"flex", alignItems:"center", gap:8}}>
                                      <strong style={{color, fontSize:15}}>{pct}%</strong>
                                      <div style={{flex:1, height:4, background:"var(--border)", borderRadius:2}}>
                                        <div style={{width:`${Math.min(pct,100)}%`, height:"100%", background:color, borderRadius:2, transition:"width .3s"}} />
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* ⑤ 차단 승인 워크플로우 + TTL 카운트다운 */}
                      {pendingBlock && (
                        <div className="card">
                          <div className="card-head">
                            <div className="card-head-icon red"><Lock size={14} /></div>
                            <span className="card-head-title">차단 승인 대기 중</span>
                            {pendingBlock.expires_at && (
                              <TtlCountdown expiresAt={pendingBlock.expires_at} />
                            )}
                          </div>
                          <div className="card-body">
                            <div className="meta-grid" style={{marginBottom:12}}>
                              {pendingBlock.target_ip && (
                                <div className="meta-cell">
                                  <div className="meta-cell-label">차단 대상 IP</div>
                                  <div className="meta-cell-value" style={{fontFamily:"var(--mono)"}}>{pendingBlock.target_ip}</div>
                                </div>
                              )}
                              {pendingBlock.ttl_seconds && (
                                <div className="meta-cell">
                                  <div className="meta-cell-label">차단 TTL</div>
                                  <div className="meta-cell-value">{Math.floor(pendingBlock.ttl_seconds / 3600)}시간</div>
                                </div>
                              )}
                              {pendingBlock.requested_by && (
                                <div className="meta-cell">
                                  <div className="meta-cell-label">요청자</div>
                                  <div className="meta-cell-value">{pendingBlock.requested_by}</div>
                                </div>
                              )}
                            </div>
                            <div style={{display:"flex", gap:8}}>
                              <button
                                className="btn btn-primary"
                                disabled={blockBusy === "approve"}
                                onClick={async () => {
                                  if (!inc) return;
                                  setBlockBusy("approve");
                                  try {
                                    await approveBlock(inc.incident_id);
                                    setSelected(await fetchIncident(inc.incident_id));
                                    setNotice("차단이 승인되었습니다.");
                                  } catch (e) { setError(e instanceof Error ? e.message : "승인 실패"); }
                                  finally { setBlockBusy(undefined); }
                                }}
                              >
                                <Lock size={13} /> {blockBusy === "approve" ? "처리 중…" : "승인 (차단 실행)"}
                              </button>
                              <button
                                className="btn"
                                style={{borderColor:"var(--c-red-500)", color:"var(--c-red-500)"}}
                                disabled={blockBusy === "reject"}
                                onClick={async () => {
                                  if (!inc) return;
                                  setBlockBusy("reject");
                                  try {
                                    await rejectBlock(inc.incident_id);
                                    setSelected(await fetchIncident(inc.incident_id));
                                    setNotice("차단 요청이 거부되었습니다.");
                                  } catch (e) { setError(e instanceof Error ? e.message : "거부 실패"); }
                                  finally { setBlockBusy(undefined); }
                                }}
                              >
                                <Unlock size={13} /> {blockBusy === "reject" ? "처리 중…" : "거부"}
                              </button>
                              <button
                                className="btn btn-sm"
                                disabled={blockBusy === "extend"}
                                onClick={async () => {
                                  if (!inc) return;
                                  setBlockBusy("extend");
                                  try {
                                    await extendBlock(inc.incident_id, 3600);
                                    setSelected(await fetchIncident(inc.incident_id));
                                    setNotice("차단이 1시간 연장되었습니다.");
                                  } catch (e) { setError(e instanceof Error ? e.message : "연장 실패"); }
                                  finally { setBlockBusy(undefined); }
                                }}
                              >
                                <Clock size={13} /> {blockBusy === "extend" ? "처리 중…" : "+1시간 연장"}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}

                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* ══ ASSETS ══ */}
      {tab === "assets" && <AssetsPage />}

      {/* ══ SEARCH & ANALYTICS ══ */}
      {tab === "search" && <NaturalSearchPage />}

      {/* ══ HEALTH ══ */}
      {tab === "health" && <HealthDashboardPage />}

      {/* ══ RULE MANAGEMENT ══ */}
      {tab === "rule_mgmt" && <RuleManagementPage />}

      {/* ══ SUPPRESSION ══ */}
      {tab === "suppression" && <SuppressionPage />}

      {/* ══ MEMBERS ══ */}
      {tab === "members" && <MembersPage user={user} />}

      {/* ══ REPORTS ══ */}
      {tab === "reports" && <ReportsPage />}

      {/* ══ RULES (legacy read-only view) ══ */}
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
                          ? <span className="pill pill-sm sev-info">활성</span>
                          : <span className="pill pill-sm" style={{background:"var(--c-gray-100)", color:"var(--text-3)", border:"1px solid var(--border)"}}>비활성</span>
                        }
                      </td>
                    </tr>
                  ))}
                  {!rules.length && <tr><td colSpan={5} style={{textAlign:"center", color:"var(--text-3)", padding:"32px"}}>룰 없음</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══ AUDIT ══ */}
      {tab === "audit" && (
        <div className="page-wrap">
          <div className="page-header">
            <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between"}}>
              <div>
                <h2 className="page-title">감사 로그</h2>
                <p className="page-subtitle">모든 사용자 활동과 시스템 액션의 불변 기록</p>
              </div>
              <button className="btn btn-sm" onClick={() => { setAuditLoading(true); fetchAuditLogs().then(setAuditLogs).catch(()=>{}).finally(()=>setAuditLoading(false)); }} disabled={auditLoading}>
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
                  {!auditLogs.length && <tr><td colSpan={5} style={{textAlign:"center", color:"var(--text-3)", padding:"32px"}}>감사 로그 없음</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══ CAMPAIGNS ══ */}
      {tab === "campaigns" && <CampaignsPage />}

      {/* ══ THREAT HUNTING ══ */}
      {tab === "threat_hunting" && <ThreatHuntingPage />}
      {tab === "sigma_marketplace" && <SigmaMarketplacePage />}

      {/* ══ SETTINGS ══ */}
      {tab === "settings" && <SettingsPage />}
      </main>
    </div>
  );
}
