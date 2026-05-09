import { useEffect, useState } from "react";
import {
  Activity, AlertTriangle, Bell, BrainCircuit, CheckCircle2,
  ClipboardList, Cog, GitCommitVertical, LogOut, Monitor,
  RefreshCw, Shield, ShieldAlert, Siren, UserPlus,
} from "lucide-react";
import { SettingsPage } from "./SettingsPage";
import { AssetsPage } from "./AssetsPage";
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

function SevPill({ s }: { s: string }) {
  const cls = `pill pill-sm sev-${s}`;
  return <span className={cls}>{s}</span>;
}

export function Dashboard({ user, onLogout, onOpenOnboarding }: Props) {
  const [tab, setTab] = useState<Tab>("incidents");
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
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

  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, []);
  useEffect(() => {
    if (tab === "rules" && !rules.length) fetchDetectionRules().then(setRules).catch(() => {});
    if (tab === "audit") { setAuditLoading(true); fetchAuditLogs().then(setAuditLogs).catch(() => {}).finally(() => setAuditLoading(false)); }
  }, [tab]);

  const llm = selected?.llm_result;
  const inc = selected?.incident;
  const cti = inc?.cti_enrichment;
  const openN   = incidents.filter(i => i.status === "open").length;
  const critN   = incidents.filter(i => i.severity === "critical").length;
  const highN   = incidents.filter(i => i.severity === "high").length;
  const doneN   = incidents.filter(i => i.status === "resolved").length;

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
                        <div className="inc-card-rule">{item.mitre_tactic}</div>
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
                          {open:"미해결", acknowledged:"확인됨", resolved:"해결됨", false_positive:"오탐"}[inc.status] ?? inc.status
                        }</span>
                      </div>
                      <div className="detail-meta-row">
                        <Shield size={12} />
                        <span>{inc.mitre_tactic}</span>
                        <code>{inc.mitre_technique}</code>
                        <span className="detail-meta-sep">·</span>
                        <span>{inc.kill_chain_stage}</span>
                        <span className="detail-meta-sep">·</span>
                        <span>Priority: <strong>{inc.priority}</strong></span>
                        <span className="detail-meta-sep">·</span>
                        <span>Confidence: <strong>{inc.confidence}</strong></span>
                      </div>
                    </div>
                    <div className="detail-actions">
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
                        <option value="acknowledged">확인됨 (Acknowledged)</option>
                        <option value="resolved">해결됨 (Resolved)</option>
                        <option value="false_positive">오탐 (False Positive)</option>
                      </select>
                    </div>
                  </div>

                  <div className="cards-stack">

                    {/* ① 문제 */}
                    <div className="card">
                      <div className="card-head">
                        <div className="card-head-icon red">🔴</div>
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
                            <span className="llm-model-badge">{llm.model}</span>
                            {llm.cached && <span className="cached-badge">캐시됨</span>}
                            <span style={{marginLeft:"auto"}}>{new Date(llm.generated_at).toLocaleString("ko-KR")}</span>
                          </div>
                        )}

                        <div className="meta-grid">
                          {[
                            { label: "Source IP", value: inc.source_ip, mono: true },
                            inc.username && { label: "계정", value: inc.username },
                            (cti?.country || cti?.city) && { label: "IP 위치", value: `${cti.country ? flag(cti.country) + " " : ""}${[cti.country, cti.city].filter(Boolean).join(" / ")}` },
                            cti?.asn_org && { label: "AS 기관", value: cti.asn_org },
                            cti?.abuse_score != null && { label: "Abuse Score", value: `${cti.abuse_score} / 100`, color: abuseColor(cti.abuse_score) },
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
                        <div className="card-head-icon green">✅</div>
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
                          <div className="confidence-note">💡 {llm.confidence_note}</div>
                        )}
                      </div>
                    </div>

                    {/* ③ 대응 현황 */}
                    <div className="card">
                      <div className="card-head">
                        <div className="card-head-icon blue">🛡️</div>
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
                                {cti.tags?.length > 0 && (
                                  <div className="cti-row" style={{alignItems:"flex-start"}}>
                                    <span className="cti-key">태그</span>
                                    <div className="cti-tags">{cti.tags.map(t => <span key={t} className="cti-tag">{t}</span>)}</div>
                                  </div>
                                )}
                                {cti.sources?.length > 0 && (
                                  <div className="cti-row" style={{alignItems:"flex-start"}}>
                                    <span className="cti-key">출처</span>
                                    <div className="cti-tags">{cti.sources.map(s => <span key={s} className="cti-tag">{s}</span>)}</div>
                                  </div>
                                )}
                              </>
                            ) : <p style={{color:"var(--text-3)", fontSize:13}}>CTI 데이터 없음</p>}
                          </div>
                        </div>
                      </div>
                    </div>

                  </div>
                </>
              )}
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
                  {!rules.length && <tr><td colSpan={5} style={{textAlign:"center", color:"var(--text-3)", padding:"32px"}}>룰 없음</td></tr>}
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

      {/* ══════════════════════════════════════════════════════
          SETTINGS
      ══════════════════════════════════════════════════════ */}
      {tab === "settings" && <SettingsPage />}
    </div>
  );
}
