import { useEffect, useState } from "react";
import { Bell, BrainCircuit, ClipboardList, LogOut, RefreshCw, Shield, Siren } from "lucide-react";
import { EvidenceTimeline } from "../components/EvidenceTimeline";
import { IncidentTable } from "../components/IncidentTable";
import {
  analyzeIncident,
  dispatchIncident,
  fetchAuditLogs,
  fetchDetectionRules,
  fetchIncident,
  fetchIncidents,
  updateIncidentStatus,
  type AuditLog,
  type AuthUser,
  type DetectionRule,
  type IncidentContract,
  type IncidentListItem,
} from "../lib/api";

type Props = {
  token: string;
  user: AuthUser;
  onLogout: () => void;
};

type Tab = "incidents" | "rules" | "audit";

export function Dashboard({ token, user, onLogout }: Props) {
  const [tab, setTab] = useState<Tab>("incidents");

  // Incidents
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();

  // Detection Rules
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(undefined);
    try {
      const items = await fetchIncidents(token);
      setIncidents(items);
      if (items.length) {
        const current = selected?.incident.incident_id ?? items[0].incident_id;
        setSelected(await fetchIncident(current, token));
      } else {
        setSelected(undefined);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function loadRules() {
    setRulesLoading(true);
    try {
      setRules(await fetchDetectionRules(token));
    } catch {
      // silent
    } finally {
      setRulesLoading(false);
    }
  }

  async function loadAudit() {
    setAuditLoading(true);
    try {
      setAuditLogs(await fetchAuditLogs(token));
    } catch {
      // silent
    } finally {
      setAuditLoading(false);
    }
  }

  async function selectIncident(incident: IncidentListItem) {
    setError(undefined);
    setNotice(undefined);
    try {
      setSelected(await fetchIncident(incident.incident_id, token));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  async function runAnalysis(refresh = false) {
    if (!selected) return;
    setBusy("analysis");
    setError(undefined);
    setNotice(undefined);
    try {
      await analyzeIncident(selected.incident.incident_id, token, refresh);
      setSelected(await fetchIncident(selected.incident.incident_id, token));
      await load();
      setNotice(refresh ? "상세 AI 분석을 갱신했습니다." : "AI 분석을 완료했습니다.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(undefined);
    }
  }

  async function sendAlert() {
    if (!selected) return;
    setBusy("dispatch");
    setError(undefined);
    setNotice(undefined);
    try {
      const result = await dispatchIncident(selected.incident.incident_id, token);
      const channels = [
        result.discord_sent ? "Discord" : undefined,
        result.email_sent ? "Email" : undefined,
      ].filter(Boolean);
      setNotice(
        channels.length
          ? `${channels.join(", ")} 알림을 발송했습니다.`
          : "설정된 알림 채널이 없어 발송된 알림이 없습니다.",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(undefined);
    }
  }

  async function changeStatus(status: string) {
    if (!selected) return;
    setBusy("status");
    setError(undefined);
    setNotice(undefined);
    try {
      await updateIncidentStatus(selected.incident.incident_id, status, token);
      setSelected(await fetchIncident(selected.incident.incident_id, token));
      await load();
      setNotice(`Incident 상태를 ${status}(으)로 변경했습니다.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(undefined);
    }
  }

  // Initial load + 30s polling for incidents
  useEffect(() => {
    load();
    const timer = setInterval(load, 30_000);
    return () => clearInterval(timer);
  }, []);

  // Load rules / audit when tab switches
  useEffect(() => {
    if (tab === "rules" && rules.length === 0) loadRules();
    if (tab === "audit") loadAudit();
  }, [tab]);

  const llm = selected?.llm_result;
  const incident = selected?.incident;
  const cti = incident?.cti_enrichment;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <span className="brand"><Siren size={20} /> InfraRed SOC</span>
          <h1>Security Operations</h1>
        </div>
        <div className="top-actions">
          <span className="user-chip">{user.email ?? user.role}</span>
          <button className="icon-button" onClick={load} disabled={loading} title="Refresh">
            <RefreshCw size={18} className={loading ? "spin" : ""} />
          </button>
          <button className="icon-button muted" onClick={onLogout} title="Sign out">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <nav className="tab-nav">
        <button
          className={`tab-btn${tab === "incidents" ? " tab-active" : ""}`}
          onClick={() => setTab("incidents")}
        >
          <Siren size={16} /> Incidents
          {incidents.length > 0 && <span className="tab-badge">{incidents.length}</span>}
        </button>
        <button
          className={`tab-btn${tab === "rules" ? " tab-active" : ""}`}
          onClick={() => setTab("rules")}
        >
          <Shield size={16} /> Detection Rules
        </button>
        <button
          className={`tab-btn${tab === "audit" ? " tab-active" : ""}`}
          onClick={() => setTab("audit")}
        >
          <ClipboardList size={16} /> Audit Logs
        </button>
      </nav>

      {error && <div className="alert">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {/* ── Incidents tab ── */}
      {tab === "incidents" && (
        <section className="layout">
          <div className="left-pane">
            <div className="section-title">
              <h2>Incidents</h2>
              <span>{incidents.length}</span>
            </div>
            <IncidentTable
              incidents={incidents}
              selectedId={incident?.incident_id}
              onSelect={selectIncident}
            />
          </div>

          <div className="right-pane">
            <div className="summary-band">
              <div>
                <span className="eyebrow">LLM Summary</span>
                <h2>{incident?.incident_id ?? "No incident selected"}</h2>
              </div>
              {incident && <span className={`pill severity-${incident.severity}`}>{incident.severity}</span>}
            </div>

            <div className="command-row">
              <button
                className="secondary-button"
                disabled={!incident || busy === "analysis"}
                onClick={() => runAnalysis(true)}
              >
                <BrainCircuit size={17} />
                {busy === "analysis" ? "Analyzing…" : "Analyze"}
              </button>
              <button
                className="secondary-button"
                disabled={!incident || busy === "dispatch"}
                onClick={sendAlert}
              >
                <Bell size={17} />
                {busy === "dispatch" ? "Sending…" : "Send Alert"}
              </button>
              <select
                value={incident?.status ?? "open"}
                disabled={!incident || busy === "status"}
                onChange={(event) => changeStatus(event.target.value)}
              >
                <option value="open">open</option>
                <option value="acknowledged">acknowledged</option>
                <option value="resolved">resolved</option>
                <option value="false_positive">false positive</option>
              </select>
            </div>

            <p className="summary-text">
              {llm?.plain_summary ?? "LLM analysis will appear after the incident trigger is processed."}
            </p>

            {llm && (
              <div className="llm-meta">
                <span>모델: {llm.model}</span>
                {llm.cached && <span className="cached-badge">캐시됨</span>}
                <span>{new Date(llm.generated_at).toLocaleString("ko-KR")}</span>
              </div>
            )}

            {llm?.attack_intent && (
              <div className="llm-section">
                <span className="label">공격 의도</span>
                <p>{llm.attack_intent}</p>
              </div>
            )}

            {llm?.kill_chain_analysis && (
              <div className="llm-section">
                <span className="label">Kill Chain 분석</span>
                <p>{llm.kill_chain_analysis}</p>
              </div>
            )}

            <div className="detail-grid">
              <div>
                <span className="label">MITRE</span>
                <strong>{incident ? `${incident.mitre_tactic} / ${incident.mitre_technique}` : "-"}</strong>
              </div>
              <div>
                <span className="label">Priority</span>
                <strong>{incident?.priority ?? "-"}</strong>
              </div>
              <div>
                <span className="label">Confidence</span>
                <strong>{incident?.confidence ?? "-"}</strong>
              </div>
              <div>
                <span className="label">Source</span>
                <strong>{incident?.source_ip ?? "-"}</strong>
              </div>
            </div>

            <div className="columns">
              <section>
                <h2>Evidence Timeline</h2>
                <EvidenceTimeline contract={selected} />
              </section>
              <section>
                <h2>Recommended Actions</h2>
                <ul className="actions">
                  {(llm?.recommended_actions ?? []).map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                  {!llm?.recommended_actions?.length && <li>Waiting for LLM worker output</li>}
                </ul>
                <div className="cti-panel">
                  <span className="label">CTI</span>
                  <strong>{cti?.abuse_score ?? "-"} abuse score</strong>
                  <p>{[cti?.country, ...(cti?.tags ?? [])].filter(Boolean).join(" / ") || "-"}</p>
                </div>
              </section>
            </div>
          </div>
        </section>
      )}

      {/* ── Detection Rules tab ── */}
      {tab === "rules" && (
        <section className="tab-content">
          <div className="section-title">
            <h2>Detection Rules</h2>
            <span>{rules.length}</span>
          </div>
          {rulesLoading ? (
            <p className="muted-text">Loading rules…</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>MITRE Tactic</th>
                  <th>Technique</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td><code>{rule.rule_id}</code></td>
                    <td>{rule.name}</td>
                    <td>{rule.mitre_tactic ?? "-"}</td>
                    <td>{rule.mitre_technique ?? "-"}</td>
                    <td>
                      <span className={`pill ${rule.enabled ? "severity-info" : "pill-disabled"}`}>
                        {rule.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr><td colSpan={5} className="muted-text">No rules found</td></tr>
                )}
              </tbody>
            </table>
          )}
        </section>
      )}

      {/* ── Audit Logs tab ── */}
      {tab === "audit" && (
        <section className="tab-content">
          <div className="section-title">
            <h2>Audit Logs</h2>
            <button className="icon-button" onClick={loadAudit} disabled={auditLoading} title="Refresh">
              <RefreshCw size={16} className={auditLoading ? "spin" : ""} />
            </button>
          </div>
          {auditLoading ? (
            <p className="muted-text">Loading…</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{new Date(log.timestamp).toLocaleString("ko-KR")}</td>
                    <td>{log.actor}</td>
                    <td><code>{log.action}</code></td>
                    <td>{log.resource ?? "-"}</td>
                    <td>{log.ip ?? "-"}</td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr><td colSpan={5} className="muted-text">No audit logs yet</td></tr>
                )}
              </tbody>
            </table>
          )}
        </section>
      )}
    </main>
  );
}
