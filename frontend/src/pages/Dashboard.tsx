import { useEffect, useState } from "react";
import { Bell, BrainCircuit, LogOut, RefreshCw, Siren } from "lucide-react";
import { EvidenceTimeline } from "../components/EvidenceTimeline";
import { IncidentTable } from "../components/IncidentTable";
import {
  analyzeIncident,
  dispatchIncident,
  fetchIncident,
  fetchIncidents,
  updateIncidentStatus,
  type AuthUser,
  type IncidentContract,
  type IncidentListItem,
} from "../lib/api";

type Props = {
  token: string;
  user: AuthUser;
  onLogout: () => void;
};

export function Dashboard({ token, user, onLogout }: Props) {
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();

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

  async function selectIncident(incident: IncidentListItem) {
    setError(undefined);
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
    try {
      await analyzeIncident(selected.incident.incident_id, token, refresh);
      setSelected(await fetchIncident(selected.incident.incident_id, token));
      await load();
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
    try {
      await dispatchIncident(selected.incident.incident_id, token);
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
    try {
      await updateIncidentStatus(selected.incident.incident_id, status, token);
      setSelected(await fetchIncident(selected.incident.incident_id, token));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setBusy(undefined);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const llm = selected?.llm_result;
  const incident = selected?.incident;
  const cti = incident?.cti_enrichment;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <span className="brand"><Siren size={20} /> InfraRed SOC</span>
          <h1>Incident Operations</h1>
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

      {error && <div className="alert">{error}</div>}

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
              onClick={() => runAnalysis(false)}
            >
              <BrainCircuit size={17} />
              {busy === "analysis" ? "Analyzing" : "Analyze"}
            </button>
            <button
              className="secondary-button"
              disabled={!incident || busy === "dispatch"}
              onClick={sendAlert}
            >
              <Bell size={17} />
              {busy === "dispatch" ? "Sending" : "Send Alert"}
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
    </main>
  );
}
