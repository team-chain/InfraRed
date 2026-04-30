import { useEffect, useState } from "react";
import { RefreshCw, Siren } from "lucide-react";
import { EvidenceTimeline } from "../components/EvidenceTimeline";
import { IncidentTable } from "../components/IncidentTable";
import {
  fetchIncident,
  fetchIncidents,
  type IncidentContract,
  type IncidentListItem,
} from "../lib/api";

export function Dashboard() {
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selected, setSelected] = useState<IncidentContract | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function load() {
    setLoading(true);
    setError(undefined);
    try {
      const items = await fetchIncidents();
      setIncidents(items);
      if (items.length) {
        const current = selected?.incident.incident_id ?? items[0].incident_id;
        setSelected(await fetchIncident(current));
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
      setSelected(await fetchIncident(incident.incident_id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const llm = selected?.llm_result;
  const incident = selected?.incident;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <span className="brand"><Siren size={20} /> InfraRed SOC</span>
          <h1>Incident Operations</h1>
        </div>
        <button className="icon-button" onClick={load} disabled={loading} title="Refresh">
          <RefreshCw size={18} className={loading ? "spin" : ""} />
        </button>
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
            </section>
          </div>
        </div>
      </section>
    </main>
  );
}
