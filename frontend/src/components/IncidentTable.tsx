import { AlertTriangle, ShieldCheck } from "lucide-react";
import type { IncidentListItem } from "../lib/api";

type Props = {
  incidents: IncidentListItem[];
  selectedId?: string;
  onSelect: (incident: IncidentListItem) => void;
};

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  info: 1,
};

export function IncidentTable({ incidents, selectedId, onSelect }: Props) {
  const sorted = [...incidents].sort(
    (a, b) =>
      (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0) ||
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );

  return (
    <div className="incident-table" role="table" aria-label="Incidents">
      <div className="incident-row incident-head" role="row">
        <span>Severity</span>
        <span>Incident</span>
        <span>Stage</span>
        <span>Source</span>
        <span>Status</span>
      </div>
      {sorted.map((incident) => (
        <button
          className={`incident-row ${incident.incident_id === selectedId ? "selected" : ""}`}
          key={incident.incident_id}
          onClick={() => onSelect(incident)}
          role="row"
          title={incident.llm_summary ?? incident.incident_id}
        >
          <span className={`pill severity-${incident.severity}`}>
            {incident.severity === "info" ? <ShieldCheck size={14} /> : <AlertTriangle size={14} />}
            {incident.severity}
          </span>
          <span className="mono">{incident.incident_id}</span>
          <span>{incident.kill_chain_stage}</span>
          <span>{incident.source_ip ?? "-"}</span>
          <span>{incident.status}</span>
        </button>
      ))}
      {!incidents.length && <div className="empty">No incidents yet</div>}
    </div>
  );
}
