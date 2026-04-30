import { GitCommitVertical } from "lucide-react";
import type { IncidentContract } from "../lib/api";

type Props = {
  contract?: IncidentContract;
};

export function EvidenceTimeline({ contract }: Props) {
  if (!contract) {
    return <div className="empty">Select an incident</div>;
  }

  return (
    <ol className="timeline">
      {contract.evidence_timeline.map((item) => (
        <li key={`${item.timestamp}-${item.signal_id ?? item.description}`}>
          <GitCommitVertical size={18} />
          <div>
            <time>{new Date(item.timestamp).toLocaleString()}</time>
            <p>{item.description}</p>
            <span className="mono">{item.rule_id ?? item.signal_id ?? ""}</span>
          </div>
        </li>
      ))}
      {!contract.evidence_timeline.length && <li>No evidence recorded</li>}
    </ol>
  );
}
