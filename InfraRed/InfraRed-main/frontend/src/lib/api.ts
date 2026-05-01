const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export type IncidentListItem = {
  incident_id: string;
  tenant_id: string;
  asset_id: string;
  severity: string;
  confidence: string;
  priority: string;
  kill_chain_stage: string;
  mitre_tactic: string;
  mitre_technique: string;
  source_ip?: string;
  username?: string;
  status: string;
  created_at: string;
  llm_summary?: string;
};

export type IncidentContract = {
  incident: IncidentListItem & {
    cti_enrichment?: Record<string, unknown>;
    signal_ids?: string[];
  };
  evidence_timeline: Array<{
    timestamp: string;
    description: string;
    signal_id?: string;
    rule_id?: string;
  }>;
  llm_result?: {
    plain_summary: string;
    attack_intent: string;
    kill_chain_analysis: string;
    recommended_actions: string[];
    confidence_note: string;
    model: string;
    generated_at: string;
  };
};

export async function fetchIncidents(): Promise<IncidentListItem[]> {
  const response = await fetch(`${API_BASE_URL}/incidents`);
  if (!response.ok) throw new Error(`Failed to load incidents: ${response.status}`);
  const data = await response.json();
  return data.items ?? [];
}

export async function fetchIncident(incidentId: string): Promise<IncidentContract> {
  const response = await fetch(`${API_BASE_URL}/incidents/${incidentId}`);
  if (!response.ok) throw new Error(`Failed to load incident: ${response.status}`);
  return response.json();
}
