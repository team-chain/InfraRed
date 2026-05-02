const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export type AuthUser = {
  user_id?: string;
  email?: string;
  tenant_id: string;
  role: string;
};

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
  updated_at?: string;
  llm_summary?: string;
};

export type LlmResult = {
  incident_id: string;
  plain_summary: string;
  attack_intent: string;
  kill_chain_analysis: string;
  recommended_actions: string[];
  confidence_note: string;
  model: string;
  cached: boolean;
  generated_at: string;
};

export type IncidentContract = {
  incident: IncidentListItem & {
    cti_enrichment?: {
      abuse_score?: number;
      country?: string;
      tags?: string[];
      sources?: string[];
      note?: string;
    };
    signal_ids?: string[];
  };
  evidence_timeline: Array<{
    timestamp: string;
    description: string;
    signal_id?: string;
    rule_id?: string;
  }>;
  llm_result?: LlmResult;
};

export type DetectionRule = {
  rule_id: string;
  name: string;
  source: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  enabled: boolean;
};

export type DispatchResult = {
  dispatched: boolean;
  discord_sent: boolean;
  email_sent: boolean;
};

export type AuditLog = {
  id: number;
  tenant_id: string;
  actor: string;
  action: string;
  resource?: string;
  ip?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
};

export async function login(
  tenantId: string,
  email: string,
  password: string,
): Promise<{ user: AuthUser }> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ tenant_id: tenantId, email, password }),
  });
  if (!response.ok) throw new Error("Login failed");
  return response.json();
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE_URL}/auth/logout`, {
    method: "POST",
    credentials: "include",
  });
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(`${response.status} ${message}`);
  }
  return response.json();
}

export async function fetchIncidents(): Promise<IncidentListItem[]> {
  const data = await apiFetch<{ items: IncidentListItem[] }>("/incidents");
  return data.items ?? [];
}

export async function fetchIncident(incidentId: string): Promise<IncidentContract> {
  return apiFetch<IncidentContract>(`/incidents/${incidentId}`);
}

export async function analyzeIncident(incidentId: string, refresh = false): Promise<LlmResult> {
  return apiFetch<LlmResult>(
    `/incidents/${incidentId}/analyze?refresh=${String(refresh)}`,
    { method: "POST" },
  );
}

export async function dispatchIncident(incidentId: string): Promise<DispatchResult> {
  return apiFetch<DispatchResult>(`/incidents/${incidentId}/dispatch`, { method: "POST" });
}

export async function updateIncidentStatus(incidentId: string, status: string): Promise<void> {
  await apiFetch(`/incidents/${incidentId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

export async function fetchDetectionRules(): Promise<DetectionRule[]> {
  const data = await apiFetch<{ items: DetectionRule[] }>("/detection-rules");
  return data.items ?? [];
}

export async function fetchAuditLogs(): Promise<AuditLog[]> {
  const data = await apiFetch<{ items: AuditLog[] }>("/audit-logs");
  return data.items ?? [];
}
