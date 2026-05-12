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
      city?: string;
      asn_org?: string;
      user_agent?: string;
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

// ── Settings ─────────────────────────────────────────────────────────────── //

export type TenantSettings = {
  tenant_id: string;
  response_mode: "manual" | "approval" | "auto";
  auto_block_min_severity: string;
  discord_webhook_url?: string;
  alert_email_to?: string;
  // AUTH 기존 임계값
  auth_brute_force_threshold: number;
  auth_brute_force_window_sec: number;
  auth_invalid_user_threshold: number;
  auth_fail_then_success_threshold: number;
  // WEB 기존 임계값
  web_admin_scan_threshold: number;
  web_404_threshold: number;
  // AUTH-006 비업무시간대 로그인
  off_hours_enabled: boolean;
  off_hours_start_kst: number;
  off_hours_end_kst: number;
  // AUTH-007 해외 IP 로그인
  foreign_login_enabled: boolean;
  allowed_countries: string;
  // WEB-005~007 on/off
  web_sql_injection_enabled: boolean;
  web_path_traversal_enabled: boolean;
  web_cve_probe_enabled: boolean;
};

export async function fetchSettings(): Promise<TenantSettings> {
  return apiFetch<TenantSettings>("/settings");
}

export async function updateSettings(patch: Partial<TenantSettings>): Promise<void> {
  await apiFetch("/settings", { method: "PUT", body: JSON.stringify(patch) });
}

// ── API Keys ─────────────────────────────────────────────────────────────── //

export type ApiKey = {
  key_id: string;
  name: string;
  source: string;
  enabled: boolean;
  created_at: string;
  last_used_at?: string;
};

export async function fetchApiKeys(): Promise<ApiKey[]> {
  const data = await apiFetch<{ items: ApiKey[] }>("/api-keys");
  return data.items ?? [];
}

export async function createApiKey(name: string, source: string): Promise<{ api_key: string; key_id: string }> {
  return apiFetch("/api-keys", { method: "POST", body: JSON.stringify({ name, source }) });
}

export async function revokeApiKey(keyId: string): Promise<void> {
  await apiFetch(`/api-keys/${keyId}`, { method: "DELETE" });
}

// ── 자동 대응 정책 (per-severity) — 설계서 5.2 ───────────────────────────────── //

export type AutoresponseActions = {
  watchlist: boolean;
  block_ip: boolean;
  discord_notify: boolean;
};

export type AutoresponsePolicy = {
  critical: AutoresponseActions;
  high: AutoresponseActions;
  medium: AutoresponseActions;
  info: AutoresponseActions;
};

export async function fetchAutoresponsePolicy(): Promise<AutoresponsePolicy> {
  const data = await apiFetch<{ policy: AutoresponsePolicy }>("/api/policy/autoresponse");
  return data.policy;
}

export async function patchAutoresponsePolicy(
  patch: Partial<AutoresponsePolicy>,
): Promise<{ policy: AutoresponsePolicy; policy_version: number }> {
  return apiFetch("/api/policy/autoresponse", {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

// ── IP 차단 롤백 ─────────────────────────────────────────────────────────── //

export async function unblockIp(ip: string): Promise<{ ok: boolean; ip: string }> {
  return apiFetch(`/policy/denylist/${encodeURIComponent(ip)}`, { method: "DELETE" });
}

// ── Pending Actions ───────────────────────────────────────────────────────── //

export type PendingAction = {
  action_id: string;
  incident_id?: string;
  action_type: string;
  target: string;
  status: string;
  created_at: string;
};

export async function fetchPendingActions(): Promise<PendingAction[]> {
  const data = await apiFetch<{ items: PendingAction[] }>("/ingest/actions/pending");
  return data.items ?? [];
}

export async function approveAction(actionId: string): Promise<void> {
  await apiFetch(`/ingest/actions/${actionId}/approve`, { method: "POST" });
}

export async function rejectAction(actionId: string): Promise<void> {
  await apiFetch(`/ingest/actions/${actionId}/reject`, { method: "POST" });
}

// ── Assets ───────────────────────────────────────────────────────────────── //

export type Asset = {
  asset_id: string;
  hostname: string;
  os?: string;
  status: string;
  last_heartbeat?: string;
};

export async function fetchAssets(): Promise<Asset[]> {
  const data = await apiFetch<{ items: Asset[] }>("/assets");
  return data.items ?? [];
}

// ── Register (stub — user creation handled by admin/seed) ─────────────────── //
export async function register(
  tenantId: string,
  email: string,
  password: string,
  role: string,
): Promise<{ user: AuthUser }> {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ tenant_id: tenantId, email, password, role }),
  });
  if (!response.ok) throw new Error("Registration failed");
  return response.json();
}
