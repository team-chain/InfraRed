// 개발 서버(Vite proxy)에서는 상대 URL("")을 사용해 CORS를 우회합니다.
// 프로덕션 빌드에서는 VITE_API_BASE_URL 환경변수를 설정하세요.
const API_BASE_URL =
  import.meta.env.DEV
    ? ""
    : (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000");

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

export type PendingBlockAction = {
  action_id: string;
  incident_id: string;
  action_type: string;
  target_ip?: string;
  requested_by?: string;
  ttl_seconds?: number;
  expires_at?: string;
  approval_required: boolean;
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
    scenario_id?: string;
    confidence_breakdown?: {
      base_score: number;
      asset_multiplier: number;
      cti_bonus: number;
      exception_penalty: number;
      final_score: number;
      [key: string]: number;
    };
    pending_block?: PendingBlockAction | null;
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
  slack_webhook_url?: string;
  teams_webhook_url?: string;
  alert_email_to?: string;
  auth_brute_force_threshold: number;
  auth_brute_force_window_sec: number;
  auth_invalid_user_threshold: number;
  auth_fail_then_success_threshold: number;
  web_admin_scan_threshold: number;
  web_404_threshold: number;
  off_hours_enabled: boolean;
  off_hours_start_kst: number;
  off_hours_end_kst: number;
  foreign_login_enabled: boolean;
  allowed_countries: string;
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

// ── 자동 대응 정책 ────────────────────────────────────────────────────────── //

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

export async function approveBlock(incidentId: string, extendTtlSeconds?: number): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/v1/incidents/${incidentId}/approve-block`, {
    method: "POST",
    body: JSON.stringify({ extend_ttl_seconds: extendTtlSeconds ?? null }),
  });
}

export async function rejectBlock(incidentId: string, reason?: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/v1/incidents/${incidentId}/reject-block`, {
    method: "POST",
    body: JSON.stringify({ reason: reason ?? "" }),
  });
}

export async function extendBlock(incidentId: string, additionalTtlSeconds?: number): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/v1/incidents/${incidentId}/extend-block`, {
    method: "POST",
    body: JSON.stringify({ additional_ttl_seconds: additionalTtlSeconds ?? 3600 }),
  });
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

// ── Register ─────────────────────────────────────────────────────────────── //

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

// ── Phase 1-A: 인시던트 워크플로우 ───────────────────────────────────────────── //

export type IncidentComment = {
  id: string;
  author_id: string;
  author_email?: string;
  body: string;
  created_at: string;
};

export type IncidentLink = {
  id: string;
  source_incident_id: string;
  target_incident_id: string;
  link_type: string;
  target_severity?: string;
  created_at: string;
};

export type StatusHistoryItem = {
  id: string;
  from_status?: string;
  to_status: string;
  changed_by?: string;
  changed_by_email?: string;
  reason?: string;
  changed_at: string;
};

export async function transitionIncidentStatus(
  incidentId: string,
  status: string,
  options?: { reason?: string; disposition?: string; close_reason?: string },
): Promise<void> {
  await apiFetch(`/incidents/${incidentId}/workflow-status`, {
    method: "PATCH",
    body: JSON.stringify({ status, ...options }),
  });
}

export async function updateAssignee(incidentId: string, assigneeId: string | null): Promise<void> {
  await apiFetch(`/incidents/${incidentId}/assignee`, {
    method: "PATCH",
    body: JSON.stringify({ assignee_id: assigneeId }),
  });
}

export async function fetchComments(incidentId: string): Promise<IncidentComment[]> {
  const data = await apiFetch<{ items: IncidentComment[] }>(`/incidents/${incidentId}/comments`);
  return data.items ?? [];
}

export async function addComment(incidentId: string, body: string): Promise<IncidentComment> {
  return apiFetch(`/incidents/${incidentId}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

export async function fetchStatusHistory(incidentId: string): Promise<StatusHistoryItem[]> {
  const data = await apiFetch<{ items: StatusHistoryItem[] }>(`/incidents/${incidentId}/history`);
  return data.items ?? [];
}

export async function fetchLinks(incidentId: string): Promise<IncidentLink[]> {
  const data = await apiFetch<{ items: IncidentLink[] }>(`/incidents/${incidentId}/links`);
  return data.items ?? [];
}

export async function createLink(
  incidentId: string,
  targetIncidentId: string,
  linkType: string,
): Promise<void> {
  await apiFetch(`/incidents/${incidentId}/links`, {
    method: "POST",
    body: JSON.stringify({ target_incident_id: targetIncidentId, link_type: linkType }),
  });
}

// ── Phase 1-B: FP 통계 & 시계열 ──────────────────────────────────────────── //

export type FpStatItem = {
  rule_id: string;
  total: number;
  fp: number;
  fp_rate_pct: number;    // 0~100 백분율
  review_recommended: boolean;
  data_sufficient: boolean;
};

export async function fetchFpStats(days = 30): Promise<FpStatItem[]> {
  const data = await apiFetch<{ items: FpStatItem[] }>(`/incidents/stats/fp?days=${days}`);
  return data.items ?? [];
}

export type TimeseriesItem = {
  bucket: string;       // ISO timestamp
  count: number;
  critical?: number;
  high?: number;
  medium?: number;
  info?: number;
};

export async function fetchTimeseries(interval: "1h" | "1d" | "1w" = "1d"): Promise<TimeseriesItem[]> {
  const hours = interval === "1h" ? 48 : interval === "1d" ? 30 * 24 : 90 * 24;
  const data = await apiFetch<{ items: TimeseriesItem[] }>(
    `/incidents/stats/timeseries?hours=${hours}&interval=${interval}`
  );
  return data.items ?? [];
}

// ── Phase 1-C: 헬스체크 ───────────────────────────────────────────────────── //

export type HealthCheckDetail = {
  ok: boolean;
  [key: string]: any;
};

export type HealthDashboard = {
  overall: "ok" | "warn" | "error";
  checked_at: string;
  checks: Record<string, HealthCheckDetail>;
};

export async function fetchHealthDashboard(): Promise<HealthDashboard> {
  return apiFetch<HealthDashboard>("/health/dashboard");
}

export type AgentHealthItem = {
  agent_id: string;
  hostname?: string;
  os?: string;
  health_status: "online" | "offline" | "never_connected" | "deactivated";
  agent_version?: string;
  version_outdated?: boolean;
  last_heartbeat_at?: string;   // ISO timestamp
  seconds_offline?: number;
};

export async function fetchAgentHealth(): Promise<AgentHealthItem[]> {
  const data = await apiFetch<{ items: AgentHealthItem[] }>("/health/agents");
  return data.items ?? [];
}

// ── Phase 2-A: 룰 관리 라이프사이클 ──────────────────────────────────────── //

export type RuleItem = {
  rule_id: string;
  name: string;
  description?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  condition_expr?: string;
  severity?: string;
  status: "draft" | "active" | "disabled" | "archived";
  version?: number;
  created_at?: string;
  updated_at?: string;
};

export type DryRunResult = {
  matched_sample_count: number;     // 최근 1h 매칭 시그널 수
  disposition_count: number;        // 판정 완료 건수
  fp_rate?: number;                 // 0~100 백분율 (데이터 충분 시)
  review_recommended: boolean;
  data_sufficient_for_fp: boolean;
};

export async function fetchRules(status?: string): Promise<RuleItem[]> {
  const qs = status ? `?status=${status}` : "";
  const data = await apiFetch<{ items: RuleItem[] }>(`/rules${qs}`);
  return data.items ?? [];
}

export async function createRule(payload: {
  rule_id: string;
  display_name: string;
  source: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  severity?: string;
  change_reason?: string;
}): Promise<RuleItem> {
  return apiFetch("/rules", { method: "POST", body: JSON.stringify(payload) });
}

export async function dryRunRule(ruleId: string): Promise<DryRunResult> {
  return apiFetch(`/rules/${ruleId}/dry-run`, { method: "POST" });
}

export async function activateRule(ruleId: string, changeReason?: string): Promise<void> {
  await apiFetch(`/rules/${ruleId}/activate`, {
    method: "POST",
    body: JSON.stringify({ change_reason: changeReason || "Manual activation" }),
  });
}

export async function disableRule(ruleId: string): Promise<void> {
  await apiFetch(`/rules/${ruleId}/disable`, { method: "POST" });
}

export async function rollbackRule(
  ruleId: string,
  targetVersion: number,
  reason: string = "Manual rollback",
): Promise<void> {
  await apiFetch(`/rules/${ruleId}/rollback`, {
    method: "POST",
    body: JSON.stringify({ target_version: targetVersion, reason }),
  });
}

// ── Phase 2-C: Allowlist / Suppression / Maintenance Window ───────────────── //

export type AllowlistEntry = {
  id: string;
  type: string;   // ip | account | asset_id
  value: string;
  reason?: string;
  created_at: string;
};

export async function fetchAllowlist(): Promise<AllowlistEntry[]> {
  const data = await apiFetch<{ items: Array<AllowlistEntry & { entry_type?: string; description?: string }> }>("/allowlist");
  return (data.items ?? []).map((item) => ({
    ...item,
    type: item.type ?? item.entry_type ?? "ip",
    reason: item.reason ?? item.description,
  }));
}

export async function addAllowlistEntry(payload: {
  type: string;
  value: string;
  reason?: string;
}): Promise<AllowlistEntry> {
  return apiFetch("/allowlist", {
    method: "POST",
    body: JSON.stringify({
      entry_type: payload.type === "asset_id" ? "asset" : payload.type,
      value: payload.value,
      description: payload.reason || undefined,
    }),
  });
}

export async function deleteAllowlistEntry(id: string): Promise<void> {
  await apiFetch(`/allowlist/${id}`, { method: "DELETE" });
}

export type SuppressionEntry = {
  id: string;
  rule_id?: string;
  source_ip?: string;
  reason?: string;
  expires_at?: string;
  created_at: string;
};

export async function fetchSuppressions(): Promise<SuppressionEntry[]> {
  const data = await apiFetch<{ items: SuppressionEntry[] }>("/suppressions");
  return data.items ?? [];
}

export async function addSuppression(payload: {
  rule_id?: string;
  source_ip?: string;
  reason?: string;
  expires_at?: string;
}): Promise<SuppressionEntry> {
  return apiFetch("/suppressions", { method: "POST", body: JSON.stringify(payload) });
}

export async function deleteSuppression(id: string): Promise<void> {
  await apiFetch(`/suppressions/${id}`, { method: "DELETE" });
}

export type MaintenanceWindow = {
  id: string;
  name: string;
  start_at: string;
  end_at: string;
  reason?: string;
  created_at: string;
};

export async function fetchMaintenanceWindows(): Promise<MaintenanceWindow[]> {
  const data = await apiFetch<{ items: MaintenanceWindow[] }>("/maintenance-windows");
  return data.items ?? [];
}

export async function addMaintenanceWindow(payload: {
  name: string;
  start_at: string;
  end_at: string;
  reason?: string;
}): Promise<MaintenanceWindow> {
  return apiFetch("/maintenance-windows", { method: "POST", body: JSON.stringify(payload) });
}

export async function deleteMaintenanceWindow(id: string): Promise<void> {
  await apiFetch(`/maintenance-windows/${id}`, { method: "DELETE" });
}

// ── Phase 3-C: 멤버십 관리 (RBAC v2) ──────────────────────────────────────── //

export type Member = {
  user_id: string;
  email: string;
  role: string;
  created_at?: string;
  last_login_at?: string;
};

export async function fetchTenantMembers(tenantId: string): Promise<Member[]> {
  const data = await apiFetch<{ items: Member[] }>(`/users/${tenantId}/members`);
  return data.items ?? [];
}

export async function inviteMember(tenantId: string, email: string, role: string): Promise<void> {
  await apiFetch(`/users/${tenantId}/invite`, {
    method: "POST",
    body: JSON.stringify({ email, role }),
  });
}

export async function changeMemberRole(
  tenantId: string,
  userId: string,
  role: string,
): Promise<void> {
  await apiFetch(`/users/${tenantId}/members/${userId}/role`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

export async function removeMember(tenantId: string, userId: string): Promise<void> {
  await apiFetch(`/users/${tenantId}/members/${userId}`, { method: "DELETE" });
}

// ── Phase 2-D: 온보딩 ────────────────────────────────────────────────────── //

export type OnboardingStatus = {
  current_step: number;
  completed_steps: number[];
  total_steps: number;
  steps: Array<{ step: number; name: string; completed: boolean }>;
  agent_connected: boolean;
  completed: boolean;
};

export async function fetchOnboardingStatus(): Promise<OnboardingStatus> {
  return apiFetch("/onboarding/status");
}

export async function completeOnboardingStep(step: number): Promise<void> {
  await apiFetch(`/onboarding/complete/${step}`, { method: "POST" });
}

export async function generateInstallCommand(): Promise<{ command: string; token: string }> {
  return apiFetch("/onboarding/generate-install-command", { method: "POST" });
}

// ── Phase 4-D: 보고서 ────────────────────────────────────────────────────── //

export type ReportItem = {
  id: string;
  report_type: "weekly" | "monthly";
  period_start?: string;
  period_end?: string;
  s3_key?: string;
  download_url?: string;
  file_size_bytes?: number;
  email_sent_to?: string;
  generated_at: string;
};

export async function fetchReports(): Promise<ReportItem[]> {
  const data = await apiFetch<{ items: ReportItem[] }>("/reports");
  return data.items ?? [];
}

export async function generateReport(reportType: "weekly" | "monthly"): Promise<ReportItem> {
  return apiFetch(`/reports/generate?report_type=${reportType}`, { method: "POST" });
}

export async function deleteReport(reportId: string): Promise<void> {
  await apiFetch(`/reports/${reportId}`, { method: "DELETE" });
}

// ── Phase 5-A: 자연어 검색 ───────────────────────────────────────────────── //

export async function naturalSearch(
  query: string,
  limit = 20,
): Promise<IncidentListItem[]> {
  const data = await apiFetch<{ items: IncidentListItem[]; parsed_params?: Record<string, string>; count?: number }>(
    "/search/natural",
    { method: "POST", body: JSON.stringify({ query, limit }) }
  );
  return data.items ?? [];
}

// ── Phase 5-B: 알림 연동 테스트 ──────────────────────────────────────────── //

export async function testSlackNotification(message: string): Promise<{ sent: boolean }> {
  return apiFetch("/notify/slack/test", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export async function testTeamsNotification(message: string): Promise<{ sent: boolean }> {
  return apiFetch("/notify/teams/test", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

// ── Phase 5-C: 설정 백업/복원 ────────────────────────────────────────────── //

export async function exportConfig(): Promise<Record<string, unknown>> {
  return apiFetch("/config/backup");
}

export async function importConfig(config: Record<string, unknown>): Promise<{ imported: string[]; errors: string[] }> {
  return apiFetch("/config/restore", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

// ── Campaigns ────────────────────────────────────────────────────────────── //

export type Campaign = {
  id: string;
  tenant_id: string;
  campaign_type: string;
  source_asn?: string;
  source_ips?: string[];
  affected_asset_ids?: string[];
  incident_ids?: string[];
  first_seen_at: string;
  last_seen_at: string;
  total_signals?: number;
  status: string;  // active / contained / closed
  campaign_label?: string;
};

export async function fetchCampaigns(status?: string): Promise<Campaign[]> {
  const qs = status ? `?status=${status}` : "";
  const data = await apiFetch<{ items: Campaign[] }>(`/api/v1/campaigns${qs}`);
  return data.items ?? [];
}

export async function fetchCampaign(id: string): Promise<Campaign> {
  return apiFetch<Campaign>(`/api/v1/campaigns/${id}`);
}

export async function containCampaign(id: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/v1/campaigns/${id}/contain`, { method: "POST" });
}
