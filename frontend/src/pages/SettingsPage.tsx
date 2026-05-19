import React, { useEffect, useRef, useState } from "react";
import {
  Bot, Bell, BellOff, CheckCircle, Cpu, SlidersHorizontal, ShieldCheck, Key,
  Copy, Check, Trash2, Plus, Link2, Send, CreditCard, ShieldAlert, QrCode,
} from "lucide-react";
import {
  fetchSettings, updateSettings, fetchApiKeys, createApiKey, revokeApiKey,
  fetchAutoresponsePolicy, patchAutoresponsePolicy,
  type TenantSettings, type ApiKey, type AutoresponsePolicy, type AutoresponseActions,
} from "../lib/api";

/* ── Sidebar nav items ─────────────────────────────────── */
const NAV = [
  {
    group: "자동 대응",
    items: [{ id: "response", icon: Bot,               label: "AI 대응 모드",    desc: "탐지 후 자동화 수준" }],
  },
  {
    group: "알림",
    items: [
      { id: "notify",         icon: Bell,              label: "알림 채널",       desc: "Discord · Email" },
      { id: "integrations",   icon: Link2,             label: "Integration Hub", desc: "Slack · PagerDuty · Jira" },
    ],
  },
  {
    group: "탐지 규칙",
    items: [
      { id: "rules",          icon: SlidersHorizontal, label: "탐지 임계값",     desc: "Brute Force · Scan" },
      { id: "advanced",       icon: ShieldCheck,       label: "감지 범위 확장",  desc: "시간대 · 해외 IP · 웹 공격" },
    ],
  },
  {
    group: "보안",
    items: [{ id: "mfa",      icon: ShieldAlert,       label: "MFA / SSO",       desc: "2단계 인증 · SAML" }],
  },
  {
    group: "과금",
    items: [{ id: "billing",  icon: CreditCard,        label: "플랜 & 과금",     desc: "구독 · 에이전트 사용량" }],
  },
  {
    group: "개발자",
    items: [{ id: "keys",     icon: Key,               label: "API Keys",        desc: "SDK 연동용 키 관리" }],
  },
] as const;

type TabId = "response" | "notify" | "integrations" | "rules" | "advanced" | "mfa" | "billing" | "keys";

/* ── Per-severity 정책 체크박스 컴포넌트 (설계서 5.2) ──────────────────────── */
const SEV_LABELS: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: "var(--c-red-500)" },
  high:     { label: "High",     color: "var(--c-orange-500)" },
  medium:   { label: "Medium",   color: "var(--c-amber-500)" },
  info:     { label: "Info",     color: "var(--c-blue-500)" },
};
const ACTION_LABELS: Record<keyof AutoresponseActions, string> = {
  watchlist:      "Watchlist 등록",
  block_ip:       "IP 차단 (Denylist)",
  discord_notify: "Discord 알림",
};

function AutoresponsePolicyTable({
  policy,
  onChange,
}: {
  policy: AutoresponsePolicy;
  onChange: (sev: string, action: keyof AutoresponseActions, value: boolean) => void;
}) {
  const severities = ["critical", "high", "medium", "info"] as const;
  const actions = ["watchlist", "block_ip", "discord_notify"] as const;

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ background: "rgba(255,255,255,0.04)" }}>
            <th style={{ padding: "8px 12px", textAlign: "left", fontWeight: 600 }}>심각도</th>
            {actions.map((a) => (
              <th key={a} style={{ padding: "8px 12px", textAlign: "center", fontWeight: 600 }}>
                {ACTION_LABELS[a]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {severities.map((sev) => {
            const meta = SEV_LABELS[sev];
            const sevPolicy = policy[sev];
            return (
              <tr key={sev} style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                <td style={{ padding: "10px 12px" }}>
                  <span style={{ color: meta.color, fontWeight: 600 }}>
                    {meta.label}
                  </span>
                </td>
                {actions.map((action) => (
                  <td key={action} style={{ padding: "10px 12px", textAlign: "center" }}>
                    <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <Toggle
                        checked={sevPolicy[action]}
                        onChange={(v) => onChange(sev, action, v)}
                      />
                      <span style={{
                        fontSize: 11,
                        fontWeight: 600,
                        minWidth: 22,
                        color: sevPolicy[action] ? "var(--c-blue-600)" : "var(--text-3)",
                      }}>
                        {sevPolicy[action] ? "ON" : "OFF"}
                      </span>
                    </div>
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
      <p style={{ fontSize: 11, opacity: 0.5, marginTop: 10 }}>
        * IP 차단은 서비스 레벨 Redis Denylist 차단입니다 (설계서 Level 2). allowlist IP / 사설망은 차단되지 않습니다.
      </p>
    </div>
  );
}

/* ── Mode definitions ──────────────────────────────────── */
const MODES: { value: string; icon: React.ReactNode; label: string; desc: string }[] = [
  {
    value: "manual",
    icon: <BellOff size={18} />,
    label: "수동 대응",
    desc: "AI가 위협을 분석하고 Discord로 알림만 전송합니다. 모든 대응 조치는 담당자가 직접 수행합니다.",
  },
  {
    value: "approval",
    icon: <CheckCircle size={18} />,
    label: "승인 후 실행",
    desc: "AI가 대응 액션을 준비하고 대시보드에 표시합니다. 담당자가 승인하면 자동 실행됩니다.",
  },
  {
    value: "auto",
    icon: <Cpu size={18} />,
    label: "완전 자동화",
    desc: "AI가 탐지부터 IP 차단·계정 잠금까지 자동으로 실행하고 결과를 보고합니다.",
  },
];

const SEVERITIES = ["info", "medium", "high", "critical"] as const;

/* ── Toggle component ──────────────────────────────────── */
function Toggle({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="toggle">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="toggle-track" />
      <span className="toggle-thumb" />
    </label>
  );
}

/* ── Range field component ─────────────────────────────── */
function RangeField({
  label,
  value,
  min,
  max,
  unit,
  onChange,
  onCommit,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  unit?: string;
  onChange: (v: number) => void;
  onCommit: (v: number) => void;
}) {
  return (
    <div className="range-field">
      <div className="range-header">
        <span className="range-label">{label}</span>
        <span className="range-value">
          {value}
          {unit && <span style={{ fontSize: 11, fontWeight: 400, color: "var(--text-3)", marginLeft: 2 }}>{unit}</span>}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(+e.target.value)}
        onMouseUp={(e) => onCommit(+(e.target as HTMLInputElement).value)}
        onTouchEnd={(e) => onCommit(+(e.target as HTMLInputElement).value)}
      />
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 2 }}>
        <span style={{ fontSize: 11, color: "var(--text-3)" }}>{min}</span>
        <span style={{ fontSize: 11, color: "var(--text-3)" }}>{max}</span>
      </div>
    </div>
  );
}

/* ── Main component ────────────────────────────────────── */
const DEFAULT_AUTORESPONSE: AutoresponsePolicy = {
  critical: { watchlist: true,  block_ip: true,  discord_notify: true },
  high:     { watchlist: true,  block_ip: false, discord_notify: true },
  medium:   { watchlist: false, block_ip: false, discord_notify: true },
  info:     { watchlist: false, block_ip: false, discord_notify: false },
};

export function SettingsPage() {
  const [settings, setSettings]   = useState<TenantSettings | null>(null);
  const [apiKeys, setApiKeys]     = useState<ApiKey[]>([]);
  const [tab, setTab]             = useState<TabId>("response");
  const [saving, setSaving]       = useState(false);
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRaw, setNewKeyRaw]  = useState<string>();
  const [copied, setCopied]        = useState(false);
  const [arPolicy, setArPolicy]    = useState<AutoresponsePolicy>(DEFAULT_AUTORESPONSE);
  const toastTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    fetchSettings().then(setSettings).catch(console.error);
    fetchApiKeys().then(setApiKeys).catch(console.error);
    fetchAutoresponsePolicy().then(setArPolicy).catch(console.error);
  }, []);

  function showToast(msg: string, ok = true) {
    clearTimeout(toastTimer.current);
    setToast({ msg, ok });
    toastTimer.current = setTimeout(() => setToast(null), 2500);
  }

  async function save(patch: Partial<TenantSettings>) {
    if (!settings) return;
    setSaving(true);
    try {
      await updateSettings(patch);
      setSettings({ ...settings, ...patch });
      showToast("변경 사항이 저장됐습니다");
    } catch {
      showToast("저장에 실패했습니다", false);
    } finally {
      setSaving(false);
    }
  }

  async function handleCreateKey() {
    if (!newKeyName.trim()) return;
    const res = await createApiKey(newKeyName, "api");
    setNewKeyRaw(res.api_key);
    setNewKeyName("");
    setApiKeys(await fetchApiKeys());
  }

  async function handleRevokeKey(keyId: string) {
    await revokeApiKey(keyId);
    setApiKeys(apiKeys.filter((k) => k.key_id !== keyId));
    showToast("API 키가 폐기됐습니다");
  }

  async function handleCopyKey() {
    if (!newKeyRaw) return;
    await navigator.clipboard.writeText(newKeyRaw);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (!settings) {
    return (
      <div style={{ padding: "60px 40px", color: "var(--text-3)", fontSize: 14 }}>
        설정을 불러오는 중...
      </div>
    );
  }

  return (
    <div className="settings-layout">
      {/* ── Sidebar ──────────────────────────────────────── */}
      <nav className="settings-sidebar">
        {NAV.map(({ group, items }) => (
          <div className="settings-sidebar-group" key={group}>
            <div className="settings-sidebar-label">{group}</div>
            {items.map(({ id, icon: Icon, label }) => (
              <button
                key={id}
                className={`settings-nav-item ${tab === id ? "active" : ""}`}
                onClick={() => setTab(id)}
              >
                <Icon size={16} />
                {label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* ── Content ──────────────────────────────────────── */}
      <div className="settings-content">

        {/* ── AI 대응 모드 ────────────────────────────────── */}
        {tab === "response" && (
          <>
            <div className="settings-section-title">AI 대응 모드</div>
            <div className="settings-section-desc">
              위협이 탐지됐을 때 AI가 어디까지 자동으로 처리할지 결정합니다.
              운영 환경에 맞게 신중하게 설정하세요.
            </div>

            <div className="mode-cards" style={{ marginBottom: 24 }}>
              {MODES.map((m) => (
                <button
                  key={m.value}
                  className={`mode-card ${settings.response_mode === m.value ? "mode-active" : ""}`}
                  onClick={() => save({ response_mode: m.value as TenantSettings["response_mode"] })}
                >
                  <div className="mode-radio">
                    <div className="mode-radio-dot" />
                  </div>
                  <div className="mode-icon" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>{m.icon}</div>
                  <div>
                    <div className="mode-label">{m.label}</div>
                    <div className="mode-desc">{m.desc}</div>
                  </div>
                </button>
              ))}
            </div>

            {(settings.response_mode === "approval" || settings.response_mode === "auto") && (
              <div className="setting-group">
                <div className="setting-row">
                  <div className="setting-row-info">
                    <div className="setting-row-label">자동 대응 최소 심각도</div>
                    <div className="setting-row-desc">
                      선택된 심각도 이상의 인시던트에 대해서만 자동 대응 액션이 활성화됩니다.
                    </div>
                    <div className="sev-selector" style={{ marginTop: 14 }}>
                      {SEVERITIES.map((sev) => {
                        const isActive = settings.auto_block_min_severity === sev;
                        return (
                          <button
                            key={sev}
                            className={`sev-btn sev-btn-${sev} ${isActive ? `sev-btn-active-${sev}` : ""}`}
                            onClick={() => save({ auto_block_min_severity: sev })}
                          >
                            {sev}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>

            )}

            {/* ── 심각도별 자동 대응 정책 (설계서 5.2) ──────── */}
            <div className="setting-group" style={{ marginTop: 8 }}>
              <div className="setting-row-label" style={{ marginBottom: 4 }}>
                심각도별 자동 대응 정책
              </div>
              <div className="setting-row-desc" style={{ marginBottom: 12 }}>
                각 심각도에서 실행할 대응 액션을 개별적으로 설정합니다. 변경 즉시 Policy Engine에 반영됩니다.
              </div>
              <AutoresponsePolicyTable
                policy={arPolicy}
                onChange={async (sev, action, value) => {
                  const updated: AutoresponsePolicy = {
                    ...arPolicy,
                    [sev]: { ...arPolicy[sev as keyof AutoresponsePolicy], [action]: value },
                  };
                  setArPolicy(updated);
                  try {
                    await patchAutoresponsePolicy({ [sev]: updated[sev as keyof AutoresponsePolicy] });
                    showToast(`${sev} 정책이 저장됐습니다`);
                  } catch {
                    showToast("정책 저장 실패", false);
                    setArPolicy(arPolicy); // 롤백
                  }
                }}
              />
            </div>
          </>
        )}

        {/* ── 알림 채널 ────────────────────────────────────── */}
        {tab === "notify" && (
          <>
            <div className="settings-section-title">알림 채널</div>
            <div className="settings-section-desc">
              보안 인시던트 탐지 시 알림을 받을 채널을 설정합니다.
            </div>

            <div className="setting-group">
              <NotifyField
                label="Discord Webhook URL"
                desc="인시던트 탐지 즉시 채널로 알림 embed가 전송됩니다."
                placeholder="https://discord.com/api/webhooks/…"
                defaultValue={settings.discord_webhook_url ?? ""}
                onSave={(v) => save({ discord_webhook_url: v })}
              />
              <NotifyField
                label="이메일 수신 주소"
                desc="Critical 심각도 인시던트 발생 시 이메일로 별도 알림을 전송합니다."
                placeholder="admin@company.com"
                defaultValue={settings.alert_email_to ?? ""}
                onSave={(v) => save({ alert_email_to: v })}
              />
            </div>
          </>
        )}

        {/* ── Integration Hub (설계서 v4 §10) ──────────────────── */}
        {tab === "integrations" && (
          <IntegrationHubSection settings={settings} save={save} />
        )}

        {/* ── 탐지 임계값 ─────────────────────────────────── */}
        {tab === "rules" && (
          <>
            <div className="settings-section-title">탐지 임계값</div>
            <div className="settings-section-desc">
              각 탐지 규칙이 Signal을 생성하는 기준값입니다. 낮을수록 민감하게 반응합니다.
            </div>

            <div className="setting-group">
              {(
                [
                  { label: "SSH Brute Force — 실패 횟수",       field: "auth_brute_force_threshold",       min: 1,  max: 30,   unit: "회" },
                  { label: "SSH Brute Force — 시간 윈도우",      field: "auth_brute_force_window_sec",      min: 60, max: 3600, unit: "초" },
                  { label: "Invalid User — 임계값",              field: "auth_invalid_user_threshold",      min: 1,  max: 50,   unit: "회" },
                  { label: "Failed → Success — 실패 횟수",      field: "auth_fail_then_success_threshold", min: 1,  max: 20,   unit: "회" },
                  { label: "Admin Path Scan — 요청 수",          field: "web_admin_scan_threshold",         min: 5,  max: 200,  unit: "req" },
                  { label: "404 Burst — 임계값",                 field: "web_404_threshold",                min: 10, max: 500,  unit: "req" },
                ] as { label: string; field: keyof TenantSettings; min: number; max: number; unit: string }[]
              ).map(({ label, field, min, max, unit }) => (
                <div key={field as string} className="setting-row">
                  <RangeField
                    label={label}
                    value={(settings[field] as number) ?? min}
                    min={min}
                    max={max}
                    unit={unit}
                    onChange={(v) => setSettings({ ...settings, [field]: v })}
                    onCommit={(v) => save({ [field]: v } as Partial<TenantSettings>)}
                  />
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── 감지 범위 확장 ───────────────────────────────── */}
        {tab === "advanced" && (
          <>
            <div className="settings-section-title">감지 범위 확장</div>
            <div className="settings-section-desc">
              기본 임계값 탐지 외 추가 규칙을 활성화합니다. 각 규칙은 독립적으로 제어할 수 있습니다.
            </div>

            {/* AUTH-006 */}
            <div className="setting-group">
              <div className="setting-row">
                <div className="setting-row-info">
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--c-gray-100)", border: "1px solid var(--border)", borderRadius: 4, padding: "1px 6px", color: "var(--text-3)" }}>AUTH-006</span>
                    <div className="setting-row-label" style={{ margin: 0 }}>비업무 시간대 로그인</div>
                  </div>
                  <div className="setting-row-desc">KST 기준 설정 시간 범위의 SSH 로그인 성공 시 Signal을 생성합니다.</div>
                </div>
                <div className="setting-row-control">
                  <Toggle
                    checked={settings.off_hours_enabled ?? true}
                    onChange={(v) => save({ off_hours_enabled: v })}
                  />
                </div>
              </div>

              {(settings.off_hours_enabled ?? true) && (
                <div className="setting-row" style={{ flexDirection: "column", gap: 16 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, width: "100%" }}>
                    <RangeField
                      label="시작 시각 (KST)"
                      value={(settings.off_hours_start_kst as number) ?? 22}
                      min={0} max={23} unit="시"
                      onChange={(v) => setSettings({ ...settings, off_hours_start_kst: v })}
                      onCommit={(v) => save({ off_hours_start_kst: v })}
                    />
                    <RangeField
                      label="종료 시각 (KST)"
                      value={(settings.off_hours_end_kst as number) ?? 7}
                      min={0} max={23} unit="시"
                      onChange={(v) => setSettings({ ...settings, off_hours_end_kst: v })}
                      onCommit={(v) => save({ off_hours_end_kst: v })}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* AUTH-007 */}
            <div className="setting-group">
              <div className="setting-row">
                <div className="setting-row-info">
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--c-gray-100)", border: "1px solid var(--border)", borderRadius: 4, padding: "1px 6px", color: "var(--text-3)" }}>AUTH-007</span>
                    <div className="setting-row-label" style={{ margin: 0 }}>해외 IP 로그인</div>
                  </div>
                  <div className="setting-row-desc">허용 국가 외 IP에서 SSH 로그인 성공 시 Signal을 생성합니다. (GeoIP 필요)</div>
                </div>
                <div className="setting-row-control">
                  <Toggle
                    checked={settings.foreign_login_enabled ?? false}
                    onChange={(v) => save({ foreign_login_enabled: v })}
                  />
                </div>
              </div>

              {settings.foreign_login_enabled && (
                <div className="setting-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 8 }}>
                  <div className="setting-row-label" style={{ fontSize: 13 }}>허용 국가 (ISO-2 코드, 콤마 구분)</div>
                  <CountryInput
                    defaultValue={settings.allowed_countries ?? "KR"}
                    onSave={(v) => save({ allowed_countries: v })}
                  />
                </div>
              )}
            </div>

            {/* WEB 공격 패턴 */}
            <div className="setting-group">
              <div style={{ padding: "14px 20px", background: "var(--c-gray-25)", borderBottom: "1px solid var(--c-gray-100)" }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-2)" }}>WEB 공격 패턴 감지</div>
              </div>
              {(
                [
                  { rule: "WEB-005", label: "SQL Injection",          desc: "URL에 union select, ' or 1=1 등 SQL 삽입 패턴 감지",           field: "web_sql_injection_enabled" },
                  { rule: "WEB-006", label: "Path Traversal / LFI",   desc: "../ 또는 /etc/passwd 등 디렉터리 탈출 패턴 감지",              field: "web_path_traversal_enabled" },
                  { rule: "WEB-007", label: "CVE 탐침 경로 접근",     desc: "/.env, /.git, /actuator, /wp-config.php 등 민감 경로 접근 감지", field: "web_cve_probe_enabled" },
                ] as { rule: string; label: string; desc: string; field: keyof TenantSettings }[]
              ).map(({ rule, label, desc, field }) => (
                <div key={field as string} className="setting-row">
                  <div className="setting-row-info">
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--c-gray-100)", border: "1px solid var(--border)", borderRadius: 4, padding: "1px 6px", color: "var(--text-3)" }}>{rule}</span>
                      <div className="setting-row-label" style={{ margin: 0 }}>{label}</div>
                    </div>
                    <div className="setting-row-desc">{desc}</div>
                  </div>
                  <div className="setting-row-control">
                    <Toggle
                      checked={(settings[field] as boolean) ?? true}
                      onChange={(v) => save({ [field]: v } as Partial<TenantSettings>)}
                    />
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── MFA / SSO ────────────────────────────────────── */}
        {tab === "mfa" && <MfaSsoSection />}

        {/* ── Billing ──────────────────────────────────────── */}
        {tab === "billing" && <BillingSection />}

        {/* ── API Keys ─────────────────────────────────────── */}
        {tab === "keys" && (
          <>
            <div className="settings-section-title">API Keys</div>
            <div className="settings-section-desc">
              서버 에이전트 및 외부 SDK 연동에 사용하는 API 키를 관리합니다.
              키는 발급 직후에만 전체 값이 표시됩니다.
            </div>

            {/* Create new key */}
            <div className="setting-group" style={{ marginBottom: 24 }}>
              <div className="setting-row" style={{ gap: 12 }}>
                <input
                  className="form-input"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleCreateKey()}
                  placeholder="키 이름 입력 (예: 웹사이트 SDK, 모니터링 Agent)"
                />
                <button
                  className="btn btn-primary"
                  onClick={handleCreateKey}
                  disabled={!newKeyName.trim()}
                  style={{ flexShrink: 0 }}
                >
                  <Plus size={14} />
                  발급
                </button>
              </div>
            </div>

            {/* New key reveal */}
            {newKeyRaw && (
              <div style={{ marginBottom: 20, background: "var(--c-amber-50)", border: "1px solid var(--c-amber-100)", borderRadius: "var(--r-lg)", padding: "16px 18px" }}>
                <div className="key-value-label">지금만 표시됩니다 — 안전한 곳에 복사해 두세요</div>
                <div className="key-value">{newKeyRaw}</div>
                <button
                  className="btn btn-sm"
                  onClick={handleCopyKey}
                  style={{ marginTop: 10 }}
                >
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  {copied ? "복사됨" : "클립보드에 복사"}
                </button>
              </div>
            )}

            {/* Key list */}
            <div className="key-list">
              {apiKeys.length === 0 && (
                <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-3)", fontSize: 14 }}>
                  발급된 API 키가 없습니다
                </div>
              )}
              {apiKeys.map((key) => (
                <div key={key.key_id} className="key-card">
                  <div className="key-indicator" />
                  <div style={{ flex: 1 }}>
                    <div className="key-name">{key.name}</div>
                    <div className="key-meta">
                      {key.source} · 생성 {new Date(key.created_at).toLocaleDateString("ko-KR")}
                      {key.last_used_at && ` · 마지막 사용 ${new Date(key.last_used_at).toLocaleDateString("ko-KR")}`}
                    </div>
                  </div>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() => handleRevokeKey(key.key_id)}
                    title="키 폐기"
                  >
                    <Trash2 size={13} />
                    폐기
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* ── Toast ────────────────────────────────────────── */}
      {toast && (
        <div style={{
          position: "fixed", bottom: 24, right: 24, zIndex: 999,
          padding: "10px 18px",
          background: toast.ok ? "var(--c-green-600)" : "var(--c-red-600)",
          color: "#fff",
          borderRadius: "var(--r-lg)",
          fontSize: 13,
          fontWeight: 500,
          boxShadow: "var(--shadow-lg)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          pointerEvents: "none",
        }}>
          {toast.ok ? <Check size={14} /> : null}
          {toast.msg}
          {saving && <span style={{ opacity: .6 }}>…</span>}
        </div>
      )}
    </div>
  );
}

/* ── Notify text field (controlled by DOM ref) ─────────── */
function NotifyField({
  label,
  desc,
  placeholder,
  defaultValue,
  onSave,
}: {
  label: string;
  desc: string;
  placeholder: string;
  defaultValue: string;
  onSave: (v: string) => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div className="setting-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 12 }}>
      <div>
        <div className="setting-row-label">{label}</div>
        <div className="setting-row-desc">{desc}</div>
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          ref={ref}
          className="form-input"
          defaultValue={defaultValue}
          placeholder={placeholder}
        />
        <button
          className="btn"
          style={{ flexShrink: 0 }}
          onClick={() => ref.current && onSave(ref.current.value)}
        >
          저장
        </button>
      </div>
    </div>
  );
}

/* ── Country code input ─────────────────────────────────── */
function CountryInput({
  defaultValue,
  onSave,
}: {
  defaultValue: string;
  onSave: (v: string) => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div style={{ display: "flex", gap: 8 }}>
      <input
        ref={ref}
        className="form-input"
        defaultValue={defaultValue}
        placeholder="예: KR,US,JP"
      />
      <button
        className="btn"
        style={{ flexShrink: 0 }}
        onClick={() => ref.current && onSave(ref.current.value)}
      >
        저장
      </button>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────
   Integration Hub Section (설계서 v4 §10 — Slack / PagerDuty / Jira)
   ───────────────────────────────────────────────────────────────────────── */

interface IntegrationCardProps {
  name: string;
  description: string;
  logo: React.ReactNode;
  fields: Array<{
    key: string;
    label: string;
    placeholder: string;
    secret?: boolean;
    helpText?: string;
  }>;
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
  onSave: () => void;
  onTest?: () => void;
  saving: boolean;
  testStatus?: "idle" | "testing" | "ok" | "fail";
}

function IntegrationCard({
  name, description, logo, fields, values, onChange, onSave, onTest,
  saving, testStatus = "idle",
}: IntegrationCardProps) {
  return (
    <div className="setting-group" style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: "var(--c-gray-100)", border: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          {logo}
        </div>
        <div>
          <div style={{ fontWeight: 600, fontSize: 14, color: "var(--text-1)" }}>{name}</div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 2 }}>{description}</div>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {fields.map((field) => (
          <div key={field.key} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-2)" }}>
              {field.label}
            </label>
            <input
              type={field.secret ? "password" : "text"}
              className="input"
              placeholder={field.placeholder}
              value={values[field.key] ?? ""}
              onChange={(e) => onChange(field.key, e.target.value)}
              style={{ fontFamily: field.secret ? "monospace" : undefined }}
            />
            {field.helpText && (
              <span style={{ fontSize: 11, color: "var(--text-4)" }}>{field.helpText}</span>
            )}
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
        <button
          className="btn btn-primary"
          onClick={onSave}
          disabled={saving}
          style={{ minWidth: 72 }}
        >
          {saving ? "저장 중…" : "저장"}
        </button>
        {onTest && (
          <button
            className="btn"
            onClick={onTest}
            disabled={testStatus === "testing"}
            style={{ display: "flex", alignItems: "center", gap: 6 }}
          >
            <Send size={13} />
            {testStatus === "testing" ? "전송 중…"
              : testStatus === "ok" ? "✅ 성공"
              : testStatus === "fail" ? "❌ 실패"
              : "테스트 전송"}
          </button>
        )}
      </div>
    </div>
  );
}

function IntegrationHubSection({
  settings,
  save,
}: {
  settings: TenantSettings;
  save: (patch: Partial<TenantSettings>) => void;
}) {
  // Slack
  const [slackValues, setSlackValues] = useState<Record<string, string>>({
    slack_webhook_url: (settings as any).slack_webhook_url ?? "",
    slack_channel: (settings as any).slack_channel ?? "",
  });
  const [slackSaving, setSlackSaving] = useState(false);
  const [slackTestStatus, setSlackTestStatus] = useState<"idle"|"testing"|"ok"|"fail">("idle");

  // PagerDuty
  const [pdValues, setPdValues] = useState<Record<string, string>>({
    pagerduty_routing_key: (settings as any).pagerduty_routing_key ?? "",
    pagerduty_severity_threshold: (settings as any).pagerduty_severity_threshold ?? "critical",
  });
  const [pdSaving, setPdSaving] = useState(false);
  const [pdTestStatus, setPdTestStatus] = useState<"idle"|"testing"|"ok"|"fail">("idle");

  // Jira
  const [jiraValues, setJiraValues] = useState<Record<string, string>>({
    jira_server_url: (settings as any).jira_server_url ?? "",
    jira_email: (settings as any).jira_email ?? "",
    jira_api_token: (settings as any).jira_api_token ?? "",
    jira_project_key: (settings as any).jira_project_key ?? "",
  });
  const [jiraSaving, setJiraSaving] = useState(false);

  async function testSlack() {
    setSlackTestStatus("testing");
    try {
      const res = await fetch("/api/v1/integrations/slack/test", {
        method: "POST",
        headers: { "Content-Type": "application/json",
                   "Authorization": `Bearer ${localStorage.getItem("ir_token") ?? ""}` },
        body: JSON.stringify({ webhook_url: slackValues.slack_webhook_url }),
      });
      setSlackTestStatus(res.ok ? "ok" : "fail");
    } catch {
      setSlackTestStatus("fail");
    }
    setTimeout(() => setSlackTestStatus("idle"), 4000);
  }

  async function testPagerDuty() {
    setPdTestStatus("testing");
    try {
      const res = await fetch("/api/v1/integrations/pagerduty/test", {
        method: "POST",
        headers: { "Content-Type": "application/json",
                   "Authorization": `Bearer ${localStorage.getItem("ir_token") ?? ""}` },
        body: JSON.stringify({ routing_key: pdValues.pagerduty_routing_key }),
      });
      setPdTestStatus(res.ok ? "ok" : "fail");
    } catch {
      setPdTestStatus("fail");
    }
    setTimeout(() => setPdTestStatus("idle"), 4000);
  }

  return (
    <>
      <div className="settings-section-title">Integration Hub</div>
      <div className="settings-section-desc">
        외부 서비스와 연동하여 인시던트를 실시간으로 전달합니다.
        설정 후 <strong>테스트 전송</strong>으로 연결을 확인하세요.
      </div>

      {/* Slack */}
      <IntegrationCard
        name="Slack"
        description="Critical/High 인시던트 탐지 시 Slack 채널로 알림 블록을 전송합니다."
        logo={<span style={{ fontWeight: 700, fontSize: 13, color: "#4a154b" }}>S</span>}
        fields={[
          {
            key: "slack_webhook_url",
            label: "Webhook URL",
            placeholder: "https://hooks.slack.com/services/…",
            secret: true,
            helpText: "Slack 앱 → Incoming Webhooks에서 URL을 복사하세요.",
          },
          {
            key: "slack_channel",
            label: "채널 (선택)",
            placeholder: "#security-alerts",
            helpText: "비워두면 Webhook 기본 채널로 전송됩니다.",
          },
        ]}
        values={slackValues}
        onChange={(k, v) => setSlackValues((p) => ({ ...p, [k]: v }))}
        onSave={async () => {
          setSlackSaving(true);
          try { save(slackValues as any); } finally { setSlackSaving(false); }
        }}
        onTest={testSlack}
        saving={slackSaving}
        testStatus={slackTestStatus}
      />

      {/* PagerDuty */}
      <IntegrationCard
        name="PagerDuty"
        description="Critical 인시던트를 PagerDuty 온콜 팀에 즉시 에스컬레이션합니다."
        logo={<span style={{ fontWeight: 700, fontSize: 13, color: "#25c151" }}>PD</span>}
        fields={[
          {
            key: "pagerduty_routing_key",
            label: "Integration Routing Key",
            placeholder: "a1b2c3d4e5f6…",
            secret: true,
            helpText: "PagerDuty → Services → Integrations → Events API v2에서 복사하세요.",
          },
          {
            key: "pagerduty_severity_threshold",
            label: "에스컬레이션 임계값",
            placeholder: "critical",
            helpText: "이 심각도 이상의 인시던트만 PagerDuty로 전달됩니다. (critical / high)",
          },
        ]}
        values={pdValues}
        onChange={(k, v) => setPdValues((p) => ({ ...p, [k]: v }))}
        onSave={async () => {
          setPdSaving(true);
          try { save(pdValues as any); } finally { setPdSaving(false); }
        }}
        onTest={testPagerDuty}
        saving={pdSaving}
        testStatus={pdTestStatus}
      />

      {/* Jira */}
      <IntegrationCard
        name="Jira"
        description="인시던트 발생 시 Jira 프로젝트에 티켓을 자동으로 생성합니다."
        logo={<span style={{ fontWeight: 700, fontSize: 13, color: "#0052cc" }}>J</span>}
        fields={[
          { key: "jira_server_url", label: "Jira Server URL",
            placeholder: "https://yourcompany.atlassian.net" },
          { key: "jira_email", label: "계정 이메일",
            placeholder: "admin@yourcompany.com" },
          { key: "jira_api_token", label: "API Token",
            placeholder: "ATATT3xFfGF0…", secret: true,
            helpText: "Atlassian 계정 → 보안 → API 토큰에서 생성하세요." },
          { key: "jira_project_key", label: "프로젝트 키",
            placeholder: "SEC",
            helpText: "티켓이 생성될 Jira 프로젝트 키입니다. (예: SEC, OPS)" },
        ]}
        values={jiraValues}
        onChange={(k, v) => setJiraValues((p) => ({ ...p, [k]: v }))}
        onSave={async () => { setJiraSaving(true); try { save(jiraValues as any); } finally { setJiraSaving(false); } }}
        saving={jiraSaving}
      />
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────────────
   MFA / SSO Section (설계서 v4 §9 — TOTP MFA + WorkOS SSO)
   ───────────────────────────────────────────────────────────────────────── */

function MfaSsoSection() {
  const [mfaEmail, setMfaEmail] = useState("");
  const [mfaSetup, setMfaSetup] = useState<{
    qr_code_base64: string;
    encrypted_secret: string;
    backup_codes: string[];
    totp_uri: string;
  } | null>(null);
  const [verifyToken, setVerifyToken] = useState("");
  const [verifyStatus, setVerifyStatus] = useState<"idle" | "ok" | "fail">("idle");
  const [loading, setLoading] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);

  const token = localStorage.getItem("ir_token") ?? "";

  async function setupMfa() {
    if (!mfaEmail) return;
    setLoading(true);
    try {
      const res = await fetch("/auth/mfa/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ user_email: mfaEmail }),
      });
      if (res.ok) setMfaSetup(await res.json());
    } catch { /* ignore */ }
    setLoading(false);
  }

  async function verifyMfa() {
    if (!mfaSetup || !verifyToken) return;
    const res = await fetch("/auth/mfa/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ encrypted_secret: mfaSetup.encrypted_secret, token: verifyToken }),
    });
    setVerifyStatus(res.ok ? "ok" : "fail");
  }

  async function initiateSso() {
    const res = await fetch(`/auth/sso/authorize?tenant_id=current`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const { authorization_url } = await res.json();
      window.location.href = authorization_url;
    }
  }

  return (
    <>
      <div className="settings-section-title">MFA (다단계 인증)</div>
      <div className="settings-section-desc">
        TOTP 기반 2단계 인증을 설정합니다. Google Authenticator, Authy 등의 앱과 호환됩니다.
      </div>

      <div className="setting-group">
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <input
            className="form-input"
            placeholder="사용자 이메일"
            value={mfaEmail}
            onChange={(e) => setMfaEmail(e.target.value)}
          />
          <button className="btn btn-primary" onClick={setupMfa} disabled={loading || !mfaEmail} style={{ flexShrink: 0 }}>
            {loading ? "생성 중…" : "MFA 설정 시작"}
          </button>
        </div>

        {mfaSetup && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {/* QR Code */}
            <div style={{ padding: 16, background: "var(--c-gray-50)", borderRadius: 8, border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>QR 코드 스캔</div>
              <img
                src={`data:image/png;base64,${mfaSetup.qr_code_base64}`}
                alt="MFA QR Code"
                style={{ width: 180, height: 180, display: "block" }}
              />
              <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-3)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>
                {mfaSetup.totp_uri}
              </div>
            </div>

            {/* 백업 코드 */}
            <div style={{ padding: 16, background: "var(--c-amber-50)", borderRadius: 8, border: "1px solid var(--c-amber-200)" }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8, color: "var(--c-amber-700)" }}>
                백업 코드 (안전한 곳에 보관하세요)
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4 }}>
                {mfaSetup.backup_codes.map((code) => (
                  <code key={code} style={{ fontSize: 12, padding: "2px 6px", background: "#fff", borderRadius: 4, border: "1px solid var(--c-amber-300)" }}>
                    {code}
                  </code>
                ))}
              </div>
            </div>

            {/* 검증 */}
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                className="form-input"
                placeholder="앱에 표시된 6자리 코드 입력"
                value={verifyToken}
                onChange={(e) => setVerifyToken(e.target.value)}
                maxLength={6}
                style={{ fontFamily: "var(--mono)", letterSpacing: "0.2em" }}
              />
              <button className="btn btn-primary" onClick={verifyMfa} disabled={verifyToken.length < 6} style={{ flexShrink: 0 }}>
                검증
              </button>
              {verifyStatus === "ok" && <span style={{ color: "var(--c-green-600)", fontSize: 13 }}>✅ 성공</span>}
              {verifyStatus === "fail" && <span style={{ color: "var(--c-red-600)", fontSize: 13 }}>❌ 실패</span>}
            </div>
          </div>
        )}
      </div>

      <div className="settings-section-title" style={{ marginTop: 32 }}>SSO (단일 로그인)</div>
      <div className="settings-section-desc">
        WorkOS 기반 SAML 2.0 / OIDC SSO를 통해 기업 IdP와 연동합니다.
        WORKOS_API_KEY 환경 변수 설정이 필요합니다.
      </div>

      <div className="setting-group">
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>SSO 로그인 활성화</div>
            <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 2 }}>
              활성화 시 이메일/비밀번호 로그인 대신 SSO 인증으로 전환됩니다.
            </div>
          </div>
          <label style={{ position: "relative", display: "inline-block", width: 40, height: 22, marginLeft: "auto", flexShrink: 0 }}>
            <input type="checkbox" checked={ssoEnabled} onChange={(e) => setSsoEnabled(e.target.checked)} style={{ opacity: 0, width: 0, height: 0 }} />
            <span style={{
              position: "absolute", cursor: "pointer", inset: 0,
              background: ssoEnabled ? "var(--c-blue-600)" : "var(--c-gray-300)",
              borderRadius: 11, transition: "0.2s",
            }}>
              <span style={{
                position: "absolute", content: "", height: 16, width: 16,
                left: ssoEnabled ? 20 : 3, bottom: 3,
                background: "#fff", borderRadius: "50%", transition: "0.2s",
              }} />
            </span>
          </label>
        </div>

        {ssoEnabled && (
          <button className="btn btn-primary" onClick={initiateSso} style={{ marginTop: 12 }}>
            SSO 로그인 시작 (WorkOS)
          </button>
        )}
      </div>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────────────
   Billing Section (설계서 v4 §11 — Stripe 과금)
   ───────────────────────────────────────────────────────────────────────── */

const PLAN_INFO: Record<string, { name: string; agents: string; retention: string; price: string; color: string }> = {
  trial:      { name: "Trial",      agents: "최대 3",   retention: "7일",   price: "무료",       color: "var(--c-gray-500)" },
  starter:    { name: "Starter",    agents: "최대 3",   retention: "7일",   price: "$49/월",     color: "var(--c-blue-600)" },
  growth:     { name: "Growth",     agents: "무제한",   retention: "90일",  price: "$199/월",    color: "var(--c-green-600)" },
  enterprise: { name: "Enterprise", agents: "무제한",   retention: "1년",   price: "협의",       color: "var(--c-purple-600)" },
};

function BillingSection() {
  const [status, setStatus] = useState<any>(null);
  const [usage, setUsage] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [subscribing, setSubscribing] = useState(false);
  const [email, setEmail] = useState("");
  const [selectedPlan, setSelectedPlan] = useState("growth");
  const [canceling, setCanceling] = useState(false);

  const token = localStorage.getItem("ir_token") ?? "";
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const [statusRes, usageRes] = await Promise.all([
          fetch("/api/v1/billing/status", { headers }),
          fetch("/api/v1/billing/usage", { headers }),
        ]);
        if (statusRes.ok) setStatus(await statusRes.json());
        if (usageRes.ok) {
          const d = await usageRes.json();
          setUsage(d.usage_history || []);
        }
      } catch { /* ignore */ }
      setLoading(false);
    }
    load();
  }, []);

  async function subscribe() {
    if (!email) return;
    setSubscribing(true);
    try {
      const res = await fetch("/api/v1/billing/subscribe", {
        method: "POST",
        headers,
        body: JSON.stringify({ plan: selectedPlan, email }),
      });
      if (res.ok) {
        const d = await res.json();
        setStatus(d);
      }
    } catch { /* ignore */ }
    setSubscribing(false);
  }

  async function cancel() {
    if (!confirm("구독을 취소하시겠습니까? 현재 결제 기간 종료 후 서비스가 중단됩니다.")) return;
    setCanceling(true);
    try {
      const res = await fetch("/api/v1/billing/cancel", { method: "POST", headers });
      if (res.ok) setStatus(await res.json());
    } catch { /* ignore */ }
    setCanceling(false);
  }

  if (loading) return <div style={{ padding: 32, color: "var(--text-3)" }}>로딩 중…</div>;

  const plan = status?.plan || "trial";
  const planInfo = PLAN_INFO[plan] || PLAN_INFO.trial;
  const trialEnd = status?.trial_ends_at ? new Date(status.trial_ends_at).toLocaleDateString("ko-KR") : null;

  return (
    <>
      <div className="settings-section-title">플랜 & 과금</div>
      <div className="settings-section-desc">
        현재 구독 플랜과 에이전트 사용량을 확인합니다.
      </div>

      {/* 현재 플랜 카드 */}
      <div className="setting-group" style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <div style={{
            padding: "4px 12px", borderRadius: 20,
            background: planInfo.color, color: "#fff",
            fontSize: 12, fontWeight: 700,
          }}>
            {planInfo.name.toUpperCase()}
          </div>
          {trialEnd && (
            <span style={{ fontSize: 12, color: "var(--c-amber-600)" }}>
              트라이얼 종료: {trialEnd}
            </span>
          )}
          {status?.stripe_subscription_id && (
            <span style={{ fontSize: 11, color: "var(--text-3)", fontFamily: "var(--mono)" }}>
              {status.stripe_subscription_id}
            </span>
          )}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 16 }}>
          {[
            { label: "에이전트 한도", value: planInfo.agents },
            { label: "로그 보존",     value: planInfo.retention },
            { label: "가격",          value: planInfo.price },
          ].map(({ label, value }) => (
            <div key={label} style={{ padding: 12, background: "var(--c-gray-50)", borderRadius: 8, border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 4 }}>{label}</div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>{value}</div>
            </div>
          ))}
        </div>

        {status?.stripe_subscription_id && plan !== "trial" && (
          <button className="btn btn-sm" onClick={cancel} disabled={canceling} style={{ color: "var(--c-red-600)", borderColor: "var(--c-red-300)" }}>
            {canceling ? "취소 중…" : "구독 취소"}
          </button>
        )}
      </div>

      {/* 플랜 업그레이드 */}
      {(plan === "trial" || plan === "starter") && (
        <div className="setting-group" style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>플랜 업그레이드</div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            {["starter", "growth", "enterprise"].map((p) => (
              <button
                key={p}
                onClick={() => setSelectedPlan(p)}
                style={{
                  padding: "6px 14px", borderRadius: 6, border: "1px solid",
                  borderColor: selectedPlan === p ? PLAN_INFO[p].color : "var(--border)",
                  background: selectedPlan === p ? `${PLAN_INFO[p].color}15` : "transparent",
                  color: selectedPlan === p ? PLAN_INFO[p].color : "var(--text-2)",
                  fontSize: 13, fontWeight: 500, cursor: "pointer",
                }}
              >
                {PLAN_INFO[p].name}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              className="form-input"
              placeholder="결제 이메일"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type="email"
            />
            <button className="btn btn-primary" onClick={subscribe} disabled={subscribing || !email} style={{ flexShrink: 0 }}>
              {subscribing ? "처리 중…" : "구독 시작"}
            </button>
          </div>
        </div>
      )}

      {/* 에이전트 사용량 히스토리 */}
      {usage.length > 0 && (
        <div className="setting-group">
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>에이전트 사용량 (최근 30일)</div>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>날짜</th>
                  <th>에이전트 수</th>
                  <th>Stripe 보고</th>
                </tr>
              </thead>
              <tbody>
                {usage.slice(0, 10).map((u, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
                      {new Date(u.reported_at).toLocaleDateString("ko-KR")}
                    </td>
                    <td><strong>{u.agent_count}</strong></td>
                    <td>{u.stripe_reported ? "✅" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
