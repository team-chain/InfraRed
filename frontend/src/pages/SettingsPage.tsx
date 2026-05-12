import { useEffect, useRef, useState } from "react";
import {
  Bot, Bell, SlidersHorizontal, ShieldCheck, Key,
  Copy, Check, Trash2, Plus,
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
    items: [{ id: "notify",   icon: Bell,              label: "알림 채널",       desc: "Discord · Email" }],
  },
  {
    group: "탐지 규칙",
    items: [
      { id: "rules",          icon: SlidersHorizontal, label: "탐지 임계값",     desc: "Brute Force · Scan" },
      { id: "advanced",       icon: ShieldCheck,       label: "감지 범위 확장",  desc: "시간대 · 해외 IP · 웹 공격" },
    ],
  },
  {
    group: "개발자",
    items: [{ id: "keys",     icon: Key,               label: "API Keys",        desc: "SDK 연동용 키 관리" }],
  },
] as const;

type TabId = "response" | "notify" | "rules" | "advanced" | "keys";

/* ── Per-severity 정책 체크박스 컴포넌트 (설계서 5.2) ──────────────────────── */
const SEV_LABELS: Record<string, { label: string; color: string; emoji: string }> = {
  critical: { label: "Critical", color: "#cc2200", emoji: "🔴" },
  high:     { label: "High",     color: "#ff6600", emoji: "🟠" },
  medium:   { label: "Medium",   color: "#ffaa00", emoji: "🟡" },
  info:     { label: "Info",     color: "#3399ff", emoji: "🔵" },
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
                    {meta.emoji} {meta.label}
                  </span>
                </td>
                {actions.map((action) => (
                  <td key={action} style={{ padding: "10px 12px", textAlign: "center" }}>
                    <Toggle
                      checked={sevPolicy[action]}
                      onChange={(v) => onChange(sev, action, v)}
                    />
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
const MODES = [
  {
    value: "manual",
    icon: "🔕",
    label: "수동 대응",
    desc: "AI가 위협을 분석하고 Discord로 알림만 전송합니다. 모든 대응 조치는 담당자가 직접 수행합니다.",
  },
  {
    value: "approval",
    icon: "✅",
    label: "승인 후 실행",
    desc: "AI가 대응 액션을 준비하고 대시보드에 표시합니다. 담당자가 승인하면 자동 실행됩니다.",
  },
  {
    value: "auto",
    icon: "🤖",
    label: "완전 자동화",
    desc: "AI가 탐지부터 IP 차단·계정 잠금까지 자동으로 실행하고 결과를 보고합니다.",
  },
] as const;

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
                  <div className="mode-icon">{m.icon}</div>
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
                <div className="key-value-label">⚠️ 지금만 표시됩니다 — 안전한 곳에 복사해 두세요</div>
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
