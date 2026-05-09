import { useEffect, useRef, useState } from "react";
import {
  Bot, Bell, SlidersHorizontal, ShieldCheck, Key,
  Copy, Check, Trash2, Plus, ShieldBan, Zap, Globe,
} from "lucide-react";
import {
  fetchSettings, updateSettings, fetchApiKeys, createApiKey, revokeApiKey,
  fetchThreatIpPolicy, updateThreatIpPolicy, fetchPolicyStatus,
  type TenantSettings, type ApiKey, type ThreatIpPolicy, type PolicyStatus,
} from "../lib/api";

/* ── Sidebar nav items ─────────────────────────────────── */
const NAV = [
  {
    group: "자동 대응",
    items: [
      { id: "response",  icon: Bot,            label: "AI 대응 모드",    desc: "탐지 후 자동화 수준" },
      { id: "autocheck", icon: Zap,            label: "Auto-Response",   desc: "심각도별 자동 대응 체크박스" },
    ],
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
    group: "IP 정책",
    items: [{ id: "policy",   icon: ShieldBan,         label: "IP Policy Manager", desc: "허용 / 차단 / 국가 정책" }],
  },
  {
    group: "개발자",
    items: [{ id: "keys",     icon: Key,               label: "API Keys",        desc: "SDK 연동용 키 관리" }],
  },
] as const;

type TabId = "response" | "autocheck" | "notify" | "rules" | "advanced" | "policy" | "keys";

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
export function SettingsPage() {
  const [settings, setSettings]   = useState<TenantSettings | null>(null);
  const [apiKeys, setApiKeys]     = useState<ApiKey[]>([]);
  const [tab, setTab]             = useState<TabId>("response");
  const [saving, setSaving]       = useState(false);
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRaw, setNewKeyRaw]  = useState<string>();
  const [copied, setCopied]        = useState(false);
  const toastTimer = useRef<ReturnType<typeof setTimeout>>();

  // IP Policy state
  const [policy, setPolicy]           = useState<ThreatIpPolicy>({ mode: "monitor", allowlist: [], denylist: [], country_block: [] });
  const [policyStatus, setPolicyStatus] = useState<PolicyStatus | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const allowRef   = useRef<HTMLTextAreaElement>(null);
  const denyRef    = useRef<HTMLTextAreaElement>(null);
  const countryRef = useRef<HTMLTextAreaElement>(null);

  // Auto-Response checkbox state (심각도별 자동 대응 활성화)
  const [autoResponse, setAutoResponse] = useState<Record<string, boolean>>({
    critical: true,
    high: false,
    medium: false,
    info: false,
  });

  useEffect(() => {
    fetchSettings().then(setSettings).catch(console.error);
    fetchApiKeys().then(setApiKeys).catch(console.error);
  }, []);

  useEffect(() => {
    if (tab === "policy") {
      setPolicyLoading(true);
      Promise.all([
        fetchThreatIpPolicy().then(setPolicy),
        fetchPolicyStatus().then(setPolicyStatus),
      ]).catch(console.error).finally(() => setPolicyLoading(false));
    }
  }, [tab]);

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
          </>
        )}

        {/* ── Auto-Response 체크박스 ──────────────────────────── */}
        {tab === "autocheck" && (
          <>
            <div className="settings-section-title">Auto-Response 설정</div>
            <div className="settings-section-desc">
              심각도별로 자동 대응을 독립적으로 켜고 끌 수 있습니다.
              AI 대응 모드가 <strong>수동(Manual)</strong>이면 이 설정은 무시됩니다.
            </div>

            <div className="setting-group">
              {(["critical", "high", "medium", "info"] as const).map((sev) => {
                const labels: Record<string, { emoji: string; desc: string }> = {
                  critical: { emoji: "🔴", desc: "즉각적인 IP 차단 및 계정 잠금 실행" },
                  high:     { emoji: "🟠", desc: "알림 발송 + 승인 후 IP 차단 실행" },
                  medium:   { emoji: "🟡", desc: "알림 발송 + 워치리스트 자동 추가" },
                  info:     { emoji: "🔵", desc: "알림만 전송, 자동 조치 없음" },
                };
                const { emoji, desc } = labels[sev];
                return (
                  <div key={sev} className="setting-row">
                    <div className="setting-row-info">
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                        <span style={{ fontSize: 16 }}>{emoji}</span>
                        <div className="setting-row-label" style={{ margin: 0, textTransform: "capitalize" }}>
                          {sev} 자동 대응
                        </div>
                        <span className={`pill pill-sm sev-${sev}`}>{sev}</span>
                      </div>
                      <div className="setting-row-desc">{desc}</div>
                    </div>
                    <div className="setting-row-control">
                      <label className="autoresponse-checkbox">
                        <input
                          type="checkbox"
                          checked={autoResponse[sev] ?? false}
                          onChange={(e) => {
                            const next = { ...autoResponse, [sev]: e.target.checked };
                            setAutoResponse(next);
                            showToast(`${sev.toUpperCase()} 자동 대응 ${e.target.checked ? "활성화" : "비활성화"}됐습니다`);
                          }}
                        />
                        <span className="autoresponse-checkbox-box" />
                        <span className="autoresponse-checkbox-label">
                          {autoResponse[sev] ? "활성" : "비활성"}
                        </span>
                      </label>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ marginTop: 12, padding: "12px 16px", background: "var(--c-blue-50)", border: "1px solid var(--c-blue-200)", borderRadius: "var(--r-md)", fontSize: 13, color: "var(--c-blue-700)", lineHeight: 1.6 }}>
              💡 이 설정은 클라이언트 UI 상태입니다. 완전한 서버 반영을 위해서는
              <strong> AI 대응 모드</strong> 탭에서 심각도 임계값도 함께 조정하세요.
            </div>
          </>
        )}

        {/* ── 알림 채널 ────────────────────────────────────── */}
        {tab === "notify" && (
          <>
            <div className="settings-section-title">알림 채널</div>
            <div className="settings-section-desc">
              보안 인시던트 탐지 시 알림을 받을 채널을 설정합니다.
              InfraRed는 <strong>2단계 알림</strong>을 지원합니다.
            </div>

            {/* 2단계 알림 설명 배너 */}
            <div className="notify-phases-banner">
              <div className="notify-phase-item">
                <div className="notify-phase-num">1</div>
                <div>
                  <div className="notify-phase-title">탐지 즉시 알림</div>
                  <div className="notify-phase-desc">인시던트가 생성되는 순간 경보 메시지를 발송합니다. AI 분석 대기 중 상태로 표시됩니다.</div>
                </div>
              </div>
              <div className="notify-phase-divider">→</div>
              <div className="notify-phase-item">
                <div className="notify-phase-num phase-2">2</div>
                <div>
                  <div className="notify-phase-title">AI 분석 완료 알림</div>
                  <div className="notify-phase-desc">LLM 분석이 끝나면 공격 의도·Kill Chain·권장 조치를 포함한 상세 embed를 추가로 전송합니다.</div>
                </div>
              </div>
            </div>

            {/* Discord 카드 */}
            <div className="notify-channel-card">
              <div className="notify-channel-header">
                <div className="notify-channel-icon" style={{ background: "#5865F2" }}>
                  <span style={{ fontSize: 18 }}>💬</span>
                </div>
                <div style={{ flex: 1 }}>
                  <div className="notify-channel-title">Discord</div>
                  <div className="notify-channel-subtitle">Webhook을 통해 지정한 채널로 인시던트 알림 embed를 전송합니다.</div>
                </div>
                <span className={`notify-status-pill ${settings.discord_webhook_url ? "configured" : "unconfigured"}`}>
                  {settings.discord_webhook_url ? "● 설정됨" : "○ 미설정"}
                </span>
              </div>

              <div className="notify-channel-body">
                <label className="notify-field-label">Webhook URL</label>
                <NotifyField
                  label=""
                  desc=""
                  placeholder="https://discord.com/api/webhooks/1234567890/abcdefg…"
                  defaultValue={settings.discord_webhook_url ?? ""}
                  onSave={(v) => save({ discord_webhook_url: v })}
                />

                {/* Discord 알림 미리보기 */}
                <div className="discord-preview">
                  <div className="discord-preview-label">📋 알림 미리보기</div>

                  {/* Phase 1 embed */}
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: ".04em" }}>Phase 1 — 탐지 즉시</div>
                    <div className="discord-embed" style={{ borderLeftColor: "#f97316" }}>
                      <div className="discord-embed-title">🚨 [HIGH] 인시던트 탐지 — INC-20260509-XXXX</div>
                      <div className="discord-embed-fields">
                        <div className="discord-embed-field">
                          <div className="discord-field-name">Source IP</div>
                          <div className="discord-field-value mono">185.12.34.56</div>
                        </div>
                        <div className="discord-embed-field">
                          <div className="discord-field-name">MITRE</div>
                          <div className="discord-field-value">Initial Access · T1110.001</div>
                        </div>
                        <div className="discord-embed-field" style={{ flexBasis: "100%" }}>
                          <div className="discord-field-name">AI 분석</div>
                          <div className="discord-field-value">⏳ AI 분석 진행 중…</div>
                        </div>
                      </div>
                      <div className="discord-embed-footer">InfraRed SOC · company-a · 방금 전</div>
                    </div>
                  </div>

                  {/* Phase 2 embed */}
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: ".04em" }}>Phase 2 — AI 분석 완료 후</div>
                    <div className="discord-embed" style={{ borderLeftColor: "#22c55e" }}>
                      <div className="discord-embed-title">🤖 AI 분석 완료 — INC-20260509-XXXX</div>
                      <div className="discord-embed-fields">
                        <div className="discord-embed-field">
                          <div className="discord-field-name">공격 요약</div>
                          <div className="discord-field-value">SSH brute force 후 root 계정 침입 성공. 즉각 대응 필요.</div>
                        </div>
                        <div className="discord-embed-field">
                          <div className="discord-field-name">권장 조치 1</div>
                          <div className="discord-field-value">185.12.34.56 즉시 차단</div>
                        </div>
                        <div className="discord-embed-field">
                          <div className="discord-field-name">권장 조치 2</div>
                          <div className="discord-field-value">root 비밀번호 즉시 변경</div>
                        </div>
                      </div>
                      <div className="discord-embed-footer">InfraRed SOC · AI 모델: claude-3-5-sonnet</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Email 카드 */}
            <div className="notify-channel-card">
              <div className="notify-channel-header">
                <div className="notify-channel-icon" style={{ background: "#0ea5e9" }}>
                  <span style={{ fontSize: 18 }}>✉️</span>
                </div>
                <div style={{ flex: 1 }}>
                  <div className="notify-channel-title">이메일</div>
                  <div className="notify-channel-subtitle">Critical 심각도 인시던트 발생 시 지정한 주소로 이메일을 발송합니다.</div>
                </div>
                <span className={`notify-status-pill ${settings.alert_email_to ? "configured" : "unconfigured"}`}>
                  {settings.alert_email_to ? "● 설정됨" : "○ 미설정"}
                </span>
              </div>

              <div className="notify-channel-body">
                <label className="notify-field-label">수신 이메일 주소</label>
                <NotifyField
                  label=""
                  desc=""
                  placeholder="admin@company.com"
                  defaultValue={settings.alert_email_to ?? ""}
                  onSave={(v) => save({ alert_email_to: v })}
                />
                <div className="notify-channel-hint">
                  💡 SMTP 설정은 서버 <code>.env</code> 파일의 <code>SMTP_HOST</code> / <code>SMTP_USER</code> 항목에서 합니다.
                </div>
              </div>
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

        {/* ── IP Policy Manager ───────────────────────────────── */}
        {tab === "policy" && (
          <>
            <div className="settings-section-title">IP Policy Manager</div>
            <div className="settings-section-desc">
              공격자 IP 차단, 신뢰 IP 허용, 국가 단위 차단 정책을 관리합니다.
              변경 즉시 Redis에 반영되고 모든 워커에 캐시 무효화 신호가 전송됩니다.
            </div>

            {policyStatus && (
              <div className="policy-status-bar">
                <div className="policy-status-item">
                  <span className="policy-status-label">정책 버전</span>
                  <span className="policy-status-val">v{policyStatus.policy_version}</span>
                </div>
                <div className="policy-status-item">
                  <span className="policy-status-label">워치리스트</span>
                  <span className="policy-status-val">{policyStatus.watchlist_count}개</span>
                </div>
                <div className="policy-status-item">
                  <span className="policy-status-label">차단 목록</span>
                  <span className="policy-status-val red">{policyStatus.denylist_count}개</span>
                </div>
                <div className="policy-status-item">
                  <span className="policy-status-label">허용 Agent</span>
                  <span className="policy-status-val">{policyStatus.allowed_agent_count}개</span>
                </div>
              </div>
            )}

            {/* 대응 모드 */}
            <div className="setting-group">
              <div className="setting-row">
                <div className="setting-row-info">
                  <div className="setting-row-label">차단 모드</div>
                  <div className="setting-row-desc">
                    <strong>monitor</strong>: 이벤트만 기록  ·  <strong>block</strong>: 실시간 차단 (Enforcement 연동 필요)
                  </div>
                </div>
                <div className="setting-row-control">
                  <div style={{ display: "flex", gap: 6 }}>
                    {(["monitor", "block"] as const).map((m) => (
                      <button
                        key={m}
                        className={`sev-btn ${policy.mode === m ? "sev-btn-active-" + (m === "block" ? "critical" : "info") : ""}`}
                        style={{ fontSize: 12, padding: "4px 12px" }}
                        onClick={() => setPolicy({ ...policy, mode: m })}
                      >
                        {m === "block" ? "🔒 Block" : "👁 Monitor"}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Allowlist */}
            <div className="setting-group">
              <div className="setting-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 10 }}>
                <div>
                  <div className="setting-row-label" style={{ color: "var(--c-green-600)" }}>✅ 허용 IP / CIDR (Allowlist)</div>
                  <div className="setting-row-desc">이 IP는 모든 탐지 룰에서 제외됩니다. 한 줄에 하나씩 입력.</div>
                </div>
                <textarea
                  ref={allowRef}
                  className="form-input policy-textarea"
                  defaultValue={policy.allowlist.join("\n")}
                  placeholder={"192.168.0.0/24\n10.0.0.1"}
                  rows={4}
                />
              </div>
            </div>

            {/* Denylist */}
            <div className="setting-group">
              <div className="setting-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 10 }}>
                <div>
                  <div className="setting-row-label" style={{ color: "var(--c-red-600)" }}>🚫 차단 IP / CIDR (Denylist)</div>
                  <div className="setting-row-desc">이 IP에서 오는 모든 요청을 즉시 차단합니다. 한 줄에 하나씩 입력.</div>
                </div>
                <textarea
                  ref={denyRef}
                  className="form-input policy-textarea"
                  defaultValue={policy.denylist.join("\n")}
                  placeholder={"1.2.3.4\n5.6.0.0/16"}
                  rows={4}
                />
              </div>
            </div>

            {/* Country block */}
            <div className="setting-group">
              <div className="setting-row" style={{ flexDirection: "column", alignItems: "stretch", gap: 10 }}>
                <div>
                  <div className="setting-row-label" style={{ color: "var(--c-orange-600)" }}>🌍 국가 차단 (Country Block)</div>
                  <div className="setting-row-desc">차단할 국가 ISO-2 코드. 콤마 또는 줄바꿈으로 구분 (예: CN, RU, KP).</div>
                </div>
                <textarea
                  ref={countryRef}
                  className="form-input policy-textarea"
                  defaultValue={policy.country_block.join(", ")}
                  placeholder={"CN\nRU\nKP"}
                  rows={3}
                />
              </div>
            </div>

            <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
              <button
                className="btn btn-primary"
                disabled={policyLoading}
                onClick={async () => {
                  const parseLines = (ref: React.RefObject<HTMLTextAreaElement | null>) =>
                    (ref.current?.value ?? "")
                      .split(/[\n,]/)
                      .map(s => s.trim())
                      .filter(Boolean);

                  const next: ThreatIpPolicy = {
                    mode: policy.mode,
                    allowlist: parseLines(allowRef),
                    denylist: parseLines(denyRef),
                    country_block: parseLines(countryRef),
                  };
                  setPolicyLoading(true);
                  try {
                    await updateThreatIpPolicy(next);
                    setPolicy(next);
                    const status = await fetchPolicyStatus();
                    setPolicyStatus(status);
                    showToast("IP 정책이 저장되고 Redis에 반영됐습니다");
                  } catch (e) {
                    showToast("정책 저장 실패: " + (e instanceof Error ? e.message : "오류"), false);
                  } finally {
                    setPolicyLoading(false);
                  }
                }}
              >
                {policyLoading ? "저장 중…" : "정책 저장 및 반영"}
              </button>
              <button
                className="btn"
                onClick={() => {
                  if (allowRef.current)   allowRef.current.value   = policy.allowlist.join("\n");
                  if (denyRef.current)    denyRef.current.value    = policy.denylist.join("\n");
                  if (countryRef.current) countryRef.current.value = policy.country_block.join(", ");
                }}
              >
                초기화
              </button>
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
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {label && <div className="setting-row-label">{label}</div>}
      {desc && <div className="setting-row-desc">{desc}</div>}
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
