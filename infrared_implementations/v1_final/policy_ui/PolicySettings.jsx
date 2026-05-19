/**
 * InfraRed v1 — 정책 설정 UI
 * 설계서_최종.docx 구현 순서 #4
 *
 * 체크박스 기반 자동 대응 설정 + 레벨별 정책 토글
 * - Level 1~4 대응 단계별 활성/비활성
 * - Allowlist IP 관리
 * - dry_run 모드 토글
 * - 정책 저장/불러오기
 */

import { useState, useEffect, useCallback } from "react";

// ─────────────────────────────────────────────────────────────
// 상수
// ─────────────────────────────────────────────────────────────
const RESPONSE_LEVELS = [
  {
    level: 1,
    name: "Discord 알림",
    description: "의심 이벤트 탐지 시 Discord 채널에 즉시 알림 발송",
    mitre: "모든 심각도",
    icon: "🔔",
  },
  {
    level: 2,
    name: "Redis Denylist 차단 (HTTP 403)",
    description: "공격 IP를 Redis Denylist에 등록하여 서비스 레벨에서 HTTP 403 차단",
    mitre: "HIGH 이상",
    icon: "🚫",
  },
  {
    level: 3,
    name: "Nginx / iptables 차단",
    description: "OS 방화벽(iptables) 및 Nginx에서 해당 IP 완전 차단",
    mitre: "HIGH 이상 + 신뢰도 0.8+",
    icon: "🛡️",
    requiresConfirm: true,
  },
  {
    level: 4,
    name: "WAF / Cloudflare 연동",
    description: "Cloudflare 또는 AWS WAF에 차단 규칙 자동 추가",
    mitre: "CRITICAL",
    icon: "☁️",
    requiresConfirm: true,
  },
];

const DEFAULT_POLICY = {
  dry_run: true,
  enabled_levels: [1],
  auto_block_confidence_threshold: 0.8,
  block_ttl_seconds: 1800,
  allowlist_ips: [],
  severity_thresholds: {
    level2: "HIGH",
    level3: "HIGH",
    level4: "CRITICAL",
  },
  notifications: {
    discord: true,
    email: false,
    slack: false,
  },
};

// ─────────────────────────────────────────────────────────────
// API 클라이언트
// ─────────────────────────────────────────────────────────────
async function fetchPolicy(tenantId) {
  const res = await fetch(`/api/v1/policy`, {
    headers: { "X-Tenant-ID": tenantId },
  });
  if (!res.ok) throw new Error("정책 로드 실패");
  return res.json();
}

async function savePolicy(tenantId, policy) {
  const res = await fetch(`/api/v1/policy`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Tenant-ID": tenantId,
    },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error("정책 저장 실패");
  return res.json();
}

// ─────────────────────────────────────────────────────────────
// 컴포넌트
// ─────────────────────────────────────────────────────────────
export default function PolicySettings({ tenantId = "default" }) {
  const [policy, setPolicy]   = useState(DEFAULT_POLICY);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const [error, setError]     = useState(null);
  const [newIp, setNewIp]     = useState("");
  const [confirmLevel, setConfirmLevel] = useState(null);

  // 정책 로드
  useEffect(() => {
    fetchPolicy(tenantId)
      .then(setPolicy)
      .catch(() => setPolicy(DEFAULT_POLICY))
      .finally(() => setLoading(false));
  }, [tenantId]);

  // 레벨 토글
  const toggleLevel = useCallback((level) => {
    const rl = RESPONSE_LEVELS.find((r) => r.level === level);
    if (rl?.requiresConfirm && !policy.enabled_levels.includes(level)) {
      setConfirmLevel(level);
      return;
    }
    setPolicy((prev) => ({
      ...prev,
      enabled_levels: prev.enabled_levels.includes(level)
        ? prev.enabled_levels.filter((l) => l !== level)
        : [...prev.enabled_levels, level].sort(),
    }));
    setSaved(false);
  }, [policy.enabled_levels]);

  const confirmEnableLevel = () => {
    if (!confirmLevel) return;
    setPolicy((prev) => ({
      ...prev,
      enabled_levels: [...prev.enabled_levels, confirmLevel].sort(),
    }));
    setConfirmLevel(null);
    setSaved(false);
  };

  // Allowlist 추가
  const addAllowlistIp = () => {
    const ip = newIp.trim();
    if (!ip || policy.allowlist_ips.includes(ip)) return;
    // 간단한 IP 형식 검증
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (!ipRegex.test(ip)) {
      setError("유효하지 않은 IP 형식입니다.");
      return;
    }
    setPolicy((prev) => ({
      ...prev,
      allowlist_ips: [...prev.allowlist_ips, ip],
    }));
    setNewIp("");
    setSaved(false);
    setError(null);
  };

  const removeAllowlistIp = (ip) => {
    setPolicy((prev) => ({
      ...prev,
      allowlist_ips: prev.allowlist_ips.filter((i) => i !== ip),
    }));
    setSaved(false);
  };

  // 저장
  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await savePolicy(tenantId, policy);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div style={styles.loadingBox}>
        <div style={styles.spinner} />
        <span>정책 설정 로드 중...</span>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {/* 헤더 */}
      <div style={styles.header}>
        <div>
          <h2 style={styles.title}>🛡️ 자동 대응 정책 설정</h2>
          <p style={styles.subtitle}>탐지된 위협에 대한 자동 대응 레벨을 구성합니다</p>
        </div>
        {/* dry_run 토글 */}
        <label style={styles.dryRunToggle}>
          <span style={{ ...styles.badge, background: policy.dry_run ? "#f59e0b" : "#ef4444" }}>
            {policy.dry_run ? "🧪 테스트 모드" : "⚡ 실행 모드"}
          </span>
          <input
            type="checkbox"
            checked={!policy.dry_run}
            onChange={(e) => {
              setPolicy((p) => ({ ...p, dry_run: !e.target.checked }));
              setSaved(false);
            }}
            style={{ display: "none" }}
          />
          <div style={{ ...styles.toggleTrack, background: policy.dry_run ? "#d1d5db" : "#10b981" }}>
            <div style={{ ...styles.toggleThumb, transform: policy.dry_run ? "none" : "translateX(20px)" }} />
          </div>
        </label>
      </div>

      {policy.dry_run && (
        <div style={styles.warningBanner}>
          ⚠️ 테스트 모드: 차단 명령이 실제로 실행되지 않습니다. 실제 대응을 활성화하려면 실행 모드로 전환하세요.
        </div>
      )}

      {/* 대응 레벨 */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>대응 레벨 설정</h3>
        <div style={styles.levelList}>
          {RESPONSE_LEVELS.map((rl) => {
            const enabled = policy.enabled_levels.includes(rl.level);
            return (
              <div key={rl.level} style={{ ...styles.levelCard, borderColor: enabled ? "#3b82f6" : "#e5e7eb" }}>
                <div style={styles.levelCardLeft}>
                  <span style={styles.levelIcon}>{rl.icon}</span>
                  <div>
                    <div style={styles.levelName}>
                      Level {rl.level}: {rl.name}
                    </div>
                    <div style={styles.levelDesc}>{rl.description}</div>
                    <div style={styles.levelMitre}>적용 조건: {rl.mitre}</div>
                  </div>
                </div>
                <label style={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={() => toggleLevel(rl.level)}
                    style={styles.checkbox}
                  />
                  <span style={{ color: enabled ? "#10b981" : "#9ca3af", fontSize: 14 }}>
                    {enabled ? "활성" : "비활성"}
                  </span>
                </label>
              </div>
            );
          })}
        </div>
      </section>

      {/* 신뢰도 임계값 */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>자동 실행 신뢰도 임계값</h3>
        <p style={styles.helpText}>
          AI 분석 신뢰도가 이 값 이상일 때만 자동 차단이 실행됩니다.
          미달 시 관리자 승인 대기 상태로 전환됩니다.
        </p>
        <div style={styles.sliderRow}>
          <input
            type="range"
            min="0.5"
            max="1.0"
            step="0.05"
            value={policy.auto_block_confidence_threshold}
            onChange={(e) => {
              setPolicy((p) => ({ ...p, auto_block_confidence_threshold: parseFloat(e.target.value) }));
              setSaved(false);
            }}
            style={styles.slider}
          />
          <span style={styles.sliderValue}>
            {(policy.auto_block_confidence_threshold * 100).toFixed(0)}%
          </span>
        </div>
      </section>

      {/* 차단 TTL */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>임시 차단 유지 시간 (TTL)</h3>
        <div style={styles.ttlRow}>
          {[900, 1800, 3600, 7200, 86400].map((ttl) => (
            <button
              key={ttl}
              style={{
                ...styles.ttlButton,
                background: policy.block_ttl_seconds === ttl ? "#3b82f6" : "#f3f4f6",
                color:      policy.block_ttl_seconds === ttl ? "white"    : "#374151",
              }}
              onClick={() => {
                setPolicy((p) => ({ ...p, block_ttl_seconds: ttl }));
                setSaved(false);
              }}
            >
              {ttl < 3600 ? `${ttl / 60}분` : `${ttl / 3600}시간`}
            </button>
          ))}
        </div>
      </section>

      {/* Allowlist */}
      <section style={styles.section}>
        <h3 style={styles.sectionTitle}>Allowlist (차단 예외 IP)</h3>
        <p style={styles.helpText}>이 목록의 IP는 어떠한 경우에도 차단되지 않습니다.</p>
        <div style={styles.ipInputRow}>
          <input
            type="text"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            placeholder="예: 203.0.113.10 또는 10.0.0.0/8"
            style={styles.input}
            onKeyDown={(e) => e.key === "Enter" && addAllowlistIp()}
          />
          <button style={styles.addButton} onClick={addAllowlistIp}>추가</button>
        </div>
        <div style={styles.ipList}>
          {policy.allowlist_ips.length === 0 ? (
            <span style={{ color: "#9ca3af", fontSize: 13 }}>등록된 IP 없음</span>
          ) : (
            policy.allowlist_ips.map((ip) => (
              <span key={ip} style={styles.ipTag}>
                {ip}
                <button style={styles.removeBtn} onClick={() => removeAllowlistIp(ip)}>×</button>
              </span>
            ))
          )}
        </div>
      </section>

      {/* 에러 / 저장 완료 */}
      {error && <div style={styles.errorBox}>{error}</div>}
      {saved && <div style={styles.successBox}>✅ 정책이 저장되었습니다.</div>}

      {/* 저장 버튼 */}
      <div style={styles.footer}>
        <button style={styles.saveButton} onClick={handleSave} disabled={saving}>
          {saving ? "저장 중..." : "정책 저장"}
        </button>
      </div>

      {/* 위험 레벨 확인 모달 */}
      {confirmLevel && (
        <div style={styles.modalOverlay}>
          <div style={styles.modal}>
            <h3 style={{ marginTop: 0 }}>⚠️ 위험한 레벨 활성화</h3>
            <p>
              Level {confirmLevel}은(는) 실제 OS 방화벽 또는 외부 WAF에 차단 규칙을 추가합니다.
              잘못 설정 시 정상 트래픽이 차단될 수 있습니다.
            </p>
            <p>신뢰도 임계값({(policy.auto_block_confidence_threshold * 100).toFixed(0)}%)이 충분히 높은지 확인하세요.</p>
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button style={styles.cancelBtn} onClick={() => setConfirmLevel(null)}>취소</button>
              <button style={styles.confirmBtn} onClick={confirmEnableLevel}>활성화</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 스타일
// ─────────────────────────────────────────────────────────────
const styles = {
  container:     { maxWidth: 720, margin: "0 auto", padding: 24, fontFamily: "system-ui, sans-serif" },
  header:        { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 },
  title:         { margin: 0, fontSize: 22, fontWeight: 700 },
  subtitle:      { margin: "4px 0 0", color: "#6b7280", fontSize: 14 },
  section:       { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 8, padding: 20, marginBottom: 16 },
  sectionTitle:  { margin: "0 0 12px", fontSize: 16, fontWeight: 600 },
  helpText:      { color: "#6b7280", fontSize: 13, margin: "0 0 12px" },
  levelList:     { display: "flex", flexDirection: "column", gap: 12 },
  levelCard:     { display: "flex", justifyContent: "space-between", alignItems: "center", padding: 14, border: "2px solid", borderRadius: 8, transition: "border-color 0.2s" },
  levelCardLeft: { display: "flex", gap: 12, alignItems: "flex-start" },
  levelIcon:     { fontSize: 22, lineHeight: 1 },
  levelName:     { fontWeight: 600, marginBottom: 2 },
  levelDesc:     { color: "#6b7280", fontSize: 13, marginBottom: 2 },
  levelMitre:    { color: "#9ca3af", fontSize: 12 },
  checkboxLabel: { display: "flex", alignItems: "center", gap: 8, cursor: "pointer" },
  checkbox:      { width: 18, height: 18, cursor: "pointer" },
  badge:         { padding: "4px 10px", borderRadius: 12, color: "white", fontSize: 13, fontWeight: 600, cursor: "pointer" },
  dryRunToggle:  { display: "flex", alignItems: "center", gap: 10, cursor: "pointer" },
  toggleTrack:   { width: 44, height: 24, borderRadius: 12, position: "relative", transition: "background 0.2s", flexShrink: 0 },
  toggleThumb:   { position: "absolute", top: 2, left: 2, width: 20, height: 20, borderRadius: "50%", background: "white", transition: "transform 0.2s", boxShadow: "0 1px 3px rgba(0,0,0,0.3)" },
  warningBanner: { background: "#fef3c7", border: "1px solid #f59e0b", borderRadius: 8, padding: "12px 16px", marginBottom: 16, fontSize: 14, color: "#92400e" },
  sliderRow:     { display: "flex", alignItems: "center", gap: 16 },
  slider:        { flex: 1, accentColor: "#3b82f6" },
  sliderValue:   { fontWeight: 700, fontSize: 18, color: "#3b82f6", minWidth: 48 },
  ttlRow:        { display: "flex", gap: 8, flexWrap: "wrap" },
  ttlButton:     { padding: "8px 16px", borderRadius: 8, border: "none", cursor: "pointer", fontWeight: 500, transition: "all 0.15s" },
  ipInputRow:    { display: "flex", gap: 8, marginBottom: 12 },
  input:         { flex: 1, padding: "8px 12px", border: "1px solid #d1d5db", borderRadius: 6, fontSize: 14 },
  addButton:     { padding: "8px 16px", background: "#3b82f6", color: "white", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 500 },
  ipList:        { display: "flex", flexWrap: "wrap", gap: 8 },
  ipTag:         { display: "flex", alignItems: "center", gap: 4, padding: "4px 10px", background: "#eff6ff", border: "1px solid #bfdbfe", borderRadius: 20, fontSize: 13, color: "#1d4ed8" },
  removeBtn:     { background: "none", border: "none", cursor: "pointer", color: "#9ca3af", fontSize: 16, lineHeight: 1, padding: 0 },
  footer:        { display: "flex", justifyContent: "flex-end", marginTop: 8 },
  saveButton:    { padding: "10px 28px", background: "#10b981", color: "white", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 15, fontWeight: 600 },
  errorBox:      { background: "#fef2f2", border: "1px solid #fca5a5", color: "#dc2626", borderRadius: 8, padding: "10px 16px", marginBottom: 12, fontSize: 14 },
  successBox:    { background: "#f0fdf4", border: "1px solid #86efac", color: "#16a34a", borderRadius: 8, padding: "10px 16px", marginBottom: 12, fontSize: 14 },
  modalOverlay:  { position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 },
  modal:         { background: "white", borderRadius: 12, padding: 28, maxWidth: 440, width: "90%", boxShadow: "0 20px 60px rgba(0,0,0,0.3)" },
  cancelBtn:     { padding: "8px 20px", background: "#f3f4f6", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 500 },
  confirmBtn:    { padding: "8px 20px", background: "#ef4444", color: "white", border: "none", borderRadius: 6, cursor: "pointer", fontWeight: 600 },
  loadingBox:    { display: "flex", alignItems: "center", gap: 12, padding: 40, justifyContent: "center" },
  spinner:       { width: 20, height: 20, border: "2px solid #e5e7eb", borderTopColor: "#3b82f6", borderRadius: "50%", animation: "spin 0.8s linear infinite" },
};
