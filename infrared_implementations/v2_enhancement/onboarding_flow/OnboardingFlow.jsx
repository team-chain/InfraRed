/**
 * InfraRed v2 — 온보딩 플로우
 * 고도화_설계서_v2.0.docx Phase 2-D
 *
 * 신규 테넌트 가입부터 에이전트 설치 완료까지 4단계 가이드:
 *   Step 1: 조직 정보 입력 (회사명, 담당자)
 *   Step 2: 알림 채널 설정 (Discord/Slack/이메일)
 *   Step 3: 에이전트 설치 가이드 (토큰 발급 + 설치 스크립트)
 *   Step 4: 첫 신호 수신 확인 + 완료
 */

import { useState, useEffect, useRef } from "react";

// ─────────────────────────────────────────────────────────────
// 상수
// ─────────────────────────────────────────────────────────────
const STEPS = [
  { id: 1, title: "조직 정보",      icon: "🏢" },
  { id: 2, title: "알림 채널",      icon: "🔔" },
  { id: 3, title: "에이전트 설치",  icon: "🤖" },
  { id: 4, title: "설치 확인",      icon: "✅" },
];

// ─────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────
async function saveOrgInfo(tenantId, data) {
  const r = await fetch("/api/v1/onboarding/org", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function saveNotifications(tenantId, data) {
  const r = await fetch("/api/v1/onboarding/notifications", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
    body: JSON.stringify(data),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function generateAgentToken(tenantId) {
  const r = await fetch("/api/v1/onboarding/agent-token", {
    method: "POST",
    headers: { "X-Tenant-ID": tenantId },
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function checkFirstSignal(tenantId) {
  const r = await fetch("/api/v1/onboarding/check-signal", {
    headers: { "X-Tenant-ID": tenantId },
  });
  return r.json();
}

// ─────────────────────────────────────────────────────────────
// Step 컴포넌트
// ─────────────────────────────────────────────────────────────
function Step1OrgInfo({ tenantId, onNext }) {
  const [form, setForm] = useState({ company: "", contact_name: "", contact_email: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  const submit = async () => {
    if (!form.company || !form.contact_email) { setError("회사명과 이메일을 입력해주세요."); return; }
    setLoading(true);
    try {
      await saveOrgInfo(tenantId, form);
      onNext();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div style={styles.stepContent}>
      <h3 style={styles.stepTitle}>🏢 조직 정보를 입력해주세요</h3>
      <p style={styles.stepDesc}>InfraRed를 사용할 조직 정보를 등록합니다.</p>
      <div style={styles.formGroup}>
        <label style={styles.label}>회사/조직명 *</label>
        <input style={styles.input} value={form.company}
          onChange={e => setForm(p => ({ ...p, company: e.target.value }))} placeholder="예: (주)보안테크" />
      </div>
      <div style={styles.formGroup}>
        <label style={styles.label}>담당자 이름</label>
        <input style={styles.input} value={form.contact_name}
          onChange={e => setForm(p => ({ ...p, contact_name: e.target.value }))} placeholder="홍길동" />
      </div>
      <div style={styles.formGroup}>
        <label style={styles.label}>담당자 이메일 *</label>
        <input style={styles.input} type="email" value={form.contact_email}
          onChange={e => setForm(p => ({ ...p, contact_email: e.target.value }))} placeholder="security@company.com" />
      </div>
      {error && <div style={styles.error}>{error}</div>}
      <button style={styles.nextBtn} onClick={submit} disabled={loading}>
        {loading ? "저장 중..." : "다음 →"}
      </button>
    </div>
  );
}

function Step2Notifications({ tenantId, onNext, onBack }) {
  const [discord, setDiscord] = useState("");
  const [slack,   setSlack]   = useState("");
  const [email,   setEmail]   = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setLoading(true);
    try {
      await saveNotifications(tenantId, { discord_webhook: discord, slack_webhook: slack, email });
      onNext();
    } catch {}
    finally { setLoading(false); }
  };

  return (
    <div style={styles.stepContent}>
      <h3 style={styles.stepTitle}>🔔 알림 채널 설정</h3>
      <p style={styles.stepDesc}>보안 이벤트 발생 시 알림을 받을 채널을 설정합니다. 나중에 변경 가능합니다.</p>
      <div style={styles.formGroup}>
        <label style={styles.label}>Discord Webhook URL</label>
        <input style={styles.input} value={discord}
          onChange={e => setDiscord(e.target.value)} placeholder="https://discord.com/api/webhooks/..." />
        <span style={styles.hint}>Discord 채널 편집 → 통합 → 웹후크에서 URL을 복사하세요</span>
      </div>
      <div style={styles.formGroup}>
        <label style={styles.label}>Slack Webhook URL</label>
        <input style={styles.input} value={slack}
          onChange={e => setSlack(e.target.value)} placeholder="https://hooks.slack.com/services/..." />
      </div>
      <div style={styles.formGroup}>
        <label style={styles.label}>알림 이메일</label>
        <input style={styles.input} type="email" value={email}
          onChange={e => setEmail(e.target.value)} placeholder="alert@company.com" />
      </div>
      <div style={styles.btnRow}>
        <button style={styles.backBtn} onClick={onBack}>← 이전</button>
        <button style={styles.nextBtn} onClick={submit} disabled={loading}>
          {loading ? "저장 중..." : "다음 →"}
        </button>
      </div>
    </div>
  );
}

function Step3AgentInstall({ tenantId, onNext, onBack }) {
  const [token,   setToken]   = useState("");
  const [loading, setLoading] = useState(true);
  const [copied,  setCopied]  = useState(false);

  useEffect(() => {
    generateAgentToken(tenantId)
      .then(d => setToken(d.token))
      .catch(() => setToken("TOKEN_GENERATION_FAILED"))
      .finally(() => setLoading(false));
  }, [tenantId]);

  const installCmd = `# InfraRed 에이전트 설치 (1줄 설치)
curl -fsSL https://install.infrared.io/agent | \\
  INFRARED_TOKEN="${token}" \\
  INFRARED_API_URL="https://your-infrared.example.com" \\
  bash

# 또는 Docker로 설치
docker run -d \\
  --name infrared-agent \\
  --restart unless-stopped \\
  --pid host \\
  --network host \\
  -v /var/log:/var/log:ro \\
  -v /proc:/proc:ro \\
  -e INFRARED_TOKEN="${token}" \\
  -e INFRARED_API_URL="https://your-infrared.example.com" \\
  infrared/agent:latest`;

  const copyCmd = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={styles.stepContent}>
      <h3 style={styles.stepTitle}>🤖 에이전트 설치</h3>
      <p style={styles.stepDesc}>
        모니터링할 서버에서 아래 명령어를 실행하세요.
        에이전트는 root 권한으로 실행되어야 합니다.
      </p>
      {loading ? (
        <div style={styles.tokenLoading}>토큰 생성 중...</div>
      ) : (
        <>
          <div style={styles.tokenBox}>
            <span style={styles.tokenLabel}>에이전트 토큰</span>
            <code style={styles.token}>{token}</code>
          </div>
          <div style={styles.codeBox}>
            <div style={styles.codeHeader}>
              <span>설치 명령어</span>
              <button style={styles.copyBtn} onClick={copyCmd}>
                {copied ? "✓ 복사됨" : "복사"}
              </button>
            </div>
            <pre style={styles.code}>{installCmd}</pre>
          </div>
          <div style={styles.infoBox}>
            <strong>📋 요구사항:</strong>
            <ul style={{ margin: "8px 0 0", paddingLeft: 20, fontSize: 13 }}>
              <li>Ubuntu 20.04+ / Debian 11+ / RHEL 8+ / CentOS 8+</li>
              <li>root 또는 sudo 권한</li>
              <li>아웃바운드 HTTPS (443) 허용</li>
              <li>Docker (Docker 설치 방식)</li>
            </ul>
          </div>
        </>
      )}
      <div style={styles.btnRow}>
        <button style={styles.backBtn} onClick={onBack}>← 이전</button>
        <button style={styles.nextBtn} onClick={onNext}>설치했습니다 →</button>
      </div>
    </div>
  );
}

function Step4Verify({ tenantId, onComplete, onBack }) {
  const [status,  setStatus]  = useState("waiting");  // waiting | success | timeout
  const [seconds, setSeconds] = useState(0);
  const intervalRef = useRef(null);

  useEffect(() => {
    // 30초마다 첫 신호 수신 확인
    const poll = async () => {
      const result = await checkFirstSignal(tenantId).catch(() => ({ received: false }));
      if (result.received) {
        setStatus("success");
        clearInterval(intervalRef.current);
      }
    };
    poll();
    intervalRef.current = setInterval(poll, 10_000);

    // 카운터
    const counter = setInterval(() => setSeconds(s => s + 1), 1000);

    // 5분 후 타임아웃
    const timeout = setTimeout(() => {
      setStatus("timeout");
      clearInterval(intervalRef.current);
      clearInterval(counter);
    }, 300_000);

    return () => {
      clearInterval(intervalRef.current);
      clearInterval(counter);
      clearTimeout(timeout);
    };
  }, [tenantId]);

  return (
    <div style={styles.stepContent}>
      <h3 style={styles.stepTitle}>✅ 설치 확인</h3>

      {status === "waiting" && (
        <>
          <div style={styles.waitingBox}>
            <div style={styles.spinner} />
            <div>
              <div style={{ fontWeight: 600 }}>에이전트 신호를 기다리는 중...</div>
              <div style={{ color: "#9ca3af", fontSize: 13, marginTop: 4 }}>
                {seconds}초 경과 · 에이전트 설치 후 30~60초 내에 신호가 도착합니다
              </div>
            </div>
          </div>
          <div style={{ textAlign: "center", marginTop: 16 }}>
            <button style={styles.skipBtn} onClick={onComplete}>나중에 확인하기</button>
          </div>
        </>
      )}

      {status === "success" && (
        <div style={styles.successBox}>
          <div style={{ fontSize: 48 }}>🎉</div>
          <h4 style={{ margin: "12px 0 8px" }}>에이전트 연결 성공!</h4>
          <p style={{ color: "#6b7280", margin: 0 }}>
            InfraRed가 서버를 모니터링하기 시작했습니다.
          </p>
          <button style={{ ...styles.nextBtn, marginTop: 20 }} onClick={onComplete}>
            대시보드로 이동 →
          </button>
        </div>
      )}

      {status === "timeout" && (
        <div style={styles.timeoutBox}>
          <div style={{ fontSize: 32 }}>⏱️</div>
          <h4>신호를 받지 못했습니다</h4>
          <p style={{ color: "#6b7280" }}>
            에이전트가 제대로 설치됐는지 확인해주세요.
            설치 로그: <code>journalctl -u infrared-agent -f</code>
          </p>
          <div style={styles.btnRow}>
            <button style={styles.backBtn} onClick={onBack}>← 이전 단계로</button>
            <button style={styles.nextBtn} onClick={onComplete}>그냥 완료하기</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// 메인
// ─────────────────────────────────────────────────────────────
export default function OnboardingFlow({ tenantId = "default", onComplete }) {
  const [step, setStep] = useState(1);

  const next = () => setStep(s => Math.min(s + 1, 4));
  const back = () => setStep(s => Math.max(s - 1, 1));

  const handleComplete = () => {
    fetch("/api/v1/onboarding/complete", {
      method: "POST",
      headers: { "X-Tenant-ID": tenantId },
    }).finally(() => onComplete?.());
  };

  return (
    <div style={styles.container}>
      {/* 진행 표시기 */}
      <div style={styles.stepper}>
        {STEPS.map((s, i) => (
          <div key={s.id} style={{ display: "flex", alignItems: "center" }}>
            <div style={{
              ...styles.stepCircle,
              background: step > s.id ? "#10b981" : step === s.id ? "#3b82f6" : "#e5e7eb",
              color:       step >= s.id ? "white" : "#9ca3af",
            }}>
              {step > s.id ? "✓" : s.icon}
            </div>
            <span style={{ ...styles.stepLabel, color: step >= s.id ? "#111827" : "#9ca3af" }}>
              {s.title}
            </span>
            {i < STEPS.length - 1 && (
              <div style={{ ...styles.stepLine, background: step > s.id ? "#10b981" : "#e5e7eb" }} />
            )}
          </div>
        ))}
      </div>

      {/* 단계 콘텐츠 */}
      <div style={styles.card}>
        {step === 1 && <Step1OrgInfo  tenantId={tenantId} onNext={next} />}
        {step === 2 && <Step2Notifications tenantId={tenantId} onNext={next} onBack={back} />}
        {step === 3 && <Step3AgentInstall  tenantId={tenantId} onNext={next} onBack={back} />}
        {step === 4 && <Step4Verify   tenantId={tenantId} onComplete={handleComplete} onBack={back} />}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
const styles = {
  container:    { maxWidth: 680, margin: "0 auto", padding: 24, fontFamily: "system-ui, sans-serif" },
  stepper:      { display: "flex", alignItems: "center", marginBottom: 32, justifyContent: "center", gap: 0 },
  stepCircle:   { width: 36, height: 36, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, flexShrink: 0 },
  stepLabel:    { fontSize: 12, fontWeight: 500, marginLeft: 6, marginRight: 4, whiteSpace: "nowrap" },
  stepLine:     { height: 2, width: 40, flexShrink: 0, margin: "0 4px" },
  card:         { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 12, padding: 32, boxShadow: "0 4px 20px rgba(0,0,0,0.06)" },
  stepContent:  {},
  stepTitle:    { margin: "0 0 8px", fontSize: 20, fontWeight: 700 },
  stepDesc:     { color: "#6b7280", margin: "0 0 24px", fontSize: 14, lineHeight: 1.6 },
  formGroup:    { marginBottom: 20 },
  label:        { display: "block", fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 6 },
  input:        { width: "100%", padding: "10px 12px", border: "1px solid #d1d5db", borderRadius: 8, fontSize: 14, boxSizing: "border-box" },
  hint:         { display: "block", fontSize: 12, color: "#9ca3af", marginTop: 4 },
  error:        { color: "#dc2626", fontSize: 13, marginBottom: 16 },
  nextBtn:      { padding: "10px 28px", background: "#3b82f6", color: "white", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 15, fontWeight: 600 },
  backBtn:      { padding: "10px 20px", background: "#f3f4f6", border: "none", borderRadius: 8, cursor: "pointer", fontSize: 14 },
  skipBtn:      { padding: "8px 20px", background: "none", border: "1px solid #d1d5db", borderRadius: 8, cursor: "pointer", fontSize: 13, color: "#6b7280" },
  btnRow:       { display: "flex", justifyContent: "space-between", marginTop: 24 },
  tokenBox:     { background: "#f0fdf4", border: "1px solid #86efac", borderRadius: 8, padding: 12, marginBottom: 16, display: "flex", alignItems: "center", gap: 12 },
  tokenLabel:   { fontSize: 12, color: "#065f46", fontWeight: 600 },
  token:        { fontFamily: "monospace", fontSize: 13, color: "#065f46", wordBreak: "break-all" },
  tokenLoading: { color: "#9ca3af", padding: 20, textAlign: "center" },
  codeBox:      { background: "#1e293b", borderRadius: 8, marginBottom: 16, overflow: "hidden" },
  codeHeader:   { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 14px", background: "#334155" },
  copyBtn:      { padding: "4px 12px", background: "#475569", color: "white", border: "none", borderRadius: 4, cursor: "pointer", fontSize: 12 },
  code:         { margin: 0, padding: 16, color: "#e2e8f0", fontSize: 12, lineHeight: 1.7, overflowX: "auto" },
  infoBox:      { background: "#eff6ff", border: "1px solid #bfdbfe", borderRadius: 8, padding: 14, fontSize: 13, color: "#1e40af" },
  waitingBox:   { display: "flex", alignItems: "center", gap: 16, padding: 24, background: "#f9fafb", borderRadius: 8 },
  spinner:      { width: 32, height: 32, border: "3px solid #e5e7eb", borderTopColor: "#3b82f6", borderRadius: "50%", animation: "spin 1s linear infinite", flexShrink: 0 },
  successBox:   { textAlign: "center", padding: 32 },
  timeoutBox:   { textAlign: "center", padding: 24 },
};
