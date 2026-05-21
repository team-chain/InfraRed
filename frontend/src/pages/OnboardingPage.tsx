import { useEffect, useRef, useState } from "react";
import {
  createApiKey,
  completeOnboardingStep,
  fetchOnboardingStatus,
} from "../lib/api";

type Step = "env" | "install" | "verify";
type Env = "server" | "web" | "api";

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

type Props = { tenantId: string; onDone: () => void };

export function OnboardingPage({ tenantId, onDone }: Props) {
  const [step, setStep] = useState<Step>("env");
  const [env, setEnv] = useState<Env>("server");
  const [apiKey, setApiKey] = useState<string>("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | undefined>();

  // 연결 검증 상태
  const [verifyState, setVerifyState] = useState<"waiting" | "connected">("waiting");
  const [verifyStartedAt, setVerifyStartedAt] = useState<number | null>(null);
  const [elapsedSec, setElapsedSec] = useState(0);
  const pollRef = useRef<number | null>(null);
  const tickerRef = useRef<number | null>(null);

  async function generateKey() {
    setGenerating(true);
    setError(undefined);
    try {
      const res = await createApiKey(`${env} 연동 키`, env);
      setApiKey(res.api_key);
      // 백엔드에 step 1/2 완료 기록 (실패해도 흐름은 진행 — backend 미세팅 환경 대비)
      void completeOnboardingStep(1).catch(() => {});
      void completeOnboardingStep(2).catch(() => {});
      setStep("install");
    } catch (e) {
      setError(e instanceof Error ? e.message : "API Key 발급 실패");
    } finally {
      setGenerating(false);
    }
  }

  function goToVerify() {
    void completeOnboardingStep(3).catch(() => {});
    setStep("verify");
    setVerifyState("waiting");
    setVerifyStartedAt(Date.now());
  }

  // Step 3에서 백엔드 onboarding/status를 polling
  useEffect(() => {
    if (step !== "verify") return;
    if (verifyState === "connected") return;

    async function check() {
      try {
        const status = await fetchOnboardingStatus();
        if (status.agent_connected) {
          setVerifyState("connected");
          void completeOnboardingStep(4).catch(() => {});
          // step 5는 사용자가 "대시보드로 이동" 클릭 시 자동 호출
        }
      } catch {
        // 무시 — 다음 polling에서 재시도
      }
    }

    // 즉시 한 번, 이후 5초 간격
    check();
    pollRef.current = window.setInterval(check, 5000);

    // 경과 시간 표시 ticker
    tickerRef.current = window.setInterval(() => {
      if (verifyStartedAt !== null) {
        setElapsedSec(Math.floor((Date.now() - verifyStartedAt) / 1000));
      }
    }, 1000);

    return () => {
      if (pollRef.current !== null) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      if (tickerRef.current !== null) {
        window.clearInterval(tickerRef.current);
        tickerRef.current = null;
      }
    };
  }, [step, verifyState, verifyStartedAt]);

  function finish() {
    void completeOnboardingStep(5).catch(() => {});
    onDone();
  }

  return (
    <div style={{ maxWidth: 600, margin: "0 auto", padding: "2rem 1.5rem" }}>
      {/* 스텝 표시 */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: "2rem" }}>
        {(["env", "install", "verify"] as Step[]).map((s, i) => (
          <div key={s} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 28, height: 28, borderRadius: "50%", display: "flex",
              alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 500,
              background: step === s ? "var(--color-text-primary)" : "var(--color-background-secondary)",
              color: step === s ? "var(--color-background-primary)" : "var(--color-text-tertiary)",
              border: "0.5px solid var(--color-border-tertiary)",
            }}>{i + 1}</div>
            {i < 2 && <div style={{ width: 40, height: 1, background: "var(--color-border-tertiary)" }} />}
          </div>
        ))}
      </div>

      {error && (
        <div className="alert" style={{ marginBottom: 12 }}>
          {error}
        </div>
      )}

      {/* Step 1: 환경 선택 */}
      {step === "env" && (
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 500, marginBottom: 8 }}>어떤 환경을 연결하나요?</h2>
          <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: "1.5rem" }}>
            환경에 맞는 설치 방법을 안내해 드릴게요.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { value: "server", icon: "🖥", label: "Linux 서버", desc: "Auth.log, Nginx 로그 수집" },
              { value: "web", icon: "🌐", label: "웹사이트", desc: "방문자 보안 감지 (JS SDK)" },
              { value: "api", icon: "⚙️", label: "앱 / 백엔드 API", desc: "직접 이벤트 전송" },
            ].map(opt => (
              <button key={opt.value} onClick={() => setEnv(opt.value as Env)} style={{
                display: "flex", alignItems: "center", gap: 14,
                padding: "14px 16px", cursor: "pointer", textAlign: "left",
                border: env === opt.value ? "1.5px solid var(--color-border-primary)" : "0.5px solid var(--color-border-tertiary)",
                borderRadius: "var(--border-radius-lg)", background: "var(--color-background-primary)",
              }}>
                <span style={{ fontSize: 24 }}>{opt.icon}</span>
                <div>
                  <div style={{ fontWeight: 500, fontSize: 14 }}>{opt.label}</div>
                  <div style={{ fontSize: 12, color: "var(--color-text-secondary)", marginTop: 2 }}>{opt.desc}</div>
                </div>
              </button>
            ))}
          </div>
          <button onClick={generateKey} disabled={generating} style={{
            marginTop: "1.5rem", width: "100%", padding: "12px",
            fontSize: 14, fontWeight: 500, cursor: "pointer",
            border: "0.5px solid var(--color-border-secondary)",
            borderRadius: "var(--border-radius-md)", background: "var(--color-text-primary)",
            color: "var(--color-background-primary)",
          }}>{generating ? "API Key 발급 중..." : "다음"}</button>
          <button type="button" onClick={onDone} style={{
            marginTop: 10, width: "100%", padding: "8px",
            fontSize: 12, color: "var(--color-text-tertiary)",
            background: "none", border: "none", cursor: "pointer",
          }}>
            나중에 설정 — 대시보드로 바로 이동
          </button>
        </div>
      )}

      {/* Step 2: 설치 가이드 */}
      {step === "install" && (
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 500, marginBottom: 8 }}>
            {env === "server" ? "서버에 Agent 설치" : env === "web" ? "웹사이트에 SDK 추가" : "API 연동"}
          </h2>
          <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: "1.5rem" }}>
            아래 방법으로 연결하면 즉시 모니터링이 시작됩니다.
          </p>

          {env === "server" && (
            <div>
              <p style={{ fontSize: 13, marginBottom: 10 }}>서버 터미널에서 아래 명령어를 실행하세요.</p>
              <pre style={{
                background: "var(--color-background-secondary)", padding: "14px 16px",
                borderRadius: "var(--border-radius-md)", fontSize: 12,
                overflowX: "auto", lineHeight: 1.6,
              }}>{`curl -sSL ${API_BASE}/install-agent.sh | \\
  bash -s -- \\
  --token=${apiKey} \\
  --tenant=${tenantId}`}</pre>
            </div>
          )}

          {env === "web" && (
            <div>
              <p style={{ fontSize: 13, marginBottom: 10 }}>웹사이트 HTML의 <code>&lt;head&gt;</code> 안에 아래 코드를 추가하세요.</p>
              <pre style={{
                background: "var(--color-background-secondary)", padding: "14px 16px",
                borderRadius: "var(--border-radius-md)", fontSize: 12,
                overflowX: "auto", lineHeight: 1.6,
              }}>{`<script src="${API_BASE}/sdk.js"\n        data-token="${apiKey}"></script>`}</pre>
            </div>
          )}

          {env === "api" && (
            <div>
              <p style={{ fontSize: 13, marginBottom: 10 }}>이벤트 발생 시 아래 API로 전송하세요.</p>
              <pre style={{
                background: "var(--color-background-secondary)", padding: "14px 16px",
                borderRadius: "var(--border-radius-md)", fontSize: 12,
                overflowX: "auto", lineHeight: 1.6,
              }}>{`POST ${API_BASE}/ingest/event
X-Tenant-Token: ${apiKey}

{
  "event_type": "ssh_login_failed",
  "source_ip": "1.2.3.4",
  "username": "root"
}`}</pre>
            </div>
          )}

          <div style={{ marginTop: "1rem", padding: "10px 14px", background: "var(--color-background-warning)",
            borderRadius: "var(--border-radius-md)", fontSize: 12, color: "var(--color-text-warning)" }}>
            API Key: <code style={{ fontWeight: 500 }}>{apiKey}</code><br />
            이 키는 다시 확인할 수 없습니다. 안전한 곳에 보관하세요.
          </div>

          <button onClick={goToVerify} style={{
            marginTop: "1.5rem", width: "100%", padding: "12px",
            fontSize: 14, fontWeight: 500, cursor: "pointer",
            border: "0.5px solid var(--color-border-secondary)",
            borderRadius: "var(--border-radius-md)", background: "var(--color-text-primary)",
            color: "var(--color-background-primary)",
          }}>설치 완료했어요 → 연결 확인</button>
        </div>
      )}

      {/* Step 3: 연결 확인 — 실시간 polling으로 agent heartbeat 감지 */}
      {step === "verify" && (
        <div style={{ textAlign: "center", paddingTop: "2rem" }}>
          {verifyState === "waiting" ? (
            <>
              <div style={{
                display: "inline-block",
                width: 56, height: 56, borderRadius: "50%",
                border: "4px solid var(--color-background-secondary)",
                borderTopColor: "var(--color-text-primary)",
                animation: "spin 0.9s linear infinite",
                marginBottom: "1rem",
              }} />
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
              <h2 style={{ fontSize: 18, fontWeight: 500, marginBottom: 8 }}>Agent 연결 대기중…</h2>
              <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: "0.5rem" }}>
                서버에서 InfraRed Agent가 첫 heartbeat을 보내면 자동으로 감지됩니다.
              </p>
              <p style={{ fontSize: 12, color: "var(--color-text-tertiary)", marginBottom: "2rem" }}>
                경과 {elapsedSec}초 · 보통 30초 안에 연결됩니다
              </p>
              <button onClick={onDone} style={{
                padding: "10px 24px", fontSize: 13, fontWeight: 500, cursor: "pointer",
                border: "0.5px solid var(--color-border-tertiary)",
                borderRadius: "var(--border-radius-md)",
                background: "transparent", color: "var(--color-text-secondary)",
              }}>건너뛰고 대시보드로 이동</button>
            </>
          ) : (
            <>
              <div style={{ fontSize: 48, marginBottom: "1rem" }}>✅</div>
              <h2 style={{ fontSize: 18, fontWeight: 500, marginBottom: 8 }}>Agent 연결 완료</h2>
              <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: "2rem" }}>
                첫 heartbeat 수신됨. 이제부터 이벤트가 자동으로 수집되고 분석됩니다.
              </p>
              <button onClick={finish} style={{
                padding: "12px 32px", fontSize: 14, fontWeight: 500, cursor: "pointer",
                border: "0.5px solid var(--color-border-secondary)",
                borderRadius: "var(--border-radius-md)", background: "var(--color-text-primary)",
                color: "var(--color-background-primary)",
              }}>대시보드로 이동</button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
