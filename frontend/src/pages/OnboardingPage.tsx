import { useState } from "react";
import { createApiKey } from "../lib/api";

type Step = "env" | "install" | "verify";
type Env = "server" | "web" | "api";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

type Props = { tenantId: string; onDone: () => void };

export function OnboardingPage({ tenantId, onDone }: Props) {
  const [step, setStep] = useState<Step>("env");
  const [env, setEnv] = useState<Env>("server");
  const [apiKey, setApiKey] = useState<string>("");
  const [generating, setGenerating] = useState(false);

  async function generateKey() {
    setGenerating(true);
    try {
      const res = await createApiKey(`${env} 연동 키`, env);
      setApiKey(res.api_key);
      setStep("install");
    } finally {
      setGenerating(false);
    }
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

          <button onClick={() => setStep("verify")} style={{
            marginTop: "1.5rem", width: "100%", padding: "12px",
            fontSize: 14, fontWeight: 500, cursor: "pointer",
            border: "0.5px solid var(--color-border-secondary)",
            borderRadius: "var(--border-radius-md)", background: "var(--color-text-primary)",
            color: "var(--color-background-primary)",
          }}>설치 완료했어요 →</button>
        </div>
      )}

      {/* Step 3: 연결 확인 */}
      {step === "verify" && (
        <div style={{ textAlign: "center", paddingTop: "2rem" }}>
          <div style={{ fontSize: 48, marginBottom: "1rem" }}>✅</div>
          <h2 style={{ fontSize: 18, fontWeight: 500, marginBottom: 8 }}>연결 설정 완료</h2>
          <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: "2rem" }}>
            첫 번째 이벤트가 수신되면 대시보드에 자동으로 표시됩니다.<br />
            서버 Agent는 30초 이내에 온라인 상태로 전환됩니다.
          </p>
          <button onClick={onDone} style={{
            padding: "12px 32px", fontSize: 14, fontWeight: 500, cursor: "pointer",
            border: "0.5px solid var(--color-border-secondary)",
            borderRadius: "var(--border-radius-md)", background: "var(--color-text-primary)",
            color: "var(--color-background-primary)",
          }}>대시보드로 이동</button>
        </div>
      )}
    </div>
  );
}
