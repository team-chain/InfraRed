import { useEffect, useRef, useState } from "react";
import { Server, Globe, Code2, CheckCircle2 } from "lucide-react";
import {
  createApiKey,
  completeOnboardingStep,
  fetchOnboardingStatus,
} from "../lib/api";

type Step = "env" | "install" | "verify";
type Env = "server" | "web" | "api";
type OsTab = "auto" | "ubuntu" | "rhel" | "docker";

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

// 명령어 표시용 절대 URL — 빈 값일 때 사용자가 복사해 갈 수 있도록 https://api.infrared.kr 폴백
function displayBase(apiBase: string): string {
  return apiBase || "https://api.infrared.kr";
}

function installCommand(tab: OsTab, apiKey: string, tenantId: string, apiBase: string): string {
  const base = displayBase(apiBase);
  if (tab === "docker") {
    return `docker run -d --name infrared-agent --restart=always \\
  --network host \\
  -e TENANT_ID=${tenantId} \\
  -e AGENT_TOKEN=${apiKey} \\
  -e BACKEND_URL=${base}/ingest \\
  -e HEARTBEAT_URL=${base}/heartbeat \\
  -e AGENT_ID=$(hostname)-agent \\
  -e ASSET_ID=$(hostname) \\
  -v /var/log:/host/var/log:ro \\
  -v infrared-data:/var/lib/infrared \\
  ghcr.io/infrared-kr/agent:latest`;
  }
  // auto / ubuntu / rhel — 동일 명령. install.sh가 OS 자동 감지.
  return `curl -fsSL "${base}/install-agent.sh" | sudo bash -s -- \\
  --token "${apiKey}" \\
  --tenant "${tenantId}"`;
}

function osHint(tab: OsTab): string {
  switch (tab) {
    case "ubuntu":
      return "Ubuntu 18.04+ / Debian 10+ 에서 검증. apt-get 자동 사용.";
    case "rhel":
      return "RHEL 8+ · CentOS 8+ · Amazon Linux 2/2023 · Rocky · AlmaLinux. yum 자동 사용.";
    case "docker":
      return "이미지 publish 준비 중 — 현재는 자동 감지 / Ubuntu·Debian / RHEL 탭을 사용해주세요.";
    case "auto":
    default:
      return "OS를 자동 감지 후 백엔드에서 agent 코드를 내려받아 Python venv 모드로 설치.";
  }
}

type Props = { tenantId: string; onDone: () => void };

export function OnboardingPage({ tenantId, onDone }: Props) {
  const [step, setStep] = useState<Step>("env");
  const [env, setEnv] = useState<Env>("server");
  const [osTab, setOsTab] = useState<OsTab>("auto");
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
              { value: "server" as Env, Icon: Server, label: "Linux 서버", desc: "Auth.log, Nginx 로그 수집" },
              { value: "web" as Env, Icon: Globe, label: "웹사이트", desc: "방문자 보안 감지 (JS SDK)" },
              { value: "api" as Env, Icon: Code2, label: "앱 / 백엔드 API", desc: "직접 이벤트 전송" },
            ].map(opt => {
              const Icon = opt.Icon;
              const active = env === opt.value;
              return (
                <button key={opt.value} onClick={() => setEnv(opt.value)} style={{
                  display: "flex", alignItems: "center", gap: 14,
                  padding: "14px 16px", cursor: "pointer", textAlign: "left",
                  border: active ? "1.5px solid var(--brand-primary)" : "1px solid var(--border)",
                  borderRadius: "var(--r-lg)", background: "var(--surface)",
                  transition: "border-color .15s, background .15s",
                }}>
                  <span style={{
                    width: 40, height: 40, borderRadius: "var(--r-md)",
                    background: active ? "var(--c-orange-50)" : "var(--c-gray-50)",
                    color: active ? "var(--brand-primary-dark)" : "var(--text-2)",
                    display: "inline-flex", alignItems: "center", justifyContent: "center",
                    flexShrink: 0,
                  }}>
                    <Icon size={20} strokeWidth={1.75} />
                  </span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{opt.label}</div>
                    <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2 }}>{opt.desc}</div>
                  </div>
                </button>
              );
            })}
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
              <p style={{ fontSize: 13, marginBottom: 10 }}>서버 환경을 선택하면 맞춤 명령을 보여드려요.</p>

              {/* OS 탭 */}
              <div style={{
                display: "flex", gap: 2, marginBottom: 10,
                borderBottom: "1px solid var(--color-border-tertiary)",
                flexWrap: "wrap",
              }}>
                {([
                  { value: "auto", label: "자동 감지" },
                  { value: "ubuntu", label: "Ubuntu / Debian" },
                  { value: "rhel", label: "RHEL · Amazon Linux" },
                  { value: "docker", label: "Docker (Preview)" },
                ] as { value: OsTab; label: string }[]).map(t => {
                  const active = osTab === t.value;
                  return (
                    <button key={t.value} onClick={() => setOsTab(t.value)} style={{
                      padding: "8px 12px", fontSize: 12, fontWeight: 500, cursor: "pointer",
                      background: "transparent", border: "none",
                      borderBottom: active ? "2px solid var(--color-text-primary)" : "2px solid transparent",
                      color: active ? "var(--color-text-primary)" : "var(--color-text-tertiary)",
                      marginBottom: -1,
                    }}>{t.label}</button>
                  );
                })}
              </div>

              {/* Docker 탭 경고 — 이미지 publish 전 */}
              {osTab === "docker" && (
                <div style={{
                  background: "var(--color-background-warning)",
                  color: "var(--color-text-warning)",
                  padding: "10px 14px",
                  borderRadius: "var(--border-radius-md)",
                  fontSize: 12,
                  marginBottom: 10,
                  lineHeight: 1.5,
                }}>
                  ⚠️ Docker 이미지가 아직 public publish 전입니다. 아래 명령은 미리보기용이며,
                  안정 사용을 원하시면 <strong>자동 감지</strong> 또는 <strong>Ubuntu</strong> · <strong>RHEL</strong> 탭을 사용해주세요.
                </div>
              )}

              {/* 명령어 박스 */}
              <pre style={{
                background: "var(--color-background-secondary)", padding: "14px 16px",
                borderRadius: "var(--border-radius-md)", fontSize: 12,
                overflowX: "auto", lineHeight: 1.6, margin: 0,
              }}>{installCommand(osTab, apiKey, tenantId, API_BASE)}</pre>

              {/* OS별 짧은 힌트 */}
              <p style={{
                fontSize: 11, color: "var(--color-text-tertiary)",
                marginTop: 6, marginBottom: 0,
              }}>
                {osHint(osTab)}
              </p>

              {/* 펼침: 이 명령이 무엇을 하나요 */}
              <details style={{ marginTop: 12, fontSize: 12 }}>
                <summary style={{
                  cursor: "pointer", color: "var(--color-text-secondary)",
                  padding: "6px 0", userSelect: "none",
                }}>
                  이 명령이 무엇을 하나요?
                </summary>
                <ol style={{
                  paddingLeft: 20, marginTop: 6,
                  color: "var(--color-text-secondary)", lineHeight: 1.7,
                }}>
                  <li><strong>설치 스크립트 다운로드</strong> — InfraRed 서버에서 <code>install-agent.sh</code> 를 가져옵니다.</li>
                  <li><strong>실행 환경 결정</strong> — Docker가 이미 깔려 있으면 컨테이너 모드, 아니면 Python venv 모드로 자동 선택.</li>
                  <li><strong>의존성 설치</strong> — 패키지 매니저(apt / yum)로 필요한 도구를 자동 설치.</li>
                  <li><strong>환경 파일 작성</strong> — <code>/opt/infrared-agent/.env</code> 에 토큰·테넌트·서버 주소 저장 (권한 600).</li>
                  <li><strong>systemd 서비스 등록</strong> — <code>infrared-agent</code> 가 자동 시작·재시작되도록 설정.</li>
                  <li><strong>첫 heartbeat 전송</strong> — 보통 30초 안에 이 화면이 자동으로 "✅ 연결 완료" 로 바뀝니다.</li>
                </ol>
              </details>

              {/* 펼침: 트러블슈팅 */}
              <details style={{ marginTop: 4, fontSize: 12 }}>
                <summary style={{
                  cursor: "pointer", color: "var(--color-text-secondary)",
                  padding: "6px 0", userSelect: "none",
                }}>
                  설치가 안 되거나 5분 넘게 연결이 안 될 때
                </summary>
                <div style={{
                  paddingLeft: 8, marginTop: 6,
                  color: "var(--color-text-secondary)", lineHeight: 1.7,
                }}>
                  <p style={{ margin: "4px 0" }}>1. 에이전트 로그 확인:</p>
                  <pre style={{
                    background: "var(--color-background-secondary)", padding: "8px 12px",
                    borderRadius: "var(--border-radius-md)", fontSize: 11, margin: "4px 0",
                  }}>sudo journalctl -u infrared-agent -n 80 --no-pager</pre>
                  <p style={{ margin: "4px 0" }}>2. 서비스 상태:</p>
                  <pre style={{
                    background: "var(--color-background-secondary)", padding: "8px 12px",
                    borderRadius: "var(--border-radius-md)", fontSize: 11, margin: "4px 0",
                  }}>sudo systemctl status infrared-agent</pre>
                  <p style={{ margin: "4px 0" }}>3. 백엔드 도달 가능 여부:</p>
                  <pre style={{
                    background: "var(--color-background-secondary)", padding: "8px 12px",
                    borderRadius: "var(--border-radius-md)", fontSize: 11, margin: "4px 0",
                  }}>{`curl -I ${displayBase(API_BASE)}/heartbeat`}</pre>
                  <p style={{ margin: "8px 0 0 0", fontSize: 11 }}>
                    그래도 막히면 위 로그를 첨부해서 알려주세요.
                  </p>
                </div>
              </details>
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
              <div style={{
                width: 64, height: 64, borderRadius: "50%",
                background: "var(--c-green-50)", color: "var(--c-green-600)",
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                marginBottom: "1rem",
              }}>
                <CheckCircle2 size={36} strokeWidth={2} />

              </div>
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
