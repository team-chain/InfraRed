import { FormEvent, useState } from "react";
import { MailCheck } from "lucide-react";
import { Logo } from "../components/Logo";

type Props = {
  onGoToLogin: () => void;
};

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

export function ForgotPasswordPage({ onGoToLogin }: Props) {
  const [email, setEmail] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(undefined);
    try {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          tenant_id: tenantId || undefined,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "요청 실패");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={submit}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}>
          <Logo height={48} />
        </div>
        <h1 style={{ textAlign: "center" }}>비밀번호 재설정</h1>
        {submitted ? (
          <div style={{ textAlign: "center", padding: "20px 0" }}>
            <MailCheck size={48} style={{ color: "var(--c-green-500, #16a34a)" }} />
            <p style={{ marginTop: 12 }}>
              해당 이메일이 등록되어 있다면 재설정 링크를 발송했습니다.
            </p>
            <p style={{ fontSize: 12, color: "var(--text-3)", marginTop: 8 }}>
              메일함을 확인해주세요. 링크는 1시간 동안 유효합니다.
            </p>
            <button type="button" className="primary-button" onClick={onGoToLogin} style={{ marginTop: 20 }}>
              로그인 화면으로
            </button>
          </div>
        ) : (
          <>
            <p style={{ fontSize: 13, color: "var(--text-3)", marginBottom: 16 }}>
              가입한 이메일을 입력하시면 재설정 링크를 보내드립니다.
            </p>
            {error && <div className="alert">{error}</div>}
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
            <label>
              Tenant (선택 — 여러 테넌트에 같은 이메일이 있을 때)
              <input
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                placeholder="비워두면 자동"
              />
            </label>
            <button className="primary-button" disabled={loading} type="submit">
              {loading ? "발송 중…" : "재설정 링크 받기"}
            </button>
            <p style={{ textAlign: "center", marginTop: 12, fontSize: 13 }}>
              <button
                type="button"
                onClick={onGoToLogin}
                style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer" }}
              >
                로그인으로 돌아가기
              </button>
            </p>
          </>
        )}
      </form>
    </main>
  );
}
