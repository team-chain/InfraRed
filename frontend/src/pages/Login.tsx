import { FormEvent, useState } from "react";
import { LogIn } from "lucide-react";
import { AuthSidePanel } from "../components/AuthSidePanel";
import { Logo } from "../components/Logo";
import { login, type AuthUser } from "../lib/api";

type Props = {
  onLogin: (user: AuthUser) => void;
  onGoToRegister?: () => void;
  onForgotPassword?: () => void;
};

export function LoginPage({ onLogin, onGoToRegister, onForgotPassword }: Props) {
  const [tenantId, setTenantId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(undefined);
    try {
      const result = await login(tenantId, email, password);
      onLogin(result.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "로그인에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-split">
      <AuthSidePanel variant="login" />

      <section className="auth-form-side">
        <form className="auth-form-panel" onSubmit={submit}>
          <div style={{ marginBottom: 12 }}>
            <Logo height={36} />
          </div>
          <div>
            <h1>로그인</h1>
            <p className="auth-form-panel-sub">
              계정으로 로그인하고 인시던트 대시보드를 확인하세요.
            </p>
          </div>

          {error && <div className="auth-form-error">{error}</div>}

          <label>
            조직 ID
            <input
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="my-company"
              autoComplete="organization"
              required
            />
          </label>
          <label>
            이메일
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              autoComplete="email"
              required
            />
          </label>
          <label>
            비밀번호
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder=""
              autoComplete="current-password"
              required
            />
          </label>

          <button className="auth-form-btn" disabled={loading} type="submit">
            <LogIn size={16} />
            {loading ? "로그인 중..." : "로그인"}
          </button>

          {onForgotPassword && (
            <p className="auth-form-muted" style={{ marginTop: 4 }}>
              <button
                type="button"
                onClick={onForgotPassword}
                className="auth-form-link"
                style={{ color: "var(--text-2)", fontWeight: 500 }}
              >
                비밀번호를 잊으셨나요?
              </button>
            </p>
          )}

          {onGoToRegister && (
            <>
              <div className="auth-form-divider" />
              <p className="auth-form-muted">
                아직 계정이 없으신가요?{" "}
                <button
                  type="button"
                  onClick={onGoToRegister}
                  className="auth-form-link"
                >
                  무료로 시작하기
                </button>
              </p>
            </>
          )}
        </form>
      </section>
    </main>
  );
}
