import { FormEvent, useState } from "react";
import { LogIn, Siren } from "lucide-react";
import { login, type AuthUser } from "../lib/api";

type Props = {
  onLogin: (token: string, user: AuthUser) => void;
  onGoToRegister: () => void;
};

export function LoginPage({ onLogin, onGoToRegister }: Props) {
  const [tenantId, setTenantId] = useState("company-a");
  const [email, setEmail] = useState("admin@infrared.local");
  const [password, setPassword] = useState("infrared123");
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(undefined);
    try {
      const result = await login(tenantId, email, password);
      onLogin(result.access_token, result.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={submit}>
        <span className="brand"><Siren size={20} /> InfraRed SOC</span>
        <h1>Analyst Sign In</h1>
        {error && <div className="alert">{error}</div>}
        <label>
          Tenant
          <input value={tenantId} onChange={(event) => setTenantId(event.target.value)} />
        </label>
        <label>
          Email
          <input value={email} onChange={(event) => setEmail(event.target.value)} />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <button className="primary-button" disabled={loading} type="submit">
          <LogIn size={18} />
          {loading ? "Signing in" : "Sign in"}
        </button>
        <p style={{ textAlign: "center", marginTop: "0.75rem", fontSize: "0.875rem" }}>
          계정이 없으신가요?{" "}
          <button
            type="button"
            onClick={onGoToRegister}
            style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}
          >
            회원가입
          </button>
        </p>
      </form>
    </main>
  );
}
