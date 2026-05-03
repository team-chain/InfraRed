import { FormEvent, useState } from "react";
import { UserPlus, Siren } from "lucide-react";
import { register, type AuthUser } from "../lib/api";

type Props = {
  onRegister: (token: string, user: AuthUser) => void;
  onGoToLogin: () => void;
};

export function RegisterPage({ onRegister, onGoToLogin }: Props) {
  const [tenantId, setTenantId] = useState("company-a");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password !== confirmPassword) {
      setError("비밀번호가 일치하지 않습니다.");
      return;
    }
    if (password.length < 8) {
      setError("비밀번호는 8자 이상이어야 합니다.");
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      const result = await register(tenantId, email, password, role);
      onRegister(result.access_token, result.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={submit}>
        <span className="brand"><Siren size={20} /> InfraRed SOC</span>
        <h1>계정 만들기</h1>
        {error && <div className="alert">{error}</div>}
        <label>
          Tenant
          <input value={tenantId} onChange={(e) => setTenantId(e.target.value)} required />
        </label>
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
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="8자 이상"
            required
          />
        </label>
        <label>
          Password 확인
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <button className="primary-button" disabled={loading} type="submit">
          <UserPlus size={18} />
          {loading ? "Creating account..." : "계정 만들기"}
        </button>
        <p style={{ textAlign: "center", marginTop: "0.75rem", fontSize: "0.875rem" }}>
          이미 계정이 있으신가요?{" "}
          <button
            type="button"
            onClick={onGoToLogin}
            style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}
          >
            로그인
          </button>
        </p>
      </form>
    </main>
  );
}
