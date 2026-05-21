import { FormEvent, useState } from "react";
import { Siren, KeyRound, CheckCircle2 } from "lucide-react";

type Props = {
  token: string;
  onDone: () => void;
};

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

export function ResetPasswordPage({ token, onDone }: Props) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (password !== confirm) {
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
      const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      const data = await res.json();
      if (!res.ok) {
        const detail = (data && data.detail) || `HTTP ${res.status}`;
        if (detail === "invalid_or_expired_token" || detail === "token_expired") {
          throw new Error("링크가 만료되었거나 잘못되었습니다. 다시 요청해주세요.");
        }
        throw new Error(detail);
      }
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "재설정 실패");
    } finally {
      setLoading(false);
    }
  }

  if (done) {
    return (
      <main className="login-shell">
        <div className="login-panel" style={{ textAlign: "center" }}>
          <span className="brand"><Siren size={20} /> InfraRed SOC</span>
          <h1>비밀번호 변경 완료</h1>
          <CheckCircle2 size={48} style={{ color: "var(--c-green-500, #16a34a)", margin: "20px auto" }} />
          <p>새 비밀번호로 로그인해주세요.</p>
          <button className="primary-button" onClick={onDone} style={{ marginTop: 20 }}>
            로그인 화면으로
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={submit}>
        <span className="brand"><Siren size={20} /> InfraRed SOC</span>
        <h1>새 비밀번호 설정</h1>
        {error && <div className="alert">{error}</div>}
        <label>
          새 비밀번호
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="8자 이상"
            required
            autoFocus
          />
        </label>
        <label>
          비밀번호 확인
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>
        <button className="primary-button" disabled={loading} type="submit">
          <KeyRound size={18} />
          {loading ? "변경 중…" : "비밀번호 변경"}
        </button>
      </form>
    </main>
  );
}
