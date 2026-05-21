import { useEffect, useState } from "react";
import { Siren, CheckCircle2, AlertTriangle } from "lucide-react";

type Props = {
  token: string;
  onDone: () => void;
};

const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_BASE_URL ?? "");

export function VerifyEmailPage({ token, onDone }: Props) {
  const [state, setState] = useState<"verifying" | "ok" | "error">("verifying");
  const [message, setMessage] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/verify-email/${encodeURIComponent(token)}`, {
          method: "GET",
        });
        const data = await res.json();
        if (res.ok && (data.status === "verified" || data.status === "already_verified")) {
          setState("ok");
          setMessage(data.email ? `${data.email} 인증 완료` : "이메일 인증 완료");
        } else {
          setState("error");
          setMessage(data.detail || "인증 실패");
        }
      } catch (e) {
        setState("error");
        setMessage(e instanceof Error ? e.message : "네트워크 오류");
      }
    })();
  }, [token]);

  return (
    <main className="login-shell">
      <div className="login-panel" style={{ textAlign: "center" }}>
        <span className="brand"><Siren size={20} /> InfraRed SOC</span>
        <h1>이메일 인증</h1>
        {state === "verifying" && <p>확인 중…</p>}
        {state === "ok" && (
          <div style={{ marginTop: 20 }}>
            <CheckCircle2 size={48} style={{ color: "var(--c-green-500, #16a34a)" }} />
            <p style={{ marginTop: 12 }}>{message}</p>
          </div>
        )}
        {state === "error" && (
          <div style={{ marginTop: 20 }}>
            <AlertTriangle size={48} style={{ color: "var(--c-red-500, #dc2626)" }} />
            <p style={{ marginTop: 12 }}>{message}</p>
            <p style={{ fontSize: 12, color: "var(--text-3)" }}>
              링크가 만료되었거나 잘못되었을 수 있습니다. 로그인 후 재발송하세요.
            </p>
          </div>
        )}
        <button className="primary-button" onClick={onDone} style={{ marginTop: 20 }}>
          로그인 화면으로
        </button>
      </div>
    </main>
  );
}
