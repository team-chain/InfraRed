import { FormEvent, useEffect, useMemo, useState } from "react";
import { UserPlus, MailCheck } from "lucide-react";
import { AuthSidePanel } from "../components/AuthSidePanel";
import { Logo } from "../components/Logo";
import { register, type AuthUser } from "../lib/api";

type Props = {
  onRegister: (user: AuthUser) => void;
  onGoToLogin: () => void;
};

/**
 * URL 파라미터로 초대 정보를 받음:
 *   /register?invite_email=user@x.com&tenant_id=acme&role=analyst
 * 또는 hash 기반:
 *   /#/register?invite_email=...
 *
 * 백엔드는 email-key 기반 pending_invitations로 동작.
 * 이메일이 일치하면 register_user() 안에서 자동으로 tenant_memberships 적용.
 */
function parseInviteFromUrl() {
  const search = new URLSearchParams(window.location.search);
  const hashIdx = window.location.hash.indexOf("?");
  const hashSearch = hashIdx >= 0
    ? new URLSearchParams(window.location.hash.slice(hashIdx + 1))
    : new URLSearchParams();
  function pick(k: string) {
    return search.get(k) ?? hashSearch.get(k) ?? "";
  }
  return {
    inviteEmail: pick("invite_email").trim(),
    inviteTenantId: pick("tenant_id").trim(),
    inviteRole: pick("role").trim(),
  };
}

export function RegisterPage({ onRegister, onGoToLogin }: Props) {
  const invite = useMemo(parseInviteFromUrl, []);
  const isInvited = Boolean(invite.inviteEmail);

  const [tenantId, setTenantId] = useState(invite.inviteTenantId || "");
  const [email, setEmail] = useState(invite.inviteEmail || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState(invite.inviteRole || "analyst");
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);

  const lockEmail = isInvited;
  const lockTenant = isInvited && Boolean(invite.inviteTenantId);

  useEffect(() => {
    if (!isInvited && !["analyst", "viewer"].includes(role)) {
      setRole("analyst");
    }
  }, [isInvited, role]);

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
      const safeRole = ["analyst", "viewer"].includes(role) ? role : "analyst";
      const result = await register(tenantId, email, password, safeRole);
      onRegister(result.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "회원가입에 실패했습니다.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-split">
      <AuthSidePanel variant="register" />

      <section className="auth-form-side">
        <form className="auth-form-panel" onSubmit={submit}>
          <div style={{ marginBottom: 12 }}>
            <Logo height={36} />
          </div>
          <div>
            <h1>계정 만들기</h1>
            <p className="auth-form-panel-sub">
              {isInvited
                ? "초대받은 조직에 합류하세요."
                : "조직 ID와 이메일만 있으면 1분 만에 시작할 수 있습니다."}
            </p>
          </div>

          {isInvited && (
            <div
              style={{
                display: "flex",
                gap: 10,
                alignItems: "flex-start",
                padding: "12px 14px",
                borderRadius: "var(--r-md)",
                background: "var(--c-blue-50)",
                border: "1px solid var(--c-blue-200)",
                fontSize: 13,
              }}
            >
              <MailCheck size={16} style={{ flexShrink: 0, marginTop: 2, color: "var(--c-blue-600)" }} />
              <div>
                <div style={{ fontWeight: 600, marginBottom: 2 }}>
                  {invite.inviteTenantId ? `${invite.inviteTenantId} 조직` : "InfraRed"}에 초대받으셨습니다
                </div>
                <div style={{ color: "var(--text-2)", fontSize: 12 }}>
                  가입을 완료하면 자동으로 합류됩니다
                  {invite.inviteRole ? ` · 역할: ${invite.inviteRole}` : ""}.
                </div>
              </div>
            </div>
          )}

          {error && <div className="auth-form-error">{error}</div>}

          <label>
            조직 ID
            <input
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              readOnly={lockTenant}
              placeholder="my-company"
              style={lockTenant ? { background: "var(--c-gray-50)", cursor: "not-allowed" } : undefined}
              required
            />
          </label>
          <label>
            이메일
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              readOnly={lockEmail}
              placeholder="you@company.com"
              style={lockEmail ? { background: "var(--c-gray-50)", cursor: "not-allowed" } : undefined}
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
              placeholder="8자 이상"
              autoComplete="new-password"
              required
            />
          </label>
          <label>
            비밀번호 확인
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="다시 입력"
              autoComplete="new-password"
              required
            />
          </label>
          {!isInvited && (
            <label>
              역할
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{
                  padding: "11px 14px",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--r-md)",
                  background: "var(--surface)",
                  fontSize: 14,
                  color: "var(--text)",
                }}
              >
                <option value="analyst">Analyst — 인시던트 조사·대응</option>
                <option value="viewer">Viewer — 읽기 전용</option>
              </select>
            </label>
          )}

          <button className="auth-form-btn" disabled={loading} type="submit">
            <UserPlus size={16} />
            {loading ? "계정 생성 중..." : "계정 만들기"}
          </button>

          <div className="auth-form-divider" />
          <p className="auth-form-muted">
            이미 계정이 있으신가요?{" "}
            <button type="button" onClick={onGoToLogin} className="auth-form-link">
              로그인
            </button>
          </p>
        </form>
      </section>
    </main>
  );
}
