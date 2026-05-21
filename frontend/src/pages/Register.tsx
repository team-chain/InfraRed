import { FormEvent, useEffect, useMemo, useState } from "react";
import { UserPlus, Siren, MailCheck } from "lucide-react";
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
  // hash에 ?가 있을 수도 있음 (#/register?invite_email=...)
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

  const [tenantId, setTenantId] = useState(invite.inviteTenantId || "company-a");
  const [email, setEmail] = useState(invite.inviteEmail || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  // 초대된 사용자는 invited role을 표시만 함 (서버에서 pending_invitations로 적용).
  // self-register는 기본 analyst.
  const [role, setRole] = useState(invite.inviteRole || "analyst");
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);

  // 초대 모드면 이메일/테넌트는 read-only로 잠금
  const lockEmail = isInvited;
  const lockTenant = isInvited && Boolean(invite.inviteTenantId);

  useEffect(() => {
    // 보안: 초대받지 않은 사용자가 임의로 admin/owner로 스스로 가입 못하도록
    // RegisterRequest pydantic에서 analyst|viewer만 허용하므로 frontend도 동일하게 제한
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
      // 초대 모드여도 self-register에서는 role은 analyst/viewer만 허용 (백엔드 검증).
      // 초대된 owner/security_manager 역할은 pending_invitations로 자동 부여됨.
      const safeRole = ["analyst", "viewer"].includes(role) ? role : "analyst";
      const result = await register(tenantId, email, password, safeRole);
      onRegister(result.user);
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

        {isInvited && (
          <div
            className="notice"
            style={{
              display: "flex",
              gap: 8,
              alignItems: "flex-start",
              padding: "10px 12px",
              marginBottom: 10,
              borderRadius: 8,
              background: "var(--c-blue-50, #eff6ff)",
              border: "1px solid var(--c-blue-200, #bfdbfe)",
              fontSize: 13,
            }}
          >
            <MailCheck size={16} style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <div style={{ fontWeight: 600, marginBottom: 2 }}>
                {invite.inviteTenantId ? `${invite.inviteTenantId} 테넌트` : "InfraRed"}에 초대받으셨습니다
              </div>
              <div style={{ color: "var(--text-3)", fontSize: 12 }}>
                가입을 완료하면 자동으로 합류됩니다
                {invite.inviteRole ? ` · 역할: ${invite.inviteRole}` : ""}.
              </div>
            </div>
          </div>
        )}

        {error && <div className="alert">{error}</div>}

        <label>
          Tenant
          <input
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            readOnly={lockTenant}
            style={lockTenant ? { background: "var(--surface-2)", cursor: "not-allowed" } : undefined}
            required
          />
        </label>
        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            readOnly={lockEmail}
            style={lockEmail ? { background: "var(--surface-2)", cursor: "not-allowed" } : undefined}
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
        {!isInvited && (
          <label>
            Role
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
          </label>
        )}
        <button className="primary-button" disabled={loading} type="submit">
          <UserPlus size={18} />
          {loading ? "Creating account..." : "계정 만들기"}
        </button>
        <p style={{ textAlign: "center", marginTop: "0.75rem", fontSize: "0.875rem" }}>
          이미 계정이 있으신가요?{" "}
          <button type="button" onClick={onGoToLogin}
            style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}>
            로그인
          </button>
        </p>
      </form>
    </main>
  );
}
