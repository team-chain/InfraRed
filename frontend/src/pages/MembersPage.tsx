/**
 * Phase 3-C: RBAC 멤버 관리 페이지
 * - 테넌트 멤버 목록 + 역할 변경 + 제거
 * - 초대 (이메일 + 역할)
 * - 온보딩 상태 표시
 */
import { useEffect, useState } from "react";
import {
  fetchTenantMembers,
  inviteMember,
  changeMemberRole,
  removeMember,
  fetchPendingInvitations,
  cancelPendingInvitation,
  type Member,
  type AuthUser,
  type PendingInvitation,
} from "../lib/api";
import { UserPlus, Trash2, RefreshCw, Crown, Shield, Eye, MailQuestion, X as XIcon, Link2 } from "lucide-react";

function buildInviteUrl(email: string, tenantId: string, role: string): string {
  const params = new URLSearchParams({ invite_email: email, tenant_id: tenantId, role });
  return `${window.location.origin}/?${params.toString()}`;
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    // Fallback for non-HTTPS / older browsers
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

type Props = { user: AuthUser };

const ROLE_OPTIONS = ["owner", "security_manager", "analyst", "viewer"] as const;
const ROLE_LABEL: Record<string, string> = {
  owner: "Owner",
  security_manager: "보안 관리자",
  analyst: "분석가",
  viewer: "뷰어",
};
const ROLE_COLOR: Record<string, string> = {
  owner: "var(--c-purple-600, #7c3aed)",
  security_manager: "var(--c-red-600)",
  analyst: "var(--c-blue-600)",
  viewer: "var(--text-3)",
};
const ROLE_ICON: Record<string, React.ReactNode> = {
  owner: <Crown size={12} />,
  security_manager: <Shield size={12} />,
  analyst: <Shield size={12} />,
  viewer: <Eye size={12} />,
};

export function MembersPage({ user }: Props) {
  const [members, setMembers] = useState<Member[]>([]);
  const [pending, setPending] = useState<PendingInvitation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<string>("analyst");
  const [inviteLoading, setInviteLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const isOwner = user.role === "owner";

  async function load() {
    setLoading(true);
    try {
      const [m, p] = await Promise.all([
        fetchTenantMembers(user.tenant_id),
        fetchPendingInvitations(user.tenant_id).catch(() => []),
      ]);
      setMembers(m);
      setPending(p);
    } catch (e: any) {
      setError(e.message || "멤버 목록 로드 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  // 알림 자동 해제 (5초)
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(null), 5000);
    return () => clearTimeout(t);
  }, [notice]);

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!inviteEmail.trim()) { setError("이메일을 입력하세요"); return; }
    setInviteLoading(true);
    setError(null);
    try {
      const result = await inviteMember(user.tenant_id, inviteEmail, inviteRole);
      if (result.status === "pending") {
        setNotice(
          `${inviteEmail}님은 아직 가입 전이에요. ${result.expires_in_days ?? 14}일 안에 가입하시면 ${ROLE_LABEL[inviteRole]}로 자동 합류해요.`,
        );
      } else {
        setNotice(`${inviteEmail}을(를) ${ROLE_LABEL[inviteRole]}로 초대했습니다`);
      }
      setInviteEmail("");
      await load();
    } catch (e: any) {
      const msg = String(e?.message ?? "");
      if (msg.includes("409")) {
        setError("이미 이 테넌트의 멤버예요.");
      } else if (msg.includes("403")) {
        setError("초대 권한이 없습니다 (owner 필요).");
      } else {
        setError(e.message || "초대 실패");
      }
    } finally {
      setInviteLoading(false);
    }
  }

  async function handleCancelPending(id: string, email: string) {
    if (!confirm(`${email} 대상 대기 초대를 취소할까요?`)) return;
    setBusyId(id);
    setError(null);
    try {
      await cancelPendingInvitation(user.tenant_id, id);
      setNotice(`${email} 대기 초대가 취소됐어요`);
      setPending((prev) => prev.filter((p) => p.id !== id));
    } catch (e: any) {
      setError(e.message || "취소 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleChangeRole(userId: string, newRole: string) {
    setBusyId(userId);
    setError(null);
    try {
      await changeMemberRole(user.tenant_id, userId, newRole);
      setNotice("역할이 변경되었습니다");
      await load();
    } catch (e: any) {
      setError(e.message || "역할 변경 실패");
    } finally {
      setBusyId(null);
    }
  }

  async function handleRemove(userId: string, email: string) {
    if (!confirm(`${email} 멤버를 제거하시겠습니까?`)) return;
    setBusyId(userId);
    setError(null);
    try {
      await removeMember(user.tenant_id, userId);
      setNotice(`${email}이(가) 제거되었습니다`);
      setMembers((prev) => prev.filter((m) => m.user_id !== userId));
    } catch (e: any) {
      setError(e.message || "제거 실패");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">팀 멤버 관리</h2>
            <p className="page-subtitle">
              테넌트: <code style={{ fontSize: 12 }}>{user.tenant_id}</code> · RBAC 역할 기반 접근 제어
            </p>
          </div>
          <button className="btn btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
          </button>
        </div>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>{error}</div>}
      {notice && <div className="notice" style={{ marginBottom: 12 }}>{notice}</div>}

      {/* 역할 설명 */}
      <div className="card" style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 20, padding: "12px 16px" }}>
        {ROLE_OPTIONS.map((role) => (
          <div key={role} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12 }}>
            <span
              style={{
                display: "inline-flex", alignItems: "center", gap: 3,
                padding: "2px 8px", borderRadius: 10,
                background: `${ROLE_COLOR[role]}15`,
                color: ROLE_COLOR[role], fontWeight: 600,
              }}
            >
              {ROLE_ICON[role]} {ROLE_LABEL[role]}
            </span>
          </div>
        ))}
      </div>

      {/* 초대 폼 (Owner만) */}
      {isOwner && (
        <form onSubmit={handleInvite} className="card" style={{ display: "flex", gap: 8, marginBottom: 20, padding: "16px", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 4, fontWeight: 600 }}>
              초대할 이메일 *
            </label>
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="user@company.com"
              className="form-input" style={{ width: "100%", boxSizing: "border-box" }}
            />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 11, color: "var(--text-3)", marginBottom: 4, fontWeight: 600 }}>
              역할
            </label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
              className="form-input" style={{ width: "auto" }}
            >
              {ROLE_OPTIONS.filter(r => r !== "owner").map(r => (
                <option key={r} value={r}>{ROLE_LABEL[r]}</option>
              ))}
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <button type="submit" className="btn btn-primary" disabled={inviteLoading}>
              <UserPlus size={14} /> {inviteLoading ? "초대 중…" : "초대"}
            </button>
          </div>
        </form>
      )}

      {/* 대기 중 초대 */}
      {pending.length > 0 && (
        <div className="card" style={{ marginBottom: 20, padding: "12px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
            <MailQuestion size={14} style={{ color: "var(--text-3)" }} />
            <strong style={{ fontSize: 13 }}>가입 대기 중 초대 ({pending.length})</strong>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 10 }}>
            아직 InfraRed에 가입하지 않은 이메일이에요. 가입하면 자동으로 합류합니다.
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {pending.map((p) => {
              const expiresIn = p.expires_at
                ? Math.ceil(
                    (new Date(p.expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24),
                  )
                : null;
              return (
                <div
                  key={p.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "8px 12px",
                    background: "var(--c-amber-50, #fffbeb)",
                    borderRadius: 6,
                    border: "1px solid var(--c-amber-200, #fde68a)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{p.email}</span>
                    <span
                      style={{
                        padding: "2px 8px",
                        borderRadius: 10,
                        background: `${ROLE_COLOR[p.role] ?? "#6b7280"}15`,
                        color: ROLE_COLOR[p.role] ?? "#6b7280",
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      {ROLE_LABEL[p.role] ?? p.role}
                    </span>
                    {expiresIn !== null && (
                      <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                        {expiresIn > 0 ? `${expiresIn}일 남음` : "만료됨"}
                      </span>
                    )}
                  </div>
                  {isOwner && (
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={async () => {
                          const url = buildInviteUrl(p.email, user.tenant_id, p.role);
                          const ok = await copyToClipboard(url);
                          if (ok) {
                            setNotice(`초대 링크가 복사되었습니다 — ${p.email}에게 전달하세요`);
                          } else {
                            setError("클립보드 복사 실패 — 수동 복사: " + url);
                          }
                        }}
                        title="초대 링크 복사 (수동 공유)"
                        style={{ padding: "4px 8px" }}
                      >
                        <Link2 size={12} />
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => handleCancelPending(p.id, p.email)}
                        disabled={busyId === p.id}
                        title="대기 초대 취소"
                        style={{ padding: "4px 8px" }}
                      >
                        <XIcon size={12} />
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 멤버 목록 */}
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>이메일</th>
              <th>역할</th>
              <th>가입일</th>
              <th>마지막 로그인</th>
              {isOwner && <th>관리</th>}
            </tr>
          </thead>
          <tbody>
            {members.map((m) => {
              const isSelf = m.user_id === user.user_id || m.email === user.email;
              const isBusy = busyId === m.user_id;
              return (
                <tr key={m.user_id} style={{ background: isSelf ? "var(--c-blue-25, #f0f9ff)" : undefined }}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div
                        style={{
                          width: 28, height: 28, borderRadius: "50%",
                          background: ROLE_COLOR[m.role] ?? "#6b7280",
                          display: "flex", alignItems: "center", justifyContent: "center",
                          color: "white", fontSize: 11, fontWeight: 700,
                          flexShrink: 0,
                        }}
                      >
                        {(m.email ?? "?").slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{m.email}</div>
                        {isSelf && <span style={{ fontSize: 11, color: "var(--c-blue-500)", fontWeight: 600 }}>나</span>}
                      </div>
                    </div>
                  </td>
                  <td>
                    {isOwner && !isSelf ? (
                      <select
                        value={m.role}
                        onChange={(e) => handleChangeRole(m.user_id, e.target.value)}
                        disabled={isBusy}
className="form-input" style={{ padding: "4px 8px", fontSize: 12, fontWeight: 600, width: "auto" }}
                      >
                        {ROLE_OPTIONS.filter(r => r !== "owner").map(r => (
                          <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                        ))}
                      </select>
                    ) : (
                      <span
                        style={{
                          display: "inline-flex", alignItems: "center", gap: 4,
                          padding: "3px 10px", borderRadius: 10,
                          background: `${ROLE_COLOR[m.role] ?? "#6b7280"}15`,
                          color: ROLE_COLOR[m.role] ?? "#6b7280",
                          fontSize: 12, fontWeight: 600,
                        }}
                      >
                        {ROLE_ICON[m.role]} {ROLE_LABEL[m.role] ?? m.role}
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--text-3)" }}>
                    {m.created_at ? new Date(m.created_at).toLocaleDateString("ko-KR") : "-"}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--text-3)" }}>
                    {m.last_login_at ? new Date(m.last_login_at).toLocaleString("ko-KR") : "-"}
                  </td>
                  {isOwner && (
                    <td>
                      {!isSelf && m.role !== "owner" && (
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => handleRemove(m.user_id, m.email)}
                          disabled={isBusy}
                          title="멤버 제거"
                        >
                          <Trash2 size={12} />
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
            {members.length === 0 && !loading && (
              <tr>
                <td colSpan={isOwner ? 5 : 4} style={{ textAlign: "center", color: "var(--text-3)", padding: "40px" }}>
                  멤버 없음
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
