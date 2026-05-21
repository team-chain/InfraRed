-- v11: 미가입 사용자 초대 (Pending Invitations)
-- 가입되지 않은 이메일에 대한 초대를 저장. 해당 이메일이 가입할 때
-- 자동으로 tenant_memberships에 INSERT되어 멤버로 합류.

CREATE TABLE IF NOT EXISTS pending_invitations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   TEXT NOT NULL,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst',
    invited_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '14 days',
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_pending_invitations_email
    ON pending_invitations(email);

CREATE INDEX IF NOT EXISTS idx_pending_invitations_tenant
    ON pending_invitations(tenant_id, expires_at);
