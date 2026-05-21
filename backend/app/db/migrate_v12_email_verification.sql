-- ============================================================
-- migrate_v12_email_verification.sql
-- 이메일 인증 + 비밀번호 재설정 — 실제 사용자 가입 흐름 필수
-- ============================================================

-- users 테이블에 인증/재설정 컬럼 추가
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified           BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS email_verified_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verification_token       TEXT,
    ADD COLUMN IF NOT EXISTS verification_sent_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS password_reset_token     TEXT,
    ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_login_at            TIMESTAMPTZ;

-- 토큰 조회용 인덱스 (token으로 검색)
CREATE INDEX IF NOT EXISTS idx_users_verification_token
    ON users (verification_token)
    WHERE verification_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_password_reset_token
    ON users (password_reset_token)
    WHERE password_reset_token IS NOT NULL;

-- 기존 admin / seed 계정은 이메일 인증된 것으로 처리 (마이그레이션 시 한 번만)
UPDATE users
SET email_verified = TRUE, email_verified_at = NOW()
WHERE email_verified = FALSE
  AND email IN ('admin@infrared.local', 'ops@infrared.kr');
