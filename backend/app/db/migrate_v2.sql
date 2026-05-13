-- ============================================================
-- InfraRed 고도화 v2.0 마이그레이션
-- 설계서 v2.0 Phase 1~5 전체 DB 스키마 추가/변경
-- ============================================================

-- ============================================================
-- 보안 기반: Row-Level Security (Phase 0 선행)
-- ============================================================

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE auto_response_logs ENABLE ROW LEVEL SECURITY;

-- RLS 정책: 현재 테넌트만 접근 허용
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'incidents' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON incidents
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'signals' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON signals
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'agents' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON agents
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'assets' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON assets
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'llm_results' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON llm_results
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'auto_response_logs' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON auto_response_logs
            USING (tenant_id = current_setting('app.current_tenant_id', true));
    END IF;
END
$$;

-- ============================================================
-- Phase 1-A: 인시던트 상태 워크플로우
-- ============================================================

-- incidents 테이블 컬럼 추가
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS assignee_id       UUID REFERENCES users(user_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS resolved_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS closed_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS disposition       TEXT,
    -- true_positive / false_positive / benign / duplicate
    ADD COLUMN IF NOT EXISTS close_reason      TEXT,
    ADD COLUMN IF NOT EXISTS detection_confidence FLOAT,
    ADD COLUMN IF NOT EXISTS ai_confidence     FLOAT;

-- primary_rule_id (Phase 3-C 선행 적용)
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS primary_rule_id   TEXT;

-- 인시던트 상태 변경 이력
CREATE TABLE IF NOT EXISTS incident_status_history (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id  TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    tenant_id    TEXT NOT NULL,
    from_status  TEXT,
    to_status    TEXT NOT NULL,
    changed_by   UUID REFERENCES users(user_id) ON DELETE SET NULL,
    reason       TEXT,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_status_history_incident ON incident_status_history(incident_id, changed_at DESC);

-- 인시던트 코멘트
CREATE TABLE IF NOT EXISTS incident_comments (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    incident_id  TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    author_id    UUID REFERENCES users(user_id) ON DELETE SET NULL,
    body         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_comments_incident ON incident_comments(incident_id, created_at DESC);

-- 인시던트 연결 (링크)
CREATE TABLE IF NOT EXISTS incident_links (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            TEXT NOT NULL,
    source_incident_id   TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    target_incident_id   TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    link_type            TEXT NOT NULL, -- same_attacker / follow_up / duplicate
    created_by           UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_links_source ON incident_links(source_incident_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON incident_links(target_incident_id);

-- ============================================================
-- Phase 1-B: 알림 그룹핑
-- ============================================================

CREATE TABLE IF NOT EXISTS alert_groups (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,
    source_ip      INET,
    asset_id       TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signal_count   INT NOT NULL DEFAULT 1,
    rule_ids       TEXT[] NOT NULL DEFAULT '{}',
    severity       TEXT,
    status         TEXT NOT NULL DEFAULT 'open',
    notified_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_groups_tenant ON alert_groups(tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_groups_ip ON alert_groups(tenant_id, source_ip, last_seen_at DESC);

-- ============================================================
-- Phase 2-A: 룰 관리 플랫폼 (기존 detection_rules 확장)
-- ============================================================

-- 기존 detection_rules 테이블 고도화 컬럼 추가
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS tenant_id       TEXT,
    ADD COLUMN IF NOT EXISTS display_name    TEXT,
    ADD COLUMN IF NOT EXISTS window_seconds  INT,
    ADD COLUMN IF NOT EXISTS threshold       INT,
    ADD COLUMN IF NOT EXISTS severity        TEXT,
    ADD COLUMN IF NOT EXISTS scope           JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS version         INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS status          TEXT NOT NULL DEFAULT 'active',
    -- draft / active / disabled / archived
    ADD COLUMN IF NOT EXISTS created_by      UUID REFERENCES users(user_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS dry_run_result  JSONB;

-- 룰 버전 스냅샷
CREATE TABLE IF NOT EXISTS detection_rule_versions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id       TEXT NOT NULL REFERENCES detection_rules(rule_id) ON DELETE CASCADE,
    tenant_id     TEXT,
    version       INT NOT NULL,
    snapshot      JSONB NOT NULL,
    changed_by    UUID REFERENCES users(user_id) ON DELETE SET NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    change_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_rule_versions_rule ON detection_rule_versions(rule_id, version DESC);

-- ============================================================
-- Phase 2-B: Allowlist / Suppression / Maintenance Window
-- ============================================================

CREATE TABLE IF NOT EXISTS allowlist_entries (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    entry_type   TEXT NOT NULL DEFAULT 'ip', -- ip / account / asset
    value        TEXT NOT NULL,
    description  TEXT,
    created_by   UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, entry_type, value)
);
CREATE INDEX IF NOT EXISTS idx_allowlist_tenant ON allowlist_entries(tenant_id, entry_type);

CREATE TABLE IF NOT EXISTS suppressions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    rule_id      TEXT,
    asset_id     TEXT REFERENCES assets(asset_id) ON DELETE CASCADE,
    source_ip    CIDR,
    username     TEXT,
    expires_at   TIMESTAMPTZ,
    reason       TEXT NOT NULL,
    created_by   UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled      BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_suppressions_tenant ON suppressions(tenant_id, enabled);

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '정기 점검',
    start_at         TIMESTAMPTZ NOT NULL,
    end_at           TIMESTAMPTZ NOT NULL,
    recurrence       TEXT,  -- cron 표현식 (NULL = 1회성)
    affected_rules   TEXT[] NOT NULL DEFAULT '{}',   -- 빈 배열 = 전체 룰
    affected_assets  TEXT[] NOT NULL DEFAULT '{}',   -- 빈 배열 = 전체 자산
    reason           TEXT,
    created_by       UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_mw_tenant ON maintenance_windows(tenant_id, start_at, end_at);

-- ============================================================
-- Phase 2-C: RBAC 고도화 - tenant_memberships
-- ============================================================

-- user_role ENUM (이미 있으면 skip)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role_enum') THEN
        CREATE TYPE user_role_enum AS ENUM ('owner', 'security_manager', 'analyst', 'viewer');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS tenant_memberships (
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'analyst',
    -- owner / security_manager / analyst / viewer
    invited_by  UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON tenant_memberships(user_id);

-- 기존 users 테이블의 role을 tenant_memberships로 마이그레이션
INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at)
SELECT tenant_id, user_id, role, created_at
FROM users
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- ============================================================
-- Phase 2-D: 온보딩 플로우 상태 추적
-- ============================================================

CREATE TABLE IF NOT EXISTS onboarding_state (
    tenant_id        TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    step             INT NOT NULL DEFAULT 1,
    -- 1=테넌트등록 2=토큰발급 3=설치명령 4=연결확인 5=정책설정
    completed_steps  INT[] NOT NULL DEFAULT '{}',
    first_heartbeat_at TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- tenant_settings에 Slack/Teams 웹훅 추가 (Phase 5)
ALTER TABLE tenant_settings
    ADD COLUMN IF NOT EXISTS slack_webhook_url  TEXT,
    ADD COLUMN IF NOT EXISTS teams_webhook_url  TEXT,
    ADD COLUMN IF NOT EXISTS sendgrid_api_key   TEXT,
    ADD COLUMN IF NOT EXISTS report_email_to    TEXT,
    ADD COLUMN IF NOT EXISTS weekly_report_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS monthly_report_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- ============================================================
-- Phase 3-D: 에이전트 Lifecycle 관리
-- ============================================================

CREATE TABLE IF NOT EXISTS agent_versions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tenant_id    TEXT NOT NULL,
    version      TEXT NOT NULL,
    reported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_versions_agent ON agent_versions(agent_id, reported_at DESC);

CREATE TABLE IF NOT EXISTS agent_commands (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    command      TEXT NOT NULL,
    -- update / restart / reconfigure / deactivate
    payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_sig  TEXT NOT NULL, -- HMAC-SHA256 서명
    expires_at   TIMESTAMPTZ NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    -- pending / delivered / executed / failed / expired
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    executed_at  TIMESTAMPTZ,
    result       JSONB
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON agent_commands(agent_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_commands_tenant ON agent_commands(tenant_id, created_at DESC);

-- agents 테이블에 상태 추가
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deactivation_reason TEXT,
    ADD COLUMN IF NOT EXISTS cpu_quota_pct   INT NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS mem_max_mb      INT NOT NULL DEFAULT 100;

-- ============================================================
-- Phase 4-B: RAG 유사 인시던트 (pgvector)
-- pgvector가 설치된 환경에서만 활성화됨 (postgres:16-alpine 기본 미포함)
-- docker-compose.yml에서 pgvector/pgvector:pg16 이미지 사용 시 자동 적용
-- ============================================================

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgvector extension not available, skipping vector features';
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'incidents' AND column_name = 'embedding'
        ) THEN
            ALTER TABLE incidents ADD COLUMN embedding vector(1536);
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'incidents' AND indexname = 'idx_incidents_embedding'
        ) THEN
            CREATE INDEX idx_incidents_embedding
                ON incidents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
        END IF;
    END IF;
END
$$;

-- ============================================================
-- Phase 4-D: PDF 리포트 이력
-- ============================================================

CREATE TABLE IF NOT EXISTS report_history (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,
    report_type    TEXT NOT NULL DEFAULT 'weekly', -- weekly / monthly
    period_start   TIMESTAMPTZ NOT NULL,
    period_end     TIMESTAMPTZ NOT NULL,
    s3_key         TEXT,
    download_url   TEXT,
    email_sent     BOOLEAN NOT NULL DEFAULT FALSE,
    generated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON report_history(tenant_id, generated_at DESC);

-- ============================================================
-- Phase 5-C: 설정 백업/복원 이력
-- ============================================================

CREATE TABLE IF NOT EXISTS config_backup_history (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,
    backup_type    TEXT NOT NULL DEFAULT 'manual', -- manual / pre_import
    s3_key         TEXT,
    snapshot       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by     UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_backups_tenant ON config_backup_history(tenant_id, created_at DESC);

-- ============================================================
-- 인덱스 추가 (성능)
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents(assignee_id);
CREATE INDEX IF NOT EXISTS idx_incidents_disposition ON incidents(tenant_id, disposition);
CREATE INDEX IF NOT EXISTS idx_incidents_primary_rule ON incidents(primary_rule_id);
