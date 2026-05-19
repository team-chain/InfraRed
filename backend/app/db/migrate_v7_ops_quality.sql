-- =============================================================================
-- InfraRed v7 ops-quality migration
-- (파일명 v7: v6 response SQL은 다른 에이전트가 생성)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. audit_logs UPDATE/DELETE 차단 트리거 (append-only 보장)
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: modification not allowed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

-- -----------------------------------------------------------------------------
-- 2. KPI 집계 스냅샷 테이블
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS kpi_snapshots (
    id             TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id      TEXT NOT NULL,
    period_start   TIMESTAMPTZ NOT NULL,
    period_end     TIMESTAMPTZ NOT NULL,
    mttd_seconds   FLOAT,
    mttr_seconds   FLOAT,
    mttc_seconds   FLOAT,
    incident_count INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kpi_snapshots_tenant
    ON kpi_snapshots(tenant_id, period_start);

-- -----------------------------------------------------------------------------
-- 3. Honeytoken 이벤트 테이블
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS honeytoken_events (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id    TEXT NOT NULL,
    token_id     TEXT NOT NULL,
    token_type   TEXT NOT NULL,   -- 'file' | 'account'
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip    TEXT,
    username     TEXT,
    raw_event    JSONB
);

CREATE INDEX IF NOT EXISTS idx_honeytoken_events_tenant
    ON honeytoken_events(tenant_id, triggered_at DESC);

CREATE INDEX IF NOT EXISTS idx_honeytoken_events_token
    ON honeytoken_events(token_id);

-- -----------------------------------------------------------------------------
-- 4. 컴플라이언스 리포트 캐시 테이블
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS compliance_reports (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id    TEXT NOT NULL,
    framework    TEXT NOT NULL,
    report_data  JSONB NOT NULL,
    score_pct    FLOAT NOT NULL DEFAULT 0,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_tenant
    ON compliance_reports(tenant_id, framework);

-- -----------------------------------------------------------------------------
-- 5. SSL 인증서 모니터링 테이블
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ssl_certificates (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    last_checked  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issuer        TEXT,
    days_remaining INT GENERATED ALWAYS AS (
        EXTRACT(DAY FROM (expires_at - NOW()))::INT
    ) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ssl_certs_domain
    ON ssl_certificates(tenant_id, domain);

-- -----------------------------------------------------------------------------
-- 6. incidents 테이블 first_event_at 컬럼 추가 (KPI MTTD 계산용)
--    이미 존재하면 무시
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'incidents'
          AND column_name = 'first_event_at'
    ) THEN
        ALTER TABLE incidents ADD COLUMN first_event_at TIMESTAMPTZ;
    END IF;
END;
$$;

-- resolved_at 컬럼 추가 (MTTC 계산용)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'incidents'
          AND column_name = 'resolved_at'
    ) THEN
        ALTER TABLE incidents ADD COLUMN resolved_at TIMESTAMPTZ;
    END IF;
END;
$$;

-- auto_response_logs 에 executed_at 컬럼 추가 (MTTR 계산용)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'auto_response_logs'
          AND column_name = 'executed_at'
    ) THEN
        ALTER TABLE auto_response_logs ADD COLUMN executed_at TIMESTAMPTZ;
    END IF;
END;
$$;
