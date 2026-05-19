-- ============================================================
-- InfraRed GDPR 삭제 충돌 해결 마이그레이션 — v7
-- ============================================================

-- 1. GDPR 삭제 요청 테이블
CREATE TABLE IF NOT EXISTS gdpr_erasure_requests (
    request_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL,
    data_subject_identifier TEXT NOT NULL,
    identifier_type      TEXT NOT NULL DEFAULT 'email',  -- email | user_id | ip_address
    reason               TEXT DEFAULT '',
    requested_categories TEXT[] DEFAULT '{}',
    conflict_analysis    JSONB DEFAULT '[]',
    status               TEXT NOT NULL DEFAULT 'pending',  -- pending | in_review | processing | completed | rejected
    processor_notes      TEXT DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gdpr_erasure_tenant ON gdpr_erasure_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gdpr_erasure_identifier ON gdpr_erasure_requests(data_subject_identifier);

-- 2. 법적 보류(Legal Hold) 테이블
CREATE TABLE IF NOT EXISTS gdpr_legal_holds (
    hold_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL,
    data_category        TEXT NOT NULL,
    reference_id         TEXT NOT NULL,
    hold_reason          TEXT NOT NULL,
    hold_until           TIMESTAMPTZ,         -- NULL = 무기한
    legal_reference      TEXT DEFAULT '',     -- 법률 조항 (예: 형사소송법 §106)
    is_active            BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gdpr_holds_tenant ON gdpr_legal_holds(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_gdpr_holds_category ON gdpr_legal_holds(data_category, is_active);

-- 3. GDPR 삭제 예약 테이블 (법적 보존 기간 만료 후 자동 삭제)
CREATE TABLE IF NOT EXISTS gdpr_deletion_schedule (
    schedule_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL,
    data_category        TEXT NOT NULL,
    identifier           TEXT NOT NULL,
    identifier_type      TEXT NOT NULL,
    scheduled_delete_at  TIMESTAMPTZ NOT NULL,
    is_executed          BOOLEAN NOT NULL DEFAULT false,
    executed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, data_category, identifier)
);

CREATE INDEX IF NOT EXISTS idx_gdpr_schedule_delete_at
    ON gdpr_deletion_schedule(scheduled_delete_at)
    WHERE NOT is_executed;

-- 4. sigma_rules 테이블에 raw_yaml 컬럼 추가 (미리보기 기능용)
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS raw_yaml TEXT;

-- 5. sigma_rules에 logsource JSON 컬럼 추가 (마켓플레이스 필터용)
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS logsource JSONB DEFAULT '{}';

-- 6. detection_rules에 sigma_source_id 컬럼 추가 (마켓플레이스 연동용)
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS sigma_source_id TEXT;

CREATE INDEX IF NOT EXISTS idx_detection_rules_sigma_source
    ON detection_rules(sigma_source_id)
    WHERE sigma_source_id IS NOT NULL;

-- 7. audit_logs에 actor_email 컬럼 추가 (GDPR 데이터 조회용)
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS actor_email TEXT;
