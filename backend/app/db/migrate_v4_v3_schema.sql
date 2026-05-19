-- ============================================================
-- InfraRed v3.0 설계서 기반 마이그레이션
-- migrate_v4_v3_schema.sql
-- 실행 순서: schema.sql → migrate_v2.sql → migrate_v3_freetier.sql → migrate_v4_v3_schema.sql
-- ============================================================

-- ============================================================
-- incidents 테이블 컬럼 추가 (v3 시나리오 / 캠페인 연동)
-- ============================================================

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS scenario_id          VARCHAR(100),
    ADD COLUMN IF NOT EXISTS confidence_breakdown JSONB,
    ADD COLUMN IF NOT EXISTS campaign_id          UUID;

-- ============================================================
-- signals 테이블 컬럼 추가 (v3 CTI 결과 / 신규성 점수)
-- ============================================================

ALTER TABLE signals
    ADD COLUMN IF NOT EXISTS cti_result    JSONB,
    ADD COLUMN IF NOT EXISTS novelty_score FLOAT DEFAULT 0.0;

-- ============================================================
-- alert_groups 테이블 컬럼 추가 (v3 공격 맥락)
-- ============================================================

ALTER TABLE alert_groups
    ADD COLUMN IF NOT EXISTS source_asn          VARCHAR(30),
    ADD COLUMN IF NOT EXISTS attack_type         VARCHAR(50),
    ADD COLUMN IF NOT EXISTS affected_asset_count INT DEFAULT 1;

-- ============================================================
-- assets 테이블 컬럼 추가 (v3 자산 중요도)
-- ============================================================

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS asset_criticality       VARCHAR(10)  DEFAULT 'medium',
    -- low / medium / high / critical
    ADD COLUMN IF NOT EXISTS asset_type              VARCHAR(20)  DEFAULT 'web',
    -- web / api / db / bastion / worker / monitoring
    ADD COLUMN IF NOT EXISTS environment             VARCHAR(10)  DEFAULT 'prod',
    -- dev / staging / prod
    ADD COLUMN IF NOT EXISTS exposure                VARCHAR(10)  DEFAULT 'public',
    -- public / private / internal
    ADD COLUMN IF NOT EXISTS contains_sensitive_data BOOLEAN      DEFAULT false,
    ADD COLUMN IF NOT EXISTS owner_team              VARCHAR(100),
    ADD COLUMN IF NOT EXISTS sla_tier                VARCHAR(10)  DEFAULT 'standard',
    -- standard / high / critical
    ADD COLUMN IF NOT EXISTS criticality_score       INT          DEFAULT 0;

-- criticality_score 자동 계산 함수
CREATE OR REPLACE FUNCTION compute_criticality_score()
RETURNS TRIGGER AS $$
BEGIN
    NEW.criticality_score :=
        CASE NEW.environment
            WHEN 'prod'    THEN 30
            WHEN 'staging' THEN 10
            ELSE 0
        END +
        CASE NEW.asset_type
            WHEN 'db'      THEN 40
            WHEN 'bastion' THEN 35
            WHEN 'api'     THEN 20
            WHEN 'web'     THEN 10
            ELSE 5
        END +
        CASE WHEN NEW.exposure = 'public' THEN 15 ELSE 0 END +
        CASE WHEN NEW.contains_sensitive_data THEN 25 ELSE 0 END;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 트리거: assets INSERT / UPDATE 시 criticality_score 자동 계산
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_compute_criticality_score'
          AND tgrelid = 'assets'::regclass
    ) THEN
        CREATE TRIGGER trg_compute_criticality_score
            BEFORE INSERT OR UPDATE ON assets
            FOR EACH ROW
            EXECUTE FUNCTION compute_criticality_score();
    END IF;
END
$$;

-- ============================================================
-- auto_response_logs 테이블 컬럼 추가 (v3 TTL / 승인 워크플로우)
-- ============================================================

ALTER TABLE auto_response_logs
    ADD COLUMN IF NOT EXISTS action_level        VARCHAR(20),
    -- iptables_block / service_block / watchlist
    ADD COLUMN IF NOT EXISTS ttl_seconds         INT,
    ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approval_required   BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS approved_by         UUID REFERENCES users(user_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS approved_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS auto_expired        BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS confidence_snapshot FLOAT,
    ADD COLUMN IF NOT EXISTS scenario_id         VARCHAR(100);

-- ============================================================
-- 신규 테이블: attack_campaigns
-- ============================================================

CREATE TABLE IF NOT EXISTS attack_campaigns (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           TEXT NOT NULL,
    campaign_type       VARCHAR(50) NOT NULL,
    source_asn          VARCHAR(30),
    source_ips          TEXT[],
    affected_asset_ids  TEXT[],
    incident_ids        TEXT[],
    first_seen_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ DEFAULT NOW(),
    total_signals       INT DEFAULT 0,
    status              VARCHAR(20) DEFAULT 'active',
    campaign_label      TEXT
);

-- ============================================================
-- 신규 테이블: watchdog_events (Tamper Detection 이벤트 저장)
-- ============================================================

CREATE TABLE IF NOT EXISTS watchdog_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'CRITICAL',
    mitre       TEXT,
    detail      JSONB DEFAULT '{}',
    reported_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- 인덱스
-- ============================================================

-- auto_response_logs: 만료 예정 레코드 (아직 복구되지 않은 것만)
CREATE INDEX IF NOT EXISTS idx_auto_response_expires
    ON auto_response_logs(expires_at)
    WHERE expires_at IS NOT NULL AND reversed = false;

-- incidents: 시나리오별 조회
CREATE INDEX IF NOT EXISTS idx_incidents_scenario
    ON incidents(tenant_id, scenario_id)
    WHERE scenario_id IS NOT NULL;

-- attack_campaigns: 테넌트 + 상태 + 최근 활동 순
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_status
    ON attack_campaigns(tenant_id, status, last_seen_at DESC);

-- signals: CTI 알려진 악성 IP 여부
CREATE INDEX IF NOT EXISTS idx_signals_cti
    ON signals(tenant_id, (cti_result->>'is_known_malicious'))
    WHERE cti_result IS NOT NULL;

-- watchdog_events: 에이전트별 시간순 조회
CREATE INDEX IF NOT EXISTS idx_watchdog_events
    ON watchdog_events(tenant_id, agent_id, reported_at DESC);
