-- v8 Security Migration — v7.0 보안 고도화 기능
-- Break-Glass 이벤트는 audit_logs에 저장 (기존 테이블 활용)
-- 새로 추가되는 테이블: deadman_switches, ueba_drift_events

-- ---------------------------------------------------------------------------
-- Dead Man's Switch 이력 테이블
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS deadman_switches (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id   TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    switch_id   TEXT NOT NULL,
    armed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disarmed_at TIMESTAMPTZ,
    ttl_seconds INT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'armed'  -- 'armed' | 'disarmed' | 'expired'
);

CREATE INDEX IF NOT EXISTS idx_deadman_tenant_asset
    ON deadman_switches(tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_deadman_status
    ON deadman_switches(status, armed_at DESC);

COMMENT ON TABLE deadman_switches IS
    'Dead Man''s Switch 이력 — 서버 격리 후 자동 격리 해제 예약 (v7.0)';

COMMENT ON COLUMN deadman_switches.status IS
    '''armed'': 활성 | ''disarmed'': 수동 해제 | ''expired'': TTL 만료 자동 해제';


-- ---------------------------------------------------------------------------
-- UEBA Drift Detection 이력 테이블
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ueba_drift_events (
    id                TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id         TEXT NOT NULL,
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    drift_score       FLOAT NOT NULL,
    affected_features JSONB NOT NULL DEFAULT '[]',
    is_resolved       BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at       TIMESTAMPTZ,
    resolved_by       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ueba_drift_tenant
    ON ueba_drift_events(tenant_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_ueba_drift_unresolved
    ON ueba_drift_events(tenant_id, is_resolved)
    WHERE is_resolved = FALSE;

COMMENT ON TABLE ueba_drift_events IS
    'UEBA Drift Detection 이력 — 4주 베이스라인 조작 탐지 (v7.0, rule_id=UEBA-DRIFT-001)';

COMMENT ON COLUMN ueba_drift_events.drift_score IS
    '정규화된 drift 점수 (0.3 초과 시 경고)';

COMMENT ON COLUMN ueba_drift_events.affected_features IS
    'Drift가 탐지된 특성 이름 목록 (JSON array)';


-- ---------------------------------------------------------------------------
-- audit_logs 테이블에 event_type 인덱스 추가 (Break-Glass 조회 최적화)
-- (audit_logs 테이블이 이미 존재한다고 가정)
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_audit_logs_action
    ON audit_logs(tenant_id, action, created_at DESC);

COMMENT ON INDEX idx_audit_logs_action IS
    'Break-Glass 이벤트 조회 최적화 (action=BREAK_GLASS 필터링)';
