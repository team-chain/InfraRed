-- ============================================================
-- InfraRed 프리티어 고도화 마이그레이션 v3 (설계서 2.7절)
-- PostgreSQL FTS (Full-Text Search) — OpenSearch 대체
-- ============================================================
-- 목적: OpenSearch(월 ~48만원) 없이 Signal 전문 검색 구현
-- 방식: GIN(Generalized Inverted Index) + tsvector
-- 성능: Signal 30만 건 이하에서 충분 (P95 < 3초 기준)
-- ============================================================

-- ── 1. signals 테이블 FTS 컬럼 추가 ─────────────────────────
ALTER TABLE signals
    ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- ── 2. GIN 인덱스 생성 (전체 인덱스)
-- 주의: WHERE created_at > NOW() 같은 파셜 인덱스는 NOW()가 IMMUTABLE이 아니라
-- PostgreSQL에서 허용하지 않음. 전체 GIN 인덱스로 대신 적용.
DROP INDEX IF EXISTS idx_signals_fts;
CREATE INDEX IF NOT EXISTS idx_signals_fts
    ON signals USING GIN(search_vector);

-- ── 3. tsvector 자동 업데이트 트리거 ─────────────────────────
CREATE OR REPLACE FUNCTION signals_search_update()
RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector(
        'simple',
        coalesce(NEW.rule_id, '')      || ' ' ||
        coalesce(NEW.rule_name, '')    || ' ' ||
        coalesce(NEW.source_ip::text, '') || ' ' ||
        coalesce(NEW.username, '')     || ' ' ||
        coalesce(NEW.mitre_tactic, '') || ' ' ||
        coalesce(NEW.mitre_technique, '') || ' ' ||
        coalesce(NEW.kill_chain_stage, '') || ' ' ||
        coalesce(NEW.notes, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS signals_search_trigger ON signals;
CREATE TRIGGER signals_search_trigger
    BEFORE INSERT OR UPDATE ON signals
    FOR EACH ROW EXECUTE FUNCTION signals_search_update();

-- ── 4. 기존 데이터 search_vector 업데이트 (마이그레이션 1회) ─
-- 대량 업데이트: 잠금 최소화를 위해 배치 처리
-- 운영 중인 DB는 아래 쿼리를 별도 실행 권장 (lock 주의)
DO $$
DECLARE
    updated INT;
BEGIN
    UPDATE signals SET
        search_vector = to_tsvector(
            'simple',
            coalesce(rule_id, '')         || ' ' ||
            coalesce(rule_name, '')       || ' ' ||
            coalesce(source_ip::text, '') || ' ' ||
            coalesce(username, '')        || ' ' ||
            coalesce(mitre_tactic, '')    || ' ' ||
            coalesce(mitre_technique, '') || ' ' ||
            coalesce(kill_chain_stage, '') || ' ' ||
            coalesce(notes, '')
        )
    WHERE search_vector IS NULL;

    GET DIAGNOSTICS updated = ROW_COUNT;
    RAISE NOTICE 'FTS 백필 완료: % 건', updated;
END;
$$;

-- ── 5. AI 분석 결과 저장 테이블 (Lambda AI Worker) ───────────
-- incident_ai_analyses: Lambda가 Bedrock 분석 결과를 저장하는 테이블
CREATE TABLE IF NOT EXISTS incident_ai_analyses (
    id              BIGSERIAL PRIMARY KEY,
    incident_id     TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    model           TEXT,                    -- Bedrock 모델 ID
    analysis        JSONB NOT NULL DEFAULT '{}',  -- Claude 분석 결과 JSON
    provider        TEXT NOT NULL DEFAULT 'bedrock',  -- 'bedrock' | 'static_playbook'
    tokens_used     INT DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_analyses_incident
    ON incident_ai_analyses(incident_id);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_created
    ON incident_ai_analyses(created_at DESC);

-- ── 6. SQS 이벤트 버스 추적 테이블 ──────────────────────────
-- Redis Streams 대체: DLQ 이벤트 추적 및 재처리를 위한 테이블
CREATE TABLE IF NOT EXISTS sqs_dlq_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    event_id        TEXT UNIQUE NOT NULL,
    event_type      TEXT,
    payload         JSONB NOT NULL DEFAULT '{}',
    error_message   TEXT,
    retry_count     INT NOT NULL DEFAULT 0,
    resolved        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_dlq_tenant_created
    ON sqs_dlq_events(tenant_id, created_at DESC)
    WHERE resolved = FALSE;

-- ── 7. 모니터링: FTS 검색 성능 뷰 ───────────────────────────
-- 관리자가 FTS 성능을 모니터링하기 위한 뷰
CREATE OR REPLACE VIEW v_fts_index_stats AS
SELECT
    schemaname,
    relname       AS tablename,
    indexrelname  AS indexname,
    idx_scan      AS total_scans,
    idx_tup_read  AS tuples_read,
    idx_tup_fetch AS tuples_fetched
FROM pg_stat_user_indexes
WHERE indexrelname LIKE '%fts%'
ORDER BY idx_scan DESC;

-- ── 8. 전환 기준 모니터링 쿼리 (참고용, 실행하지 않음) ────────
-- 아래 기준 초과 시 OpenSearch 도입 검토:
--   - Signal 누적 30만 건 초과
--   - 검색 쿼리 P95 3초 초과
--
-- SELECT COUNT(*) FROM signals WHERE created_at > NOW() - INTERVAL '30 days';
-- SELECT pg_size_pretty(pg_relation_size('idx_signals_fts'));
