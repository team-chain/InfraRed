-- v9 TimescaleDB Hypertable Migration — v4.0 설계서
-- 설계서 §: 시계열 데이터 성능 최적화 — TimescaleDB Extension 적용
--
-- 적용 대상 테이블:
--   - normalized_events  (timestamp 컬럼)
--   - signals            (detected_at 컬럼)
--   - audit_logs         (timestamp 컬럼)
--   - incidents          (created_at 컬럼)
--   - auto_response_logs (created_at 컬럼)
--
-- 실행 전제조건:
--   TimescaleDB Extension이 설치되어 있어야 합니다.
--   (docker-compose.yml 또는 RDS 파라미터 그룹에서 timescaledb 활성화 필요)
--
-- 실행 방법:
--   psql -h <host> -U <user> -d <dbname> -f migrate_v9_timescale.sql
--
-- 참고: CREATE EXTENSION은 슈퍼유저 권한 필요.
--       RDS/Aurora의 경우 rds_superuser 역할로 실행.

-- ---------------------------------------------------------------------------
-- 0. TimescaleDB Extension 활성화
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ---------------------------------------------------------------------------
-- 1. normalized_events → hypertable
--    시간 범위: timestamp (TIMESTAMPTZ)
--    청크 간격: 1일 (고빈도 이벤트 수집)
-- ---------------------------------------------------------------------------

SELECT create_hypertable(
    'normalized_events',
    'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists        => TRUE
);

-- 압축 정책: 7일 이후 청크 자동 압축 (저장 공간 최적화)
SELECT add_compression_policy(
    'normalized_events',
    compress_after => INTERVAL '7 days',
    if_not_exists  => TRUE
);

-- 데이터 보존 정책: 90일 이후 청크 자동 삭제
SELECT add_retention_policy(
    'normalized_events',
    drop_after    => INTERVAL '90 days',
    if_not_exists => TRUE
);

COMMENT ON TABLE normalized_events IS
    'TimescaleDB Hypertable — 이벤트 수집 데이터 (청크 간격 1일, 7일 압축, 90일 보존)';


-- ---------------------------------------------------------------------------
-- 2. signals → hypertable
--    시간 범위: detected_at (TIMESTAMPTZ)
--    청크 간격: 1일
-- ---------------------------------------------------------------------------

SELECT create_hypertable(
    'signals',
    'detected_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists        => TRUE
);

SELECT add_compression_policy(
    'signals',
    compress_after => INTERVAL '7 days',
    if_not_exists  => TRUE
);

SELECT add_retention_policy(
    'signals',
    drop_after    => INTERVAL '180 days',
    if_not_exists => TRUE
);

COMMENT ON TABLE signals IS
    'TimescaleDB Hypertable — 탐지 시그널 (청크 간격 1일, 7일 압축, 180일 보존)';


-- ---------------------------------------------------------------------------
-- 3. audit_logs → hypertable
--    시간 범위: timestamp (TIMESTAMPTZ)
--    청크 간격: 7일 (감사 로그는 빈도가 낮음)
-- ---------------------------------------------------------------------------

SELECT create_hypertable(
    'audit_logs',
    'timestamp',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists        => TRUE
);

-- 감사 로그는 규정 준수 목적으로 365일 보존
SELECT add_retention_policy(
    'audit_logs',
    drop_after    => INTERVAL '365 days',
    if_not_exists => TRUE
);

COMMENT ON TABLE audit_logs IS
    'TimescaleDB Hypertable — 감사 로그 (청크 간격 7일, 365일 보존 — 규정 준수)';


-- ---------------------------------------------------------------------------
-- 4. incidents → hypertable
--    시간 범위: created_at (TIMESTAMPTZ)
--    청크 간격: 7일
-- ---------------------------------------------------------------------------

SELECT create_hypertable(
    'incidents',
    'created_at',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists        => TRUE
);

SELECT add_retention_policy(
    'incidents',
    drop_after    => INTERVAL '365 days',
    if_not_exists => TRUE
);

COMMENT ON TABLE incidents IS
    'TimescaleDB Hypertable — 인시던트 (청크 간격 7일, 365일 보존)';


-- ---------------------------------------------------------------------------
-- 5. auto_response_logs → hypertable
--    시간 범위: created_at (TIMESTAMPTZ)
--    청크 간격: 7일
-- ---------------------------------------------------------------------------

SELECT create_hypertable(
    'auto_response_logs',
    'created_at',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists        => TRUE
);

SELECT add_retention_policy(
    'auto_response_logs',
    drop_after    => INTERVAL '180 days',
    if_not_exists => TRUE
);

COMMENT ON TABLE auto_response_logs IS
    'TimescaleDB Hypertable — 자동 대응 로그 (청크 간격 7일, 180일 보존)';


-- ---------------------------------------------------------------------------
-- 6. 연속 집계(Continuous Aggregates) — 실시간 대시보드 최적화
--    설계서: 시계열 KPI 집계 뷰
-- ---------------------------------------------------------------------------

-- 테넌트별 1시간 단위 시그널 집계
CREATE MATERIALIZED VIEW IF NOT EXISTS signals_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', detected_at)  AS bucket,
    tenant_id,
    rule_id,
    severity,
    count(*)                            AS signal_count,
    avg(confidence)                     AS avg_confidence
FROM signals
GROUP BY bucket, tenant_id, rule_id, severity
WITH NO DATA;

SELECT add_continuous_aggregate_policy(
    'signals_hourly',
    start_offset  => INTERVAL '3 hours',
    end_offset    => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

COMMENT ON MATERIALIZED VIEW signals_hourly IS
    'TimescaleDB Continuous Aggregate — 테넌트별 1시간 시그널 집계 (대시보드 최적화)';


-- 테넌트별 1일 단위 인시던트 집계
CREATE MATERIALIZED VIEW IF NOT EXISTS incidents_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', created_at)    AS bucket,
    tenant_id,
    severity,
    status,
    count(*)                            AS incident_count,
    avg(detection_confidence)           AS avg_confidence
FROM incidents
GROUP BY bucket, tenant_id, severity, status
WITH NO DATA;

SELECT add_continuous_aggregate_policy(
    'incidents_daily',
    start_offset  => INTERVAL '2 days',
    end_offset    => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

COMMENT ON MATERIALIZED VIEW incidents_daily IS
    'TimescaleDB Continuous Aggregate — 테넌트별 1일 인시던트 집계 (KPI/보고서 최적화)';


-- ---------------------------------------------------------------------------
-- 7. TimescaleDB 설정 확인 쿼리 (실행 후 검증용)
-- ---------------------------------------------------------------------------

-- 아래 쿼리로 hypertable 등록 확인:
-- SELECT hypertable_name, num_chunks FROM timescaledb_information.hypertables;

-- 아래 쿼리로 압축/보존 정책 확인:
-- SELECT * FROM timescaledb_information.jobs WHERE application_name LIKE '%Policy%';
