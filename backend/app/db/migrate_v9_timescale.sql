-- v9 TimescaleDB Hypertable Migration — v4.0 설계서
-- NOTE: AWS RDS PostgreSQL은 TimescaleDB extension을 지원하지 않습니다.
--       이 마이그레이션은 RDS 환경에서 자동으로 건너뜁니다.
--       TimescaleDB가 필요한 환경(자체 관리 PostgreSQL)에서는
--       원본 migrate_v9_timescale_full.sql을 수동으로 실행하세요.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'
    ) THEN
        RAISE NOTICE 'TimescaleDB available — run migrate_v9_timescale_full.sql manually to activate hypertables';
    ELSE
        RAISE NOTICE 'TimescaleDB not available (RDS/managed PostgreSQL) — v9 migration skipped. Performance optimization not applied.';
    END IF;
END;
$$;
