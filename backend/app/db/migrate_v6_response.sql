-- v6 Response & Forensics Schema Migration
-- 기존 v5_billing.sql 이후 적용 (파일명 v6 시작)

-- ── 포렌식 번들 메타데이터 ──────────────────────────────────────────────── --
CREATE TABLE IF NOT EXISTS forensic_bundles (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id     TEXT NOT NULL,
    incident_id   TEXT NOT NULL,
    asset_id      TEXT,
    collected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    s3_key        TEXT NOT NULL,
    manifest_sig  TEXT NOT NULL,
    item_count    INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_forensic_bundles_incident
    ON forensic_bundles(incident_id);

CREATE INDEX IF NOT EXISTS idx_forensic_bundles_tenant
    ON forensic_bundles(tenant_id, collected_at DESC);

-- ── 취약점 스캔 결과 ────────────────────────────────────────────────────── --
CREATE TABLE IF NOT EXISTS vuln_scan_results (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id     TEXT NOT NULL,
    asset_id      TEXT NOT NULL,
    scanned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    findings      JSONB NOT NULL DEFAULT '[]',
    critical_count INT NOT NULL DEFAULT 0,
    high_count    INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vuln_scan_asset
    ON vuln_scan_results(tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_vuln_scan_scanned_at
    ON vuln_scan_results(scanned_at DESC);
