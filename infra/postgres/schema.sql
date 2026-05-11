CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    plan          TEXT NOT NULL DEFAULT 'mvp',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id      TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    hostname      TEXT NOT NULL,
    os            TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);

CREATE TABLE IF NOT EXISTS agents (
    agent_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    asset_id        TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'registered',
    last_heartbeat  TIMESTAMPTZ,
    agent_version   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id          TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    source           TEXT NOT NULL,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    config           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id      TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    asset_id      TEXT,
    agent_id      TEXT,
    event_type    TEXT NOT NULL,
    timestamp     TIMESTAMPTZ NOT NULL,
    host          TEXT,
    username      TEXT,
    source_ip     INET,
    result        TEXT,
    raw_source    TEXT NOT NULL DEFAULT 'auth.log',
    late_event    BOOLEAN NOT NULL DEFAULT FALSE,
    payload       JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_norm_events_tenant_ts ON normalized_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_norm_events_ip ON normalized_events(source_ip);

CREATE TABLE IF NOT EXISTS signals (
    signal_id              TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL,
    asset_id               TEXT NOT NULL,
    rule_id                TEXT NOT NULL REFERENCES detection_rules(rule_id),
    rule_name              TEXT NOT NULL,
    mitre_tactic           TEXT,
    mitre_technique        TEXT,
    mitre_subtechnique     TEXT,
    kill_chain_stage       TEXT,
    source_ip              INET,
    username               TEXT,
    detected_count         INT NOT NULL DEFAULT 1,
    detected_at            TIMESTAMPTZ NOT NULL,
    window_start           TIMESTAMPTZ,
    window_end             TIMESTAMPTZ,
    triggering_event_ids   JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes                  TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_signals_tenant_ts ON signals(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_signals_rule ON signals(rule_id);
CREATE INDEX IF NOT EXISTS idx_signals_ip ON signals(source_ip);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id        TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    asset_id           TEXT NOT NULL,
    severity           TEXT NOT NULL,
    confidence         TEXT NOT NULL,
    priority           TEXT NOT NULL,
    kill_chain_stage   TEXT NOT NULL,
    mitre_tactic       TEXT,
    mitre_technique    TEXT,
    cti_enrichment     JSONB,
    source_ip          INET,
    username           TEXT,
    signal_ids         JSONB NOT NULL DEFAULT '[]'::jsonb,
    status             TEXT NOT NULL DEFAULT 'open',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_ts ON incidents(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS incident_evidence (
    id             BIGSERIAL PRIMARY KEY,
    incident_id    TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    tenant_id      TEXT NOT NULL,
    timestamp      TIMESTAMPTZ NOT NULL,
    description    TEXT NOT NULL,
    signal_id      TEXT,
    rule_id        TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id, timestamp);

CREATE TABLE IF NOT EXISTS llm_results (
    id                    BIGSERIAL PRIMARY KEY,
    incident_id           TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    tenant_id             TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending',  -- pending | success | fallback
    plain_summary         TEXT,                             -- pending 시 NULL 허용
    attack_intent         TEXT,
    kill_chain_analysis   TEXT,
    recommended_actions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_note       TEXT,
    failure_reason        TEXT,                             -- timeout | api_error 등
    model                 TEXT,                             -- pending 시 NULL 허용
    cached                BOOLEAN NOT NULL DEFAULT FALSE,
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_llm_incident ON llm_results(incident_id);

-- demo_signals: Honeypot /demo 방문자 정보 (incidents와 물리적 분리, 설계서 6.5/17.3)
CREATE TABLE IF NOT EXISTS demo_signals (
    demo_signal_id   TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    asset_id         TEXT NOT NULL,
    source_ip        TEXT,                      -- 마스킹 표시용 (예: 121.135.xx.xx)
    source_ip_hash   TEXT,                      -- 원본 IP 해시 (중복 식별용, 평문 미저장)
    country          TEXT,
    region           TEXT,
    accuracy_radius  INT,
    device_type      TEXT,
    os_family        TEXT,
    browser_family   TEXT,
    accept_language  TEXT,
    path             TEXT NOT NULL DEFAULT '/demo',
    severity         TEXT NOT NULL DEFAULT 'info',
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_demo_signals_tenant_ts ON demo_signals(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_demo_signals_expires   ON demo_signals(expires_at);

-- auto_response_logs: 자동 대응 실행 이력 (append-only 불변 감사 로그, 설계서 6.7)
CREATE TABLE IF NOT EXISTS auto_response_logs (
    auto_response_id  TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    incident_id       TEXT,
    rule_id           TEXT,
    severity          TEXT,
    actions_taken     JSONB NOT NULL DEFAULT '[]'::jsonb,
    dry_run           BOOLEAN NOT NULL DEFAULT TRUE,
    triggered_by      TEXT,
    policy_reason     TEXT,
    policy_version    INT,
    executed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reversed          BOOLEAN NOT NULL DEFAULT FALSE,
    reversed_at       TIMESTAMPTZ,
    reversed_by       TEXT
);
CREATE INDEX IF NOT EXISTS idx_autoresponse_tenant_ts ON auto_response_logs(tenant_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_autoresponse_incident  ON auto_response_logs(incident_id);

-- ip_policies: 테넌트별 IP 허용/차단 정책 3종 분리 (설계서 6.6)
-- policy_type: 'agent_access' | 'threat_ip' | 'dashboard_access'
CREATE TABLE IF NOT EXISTS ip_policies (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    policy_type     TEXT NOT NULL,
    policy_version  INT NOT NULL DEFAULT 1,
    mode            TEXT NOT NULL DEFAULT 'allow_all',
    allowlist       JSONB NOT NULL DEFAULT '[]'::jsonb,
    denylist        JSONB NOT NULL DEFAULT '[]'::jsonb,
    country_block   JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_agents  JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT,
    UNIQUE (tenant_id, policy_type)
);
CREATE INDEX IF NOT EXISTS idx_ip_policies_tenant ON ip_policies(tenant_id, policy_type);

CREATE TABLE IF NOT EXISTS users (
    user_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'analyst',
    mfa_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS known_ips (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    username    TEXT NOT NULL,
    source_ip   INET NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, asset_id, username, source_ip)
);
CREATE INDEX IF NOT EXISTS idx_known_ips_lookup ON known_ips(tenant_id, asset_id, username);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT,
    ip          INET,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata    JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs(tenant_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    key_hash     TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL DEFAULT 'default',
    source       TEXT NOT NULL DEFAULT 'api',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id          TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    response_mode      TEXT NOT NULL DEFAULT 'manual',
    auto_block_min_severity TEXT NOT NULL DEFAULT 'critical',
    discord_webhook_url TEXT,
    alert_email_to     TEXT,
    auth_brute_force_threshold     INT NOT NULL DEFAULT 3,
    auth_brute_force_window_sec    INT NOT NULL DEFAULT 300,
    auth_invalid_user_threshold    INT NOT NULL DEFAULT 5,
    auth_fail_then_success_threshold INT NOT NULL DEFAULT 3,
    web_admin_scan_threshold       INT NOT NULL DEFAULT 30,
    web_404_threshold              INT NOT NULL DEFAULT 50,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pending_actions (
    action_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    incident_id    TEXT REFERENCES incidents(incident_id) ON DELETE SET NULL,
    action_type    TEXT NOT NULL,
    target         TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}'::jsonb,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at    TIMESTAMPTZ,
    resolved_by    TEXT,
    result         JSONB
);
CREATE INDEX IF NOT EXISTS idx_pending_actions_tenant ON pending_actions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_pending_actions_incident ON pending_actions(incident_id);
