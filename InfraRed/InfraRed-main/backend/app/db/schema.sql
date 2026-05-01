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
    plain_summary         TEXT NOT NULL,
    attack_intent         TEXT,
    kill_chain_analysis   TEXT,
    recommended_actions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_note       TEXT,
    model                 TEXT NOT NULL,
    cached                BOOLEAN NOT NULL DEFAULT FALSE,
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_llm_incident ON llm_results(incident_id);

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
