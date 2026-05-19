-- v5: Billing 스키마 추가

-- tenants에 billing 컬럼 추가
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS plan VARCHAR(20) DEFAULT 'starter',
    ADD COLUMN IF NOT EXISTS plan_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS stripe_subscription_item_id VARCHAR(100),
    ADD COLUMN IF NOT EXISTS billing_email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS grace_period_ends_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS agent_limit INT DEFAULT 3;

-- Stripe 웹훅 이벤트 이력
CREATE TABLE IF NOT EXISTS billing_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id TEXT NOT NULL,
    stripe_event_id VARCHAR(200) UNIQUE,
    event_type VARCHAR(100),
    payload JSONB,
    processed_at TIMESTAMPTZ DEFAULT NOW()
);

-- 에이전트 사용량 기록
CREATE TABLE IF NOT EXISTS agent_usage_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id TEXT NOT NULL,
    reported_at TIMESTAMPTZ DEFAULT NOW(),
    agent_count INT NOT NULL,
    stripe_reported BOOLEAN DEFAULT false
);

-- UEBA daily_user_profiles 테이블
CREATE TABLE IF NOT EXISTS daily_user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id TEXT NOT NULL,
    user_account TEXT NOT NULL,
    profile_date DATE NOT NULL,
    login_hour_mean FLOAT DEFAULT 0,
    login_hour_std FLOAT DEFAULT 0,
    login_count INT DEFAULT 0,
    off_hours_login_count INT DEFAULT 0,
    unique_source_ips INT DEFAULT 0,
    unique_countries INT DEFAULT 0,
    new_ip_ratio FLOAT DEFAULT 0,
    failed_login_count INT DEFAULT 0,
    success_after_failure INT DEFAULT 0,
    commands_executed INT DEFAULT 0,
    sudo_commands INT DEFAULT 0,
    files_accessed INT DEFAULT 0,
    session_duration_mean FLOAT DEFAULT 0,
    concurrent_sessions INT DEFAULT 0,
    anomaly_score FLOAT,
    is_anomalous BOOLEAN DEFAULT false,
    model_version VARCHAR(20),
    model_type VARCHAR(20) DEFAULT 'isolation_forest',
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, user_account, profile_date)
);

CREATE INDEX IF NOT EXISTS idx_billing_events_tenant ON billing_events(tenant_id, processed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_usage_tenant ON agent_usage_reports(tenant_id, reported_at DESC);
CREATE INDEX IF NOT EXISTS idx_daily_profiles_tenant_date ON daily_user_profiles(tenant_id, profile_date DESC);
CREATE INDEX IF NOT EXISTS idx_daily_profiles_anomalous ON daily_user_profiles(tenant_id, is_anomalous) WHERE is_anomalous = true;
