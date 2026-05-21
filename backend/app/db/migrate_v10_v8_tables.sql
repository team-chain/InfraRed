-- v10 Migration — v8.0 보안 심화 DB 테이블 6종
-- 대상 설계서: InfraRed_v8_보안심화_설계서.md §11
-- 적용 순서: migrate_v8_security.sql 다음 실행

-- ---------------------------------------------------------------------------
-- 1. Impossible Travel 이력 (TRAVEL-001)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS login_location_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    account      VARCHAR(255) NOT NULL,
    source_ip    INET NOT NULL,
    city         VARCHAR(100),
    country      VARCHAR(10),
    latitude     DECIMAL(9, 6),
    longitude    DECIMAL(9, 6),
    logged_in_at TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_location_account
    ON login_location_history (tenant_id, account, logged_in_at DESC);

COMMENT ON TABLE login_location_history IS
    'Impossible Travel 탐지를 위한 로그인 위치 이력 (TRAVEL-001, T1078)';

COMMENT ON COLUMN login_location_history.account IS
    '로그인한 계정 식별자 (username 또는 email)';


-- ---------------------------------------------------------------------------
-- 2. First-Execution 베이스라인 (EXEC-FIRST-001/002)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS known_binary_hashes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    sha256     CHAR(64) NOT NULL,
    exe_path   TEXT NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT now(),
    UNIQUE (tenant_id, sha256)
);

CREATE INDEX IF NOT EXISTS idx_known_binary_hashes_lookup
    ON known_binary_hashes (tenant_id, sha256);

CREATE INDEX IF NOT EXISTS idx_known_binary_hashes_path
    ON known_binary_hashes (tenant_id, exe_path);

COMMENT ON TABLE known_binary_hashes IS
    '에이전트 설치 후 학습된 바이너리 SHA-256 베이스라인 (EXEC-FIRST-001/002, T1554/T1059)';

COMMENT ON COLUMN known_binary_hashes.sha256 IS
    'SHA-256 hex digest (64자)';

COMMENT ON COLUMN known_binary_hashes.exe_path IS
    '최초 관찰 시점의 실행 파일 절대 경로';


-- ---------------------------------------------------------------------------
-- 3. Process Ancestry 학습 데이터 (EXEC-ANCESTRY-002)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS known_process_pairs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    parent_name VARCHAR(255) NOT NULL,
    child_name  VARCHAR(255) NOT NULL,
    first_seen  TIMESTAMPTZ DEFAULT now(),
    occurrence  INT DEFAULT 1,
    UNIQUE (tenant_id, parent_name, child_name)
);

CREATE INDEX IF NOT EXISTS idx_known_process_pairs_lookup
    ON known_process_pairs (tenant_id, parent_name, child_name);

COMMENT ON TABLE known_process_pairs IS
    '정상 부모-자식 프로세스 계보 학습 데이터 (EXEC-ANCESTRY-002, T1059). '
    '처음 관찰된 조합은 EXEC-ANCESTRY-002(HIGH)로 경보 후 여기에 학습됨.';


-- ---------------------------------------------------------------------------
-- 4. JIT SSH 키 이력 (PERSIST-JIT)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS jit_ssh_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    command_id      UUID NOT NULL REFERENCES agent_commands(id) ON DELETE SET NULL,
    target_user     VARCHAR(100) NOT NULL,
    key_fingerprint VARCHAR(255) NOT NULL,
    injected_at     TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoke_reason   VARCHAR(50)  -- 'ttl_expired' | 'manual' | 'emergency'
);

CREATE INDEX IF NOT EXISTS idx_jit_ssh_keys_tenant_agent
    ON jit_ssh_keys (tenant_id, agent_id, injected_at DESC);

CREATE INDEX IF NOT EXISTS idx_jit_ssh_keys_active
    ON jit_ssh_keys (tenant_id, expires_at)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE jit_ssh_keys IS
    'JIT SSH 임시 키 주입 이력. '
    '평소 authorized_keys = 빈 파일. 관리자 요청 시 TTL 기반으로 임시 주입. (T1098.004)';

COMMENT ON COLUMN jit_ssh_keys.revoke_reason IS
    'ttl_expired: TTL 만료 자동 삭제 | manual: 수동 삭제 | emergency: 긴급 삭제';


-- ---------------------------------------------------------------------------
-- 5. AWS Honey Key 설정 이력 (DECEPTION-003)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS honey_key_configs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    iam_user      VARCHAR(255) NOT NULL,
    access_key_id VARCHAR(20)  NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT now(),
    is_active     BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_honey_key_configs_tenant
    ON honey_key_configs (tenant_id, is_active);

CREATE INDEX IF NOT EXISTS idx_honey_key_configs_key_id
    ON honey_key_configs (access_key_id);

COMMENT ON TABLE honey_key_configs IS
    'AWS Honey Access Key 설정. '
    'IAM 명시적 Deny* 정책 부착. CloudTrail 사용 감지 시 DECEPTION-003(CRITICAL) 발생. '
    '(T1552.005)';

COMMENT ON COLUMN honey_key_configs.iam_user IS
    'Honey Key가 연결된 IAM User 이름 (예: infrared-honey-{tenant_id[:8]})';

COMMENT ON COLUMN honey_key_configs.access_key_id IS
    'AWS Access Key ID (AKIA...)';


-- ---------------------------------------------------------------------------
-- 6. Canary Pack 배포 이력
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS canary_pack_deployments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    profile     VARCHAR(100) NOT NULL,
    deployed_at TIMESTAMPTZ DEFAULT now(),
    removed_at  TIMESTAMPTZ,
    token_paths JSONB NOT NULL  -- 배포된 미끼 파일 경로 목록
);

CREATE INDEX IF NOT EXISTS idx_canary_pack_deployments_tenant
    ON canary_pack_deployments (tenant_id, deployed_at DESC);

CREATE INDEX IF NOT EXISTS idx_canary_pack_deployments_active
    ON canary_pack_deployments (tenant_id, agent_id)
    WHERE removed_at IS NULL;

COMMENT ON TABLE canary_pack_deployments IS
    'Canary Pack CLI를 통해 배포된 미끼 파일 이력. '
    'profile: web-server | aws | docker | minimal. '
    'token_paths: [{type, path, deployed_at}, ...] JSON 배열.';

COMMENT ON COLUMN canary_pack_deployments.token_paths IS
    '배포된 미끼 항목 목록: [{type: "file"|"aws_honey_key", path: "...", deployed_at: "..."}]';


-- ---------------------------------------------------------------------------
-- migrate 함수 업데이트용 더미 반환
-- ---------------------------------------------------------------------------

SELECT 'v10 migration complete — 6 v8 tables created' AS result;
