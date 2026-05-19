# 섹션 7 — DB 스키마 변경 전체 요약
> InfraRed 고도화 설계서 v2.0 §7 (미완성 → 완성)

---

## 7.1 마이그레이션 파일 목록

| 파일 | 버전 | 주요 내용 |
|------|------|-----------|
| `schema.sql` | v1.0 기반 | 기본 테이블 (incidents, signals, agents, tenants 등) |
| `migrate_v2.sql` | v2.0 고도화 | Phase 1~5 전체 스키마 (365줄) |
| `migrate_v3_freetier.sql` | v1.0 프리티어 | PostgreSQL FTS (GIN 인덱스, OpenSearch 대체) |
| `migrate_v4_v3_schema.sql` | v3/v4 엔터프라이즈 | novelty_score, 공격체인, CTI 멀티소스 |
| `migrate_v5_billing.sql` | v4 엔터프라이즈 | Stripe 연동, 구독 모델 |
| `migrate_v6_response.sql` | v3 대응 | 대응 정책 매트릭스, TTL 차단 |
| `migrate_v7_gdpr.sql` | v7 보안고도화 | GDPR 삭제 요청, 법적 보류 테이블 |
| `migrate_v7_ops_quality.sql` | v7 운영품질 | KPI 자동계산, 감사로그 불변성 |
| `migrate_v8_security.sql` | v8 보안심화 | Canary, Honeytoken, Impossible Travel |

---

## 7.2 핵심 테이블 스키마 (v2.0 고도화 기준)

### 7.2.1 인시던트 워크플로우 테이블

```sql
-- 인시던트 상태 이력 (Phase 1)
CREATE TABLE incident_status_history (
    history_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   UUID NOT NULL REFERENCES incidents(incident_id),
    tenant_id     UUID NOT NULL,
    old_status    TEXT NOT NULL,
    new_status    TEXT NOT NULL,  -- open|ack|in_progress|contained|resolved|closed
    changed_by    UUID,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes         TEXT DEFAULT ''
);

-- 인시던트 코멘트 (Phase 1)
CREATE TABLE incident_comments (
    comment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   UUID NOT NULL REFERENCES incidents(incident_id),
    tenant_id     UUID NOT NULL,
    author_id     UUID,
    author_email  TEXT NOT NULL,
    body          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 인시던트 링크 (related/duplicate/caused_by) (Phase 1)
CREATE TABLE incident_links (
    link_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id     UUID NOT NULL REFERENCES incidents(incident_id),
    target_id     UUID NOT NULL REFERENCES incidents(incident_id),
    link_type     TEXT NOT NULL,  -- related|duplicate|caused_by
    tenant_id     UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 7.2.2 알림 그룹핑 (Phase 1-B)

```sql
CREATE TABLE alert_groups (
    group_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    group_key       TEXT NOT NULL,   -- 그룹핑 키 (rule_id + source_ip 해시 등)
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    signal_count    INT NOT NULL DEFAULT 1,
    representative_incident_id UUID REFERENCES incidents(incident_id),
    is_open         BOOLEAN NOT NULL DEFAULT true
);
```

### 7.2.3 룰 관리 플랫폼 (Phase 2)

```sql
-- 탐지 룰 버전 이력
CREATE TABLE detection_rule_versions (
    version_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id           UUID NOT NULL REFERENCES detection_rules(rule_id),
    tenant_id         UUID NOT NULL,
    version_number    INT NOT NULL,
    display_name      TEXT NOT NULL,
    conditions        JSONB NOT NULL DEFAULT '{}',
    severity          TEXT NOT NULL,
    is_active_version BOOLEAN NOT NULL DEFAULT false,
    activated_by      UUID,
    activated_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- FP(False Positive) 통계
CREATE TABLE rule_fp_stats (
    stat_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id      UUID NOT NULL REFERENCES detection_rules(rule_id),
    tenant_id    UUID NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    total_alerts INT NOT NULL DEFAULT 0,
    fp_count     INT NOT NULL DEFAULT 0,
    fp_rate      FLOAT GENERATED ALWAYS AS (
        CASE WHEN total_alerts > 0
             THEN fp_count::float / total_alerts * 100
             ELSE 0 END
    ) STORED,
    computed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 7.2.4 Allowlist / Suppression / Maintenance Window (Phase 2-C)

```sql
CREATE TABLE allowlist_entries (
    entry_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    entry_type   TEXT NOT NULL,  -- ip|cidr|hostname|user|process
    value        TEXT NOT NULL,
    rule_ids     UUID[] DEFAULT '{}',
    expires_at   TIMESTAMPTZ,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE suppression_rules (
    suppression_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL,
    name           TEXT NOT NULL,
    conditions     JSONB NOT NULL DEFAULT '{}',
    expires_at     TIMESTAMPTZ,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE maintenance_windows (
    window_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    name         TEXT NOT NULL,
    starts_at    TIMESTAMPTZ NOT NULL,
    ends_at      TIMESTAMPTZ NOT NULL,
    suppressed_rule_ids UUID[] DEFAULT '{}',
    is_active    BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 7.2.5 RBAC + 테넌트 멤버십 (Phase 3)

```sql
CREATE TYPE user_role AS ENUM ('owner', 'admin', 'analyst', 'viewer');

CREATE TABLE tenant_memberships (
    membership_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    user_id       UUID NOT NULL,
    email         TEXT NOT NULL,
    role          user_role NOT NULL DEFAULT 'viewer',
    invited_by    UUID,
    joined_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id)
);
```

### 7.2.6 에이전트 Lifecycle (Phase 3)

```sql
CREATE TABLE agent_versions (
    version_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(agent_id),
    tenant_id     UUID NOT NULL,
    version_str   TEXT NOT NULL,  -- e.g. "1.2.3"
    deployed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_current    BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE agent_commands (
    command_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID NOT NULL REFERENCES agents(agent_id),
    tenant_id     UUID NOT NULL,
    command_type  TEXT NOT NULL,  -- restart|update|config_reload|isolate
    payload       JSONB DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending|sent|ack|done|failed
    issued_by     UUID,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ack_at        TIMESTAMPTZ
);
```

### 7.2.7 GDPR 데이터 거버넌스 (v7)

```sql
-- (migrate_v7_gdpr.sql 참조)
-- gdpr_erasure_requests  — 삭제 요청 추적
-- gdpr_legal_holds       — 법적 보류 설정
-- gdpr_deletion_schedule — 보존 기간 만료 후 자동 삭제 예약
```

---

## 7.3 인덱스 전략 요약

```sql
-- 핵심 조회 패턴별 인덱스
CREATE INDEX idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX idx_signals_tenant_ts ON signals(tenant_id, created_at DESC);
CREATE INDEX idx_agents_tenant_status ON agents(tenant_id, status);
CREATE INDEX idx_detection_rules_tenant ON detection_rules(tenant_id, is_active);
CREATE INDEX idx_rule_fp_stats_rule_id ON rule_fp_stats(rule_id, period_start DESC);
CREATE INDEX idx_allowlist_tenant ON allowlist_entries(tenant_id, entry_type);

-- FTS (프리티어: OpenSearch 대체)
CREATE INDEX idx_signals_fts ON signals USING GIN(search_vector);

-- pgvector (유사 인시던트 RAG)
CREATE INDEX idx_incidents_embedding ON incidents USING ivfflat(embedding vector_cosine_ops)
    WITH (lists = 100);
```

---

## 7.4 마이그레이션 실행 순서

```bash
# 순서 중요: 의존성 순서대로 실행
psql $DATABASE_URL -f backend/app/db/schema.sql
psql $DATABASE_URL -f backend/app/db/migrate_v2.sql
psql $DATABASE_URL -f backend/app/db/migrate_v3_freetier.sql
psql $DATABASE_URL -f backend/app/db/migrate_v4_v3_schema.sql
psql $DATABASE_URL -f backend/app/db/migrate_v5_billing.sql
psql $DATABASE_URL -f backend/app/db/migrate_v6_response.sql
psql $DATABASE_URL -f backend/app/db/migrate_v7_gdpr.sql
psql $DATABASE_URL -f backend/app/db/migrate_v7_ops_quality.sql
psql $DATABASE_URL -f backend/app/db/migrate_v8_security.sql
```

