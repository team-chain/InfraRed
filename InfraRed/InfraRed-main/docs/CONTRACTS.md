# InfraRed 공용 계약

세 명 모두 아래 계약을 기준으로 개발합니다. 이 파일과 `backend/app/models/` 변경은 반드시 서로 공유하고 리뷰합니다.

## Raw Event Envelope

위치: `backend/app/models/envelope.py`

필수 필드:

- `event_id`
- `tenant_id`
- `agent_id`
- `timestamp`

권장 필드:

- `asset_id`
- `host`
- `raw_source`
- `raw_line`
- `file_inode`
- `file_offset`

Ingestion API는 envelope 수준만 빠르게 검증하고, 의미 해석은 Detection Worker가 맡습니다.

## Redis Streams

위치: `backend/app/redis_kv/streams.py`

- `tenant:{tid}:stream:events:raw`
- `tenant:{tid}:stream:events:deadletter`
- `tenant:{tid}:stream:events:failed`
- `tenant:{tid}:stream:signals:matched`
- `tenant:{tid}:stream:signals:enriched`
- `tenant:{tid}:stream:incidents:new`

Consumer Group:

- `detection-workers`
- `enrichment-workers`
- `correlation-workers`
- `llm-workers`
- `dispatcher-workers`

## PostgreSQL Tables

위치: `backend/app/db/schema.sql`

- `tenants`
- `assets`
- `agents`
- `detection_rules`
- `normalized_events`
- `signals`
- `incidents`
- `incident_evidence`
- `llm_results`
- `users`
- `audit_logs`

## Incident Contract API

Endpoint:

```text
GET /incidents/{incident_id}
```

응답 구조:

```json
{
  "incident": {},
  "evidence_timeline": [],
  "llm_result": {}
}
```

C 영역의 LLM Worker와 Dashboard는 이 API를 기준으로 Incident를 소비합니다.
