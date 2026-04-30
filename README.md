# InfraRed

InfraRed는 `auth.log` 기반 SSH 이상 행위를 수집하고, Redis Streams와 Worker 파이프라인을 거쳐 Incident로 묶은 뒤 LLM 요약과 알림, 대시보드까지 연결하는 MVP입니다.

이 저장소는 3명이 **동일하게 가져가는 초기 구성**입니다. 폴더는 역할별로 소유권을 나누되, 공용 계약은 `backend/app/models/`, Redis/DB 계약은 `backend/app/redis_kv/`, `backend/app/db/schema.sql`에 모았습니다.

## 역할 경계

| 역할 | 담당 | 주요 경로 |
| --- | --- | --- |
| A | 로그 수집, 마스킹, Envelope 생성, Ingestion API, Redis XADD, 인프라 | `agent/`, `backend/app/ingestion/`, `backend/app/redis_kv/`, `infra/`, `docker-compose.yml` |
| B | raw_line 파싱, 정규화, Dedup, Rule Match, Enrichment, Correlation, Incident 저장 | `backend/app/workers/detection/`, `backend/app/workers/enrichment/`, `backend/app/workers/correlation/`, `backend/app/db/` |
| C | Incident Contract API 소비, LLM 분석, Slack/Email, Dashboard, IAM/RBAC, Monitoring | `backend/app/workers/llm/`, `backend/app/dispatcher/`, `backend/app/iam/`, `frontend/`, `infra/prometheus/`, `infra/grafana/` |

자세한 경계는 [docs/ROLES.md](docs/ROLES.md)를 보세요.

## 빠른 시작

```powershell
Copy-Item .env.example .env
python scripts/generate_jwt.py --role agent
```

출력된 JWT를 `.env`의 `AGENT_TOKEN`에 넣습니다.

```powershell
docker compose up --build
```

서비스 포트:

- API: http://localhost:8000
- Dashboard: http://localhost:3000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001 (`admin` / `admin`)
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

Agent를 기다리지 않고 샘플 이벤트를 넣으려면:

```powershell
python scripts/send_test_event.py
```

## 파이프라인

```text
Docker Agent
  -> POST /ingest
  -> tenant:{tid}:stream:events:raw
  -> Detection Worker
  -> tenant:{tid}:stream:signals:matched
  -> Enrichment Worker
  -> tenant:{tid}:stream:signals:enriched
  -> Correlation Worker
  -> PostgreSQL incidents / evidence
  -> tenant:{tid}:stream:incidents:new
  -> LLM Worker + Dispatcher
  -> Dashboard / Slack / Email
```

## 공용 계약

- Raw Event Envelope: `backend/app/models/envelope.py`
- Normalized Event: `backend/app/models/envelope.py`
- Signal: `backend/app/models/signal.py`
- Incident: `backend/app/models/incident.py`
- LLM Result: `backend/app/models/llm.py`
- Redis Stream names: `backend/app/redis_kv/streams.py`
- Redis Key patterns: `backend/app/redis_kv/keys.py`
- PostgreSQL schema: `backend/app/db/schema.sql`

## 다음 작업

1. A: 실제 운영 서버의 `/var/log/auth.log` 마운트 방식과 JWT 발급/회전 정책 확정
2. B: AUTH-001~005 임계값, Incident merge 정책, GeoIP/CTI Provider 교체
3. C: Dashboard 인증 적용, Bedrock 프롬프트 고도화, Slack/Email 템플릿 확정
>>>>>>> e0f66ce (Initial InfraRed MVP scaffold)
