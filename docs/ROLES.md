# InfraRed 3인 역할 분담

이 문서는 세 명이 같은 초기 구성을 받은 뒤 충돌 없이 나눠 작업하기 위한 경계 문서입니다.

## A - 데이터 수집/전송

소유 경로:

- `agent/`
- `backend/app/ingestion/`
- `backend/app/redis_kv/`
- `infra/docker/`
- `infra/redis/`
- `docker-compose.yml`

책임:

- `auth.log` tailing
- log rotation 감지
- SQLite offset 저장
- 민감정보 마스킹
- Agent Heartbeat
- JWT 검증
- Raw Event Envelope 검증
- Redis `events:raw` XADD
- Dead Letter Stream 설계
- 멀티테넌시 stream/key 격리

완료 기준:

- Agent가 중복 전송 없이 로그를 읽는다.
- Ingestion API가 envelope를 검증하고 Redis Stream에 적재한다.
- 실패 이벤트가 Dead Letter로 분리된다.

## B - 탐지/분석 엔진

소유 경로:

- `backend/app/workers/detection/`
- `backend/app/workers/enrichment/`
- `backend/app/workers/correlation/`
- `backend/app/db/`
- `backend/app/models/signal.py`
- `backend/app/models/incident.py`

책임:

- `raw_line` 파싱
- Normalized Event 저장
- Event Dedup
- AUTH-001~005 Rule Match
- MITRE ATT&CK 매핑
- GeoIP/CTI enrichment
- Signal correlation
- Kill Chain 전이
- Evidence Timeline
- Severity/Confidence/Priority 산정
- Incident Dedup
- PostgreSQL 저장
- C 영역으로 `incidents:new` trigger 발행

완료 기준:

- Redis raw event가 signal과 incident로 이어진다.
- DB에 `normalized_events`, `signals`, `incidents`, `incident_evidence`가 남는다.
- C가 사용할 Incident Contract API가 필요한 데이터를 조회할 수 있다.

## C - AI/알림/프론트엔드

소유 경로:

- `backend/app/workers/llm/`
- `backend/app/dispatcher/`
- `backend/app/iam/`
- `frontend/`
- `infra/prometheus/`
- `infra/grafana/`
- `backend/app/models/llm.py`

책임:

- Redis `incidents:new` 수신
- Incident Contract API 호출
- Bedrock Claude 연동
- Static Playbook fallback
- LLM 결과 캐싱
- Slack Webhook 발송
- Email 발송
- 고객용 웹 대시보드
- IAM/RBAC
- Audit Log
- Prometheus/Grafana 구성

완료 기준:

- Incident 생성 후 LLM 결과가 `llm_results`에 저장된다.
- Dashboard에서 Incident 목록, LLM 요약, Evidence Timeline을 볼 수 있다.
- 알림 채널이 설정된 경우 Slack/Email로 발송된다.
