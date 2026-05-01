# InfraRed — 역할 A 구현 가이드

> **역할 A 담당 범위**: 로그 수집 → 마스킹 → Envelope 생성 → Ingestion API → Redis XADD → 인프라

---

## 목차

1. [시스템 개요](#1-시스템-개요)
2. [디렉토리 구조](#2-디렉토리-구조)
3. [데이터 흐름](#3-데이터-흐름)
4. [컴포넌트 상세](#4-컴포넌트-상세)
5. [로컬 실행 (Docker Compose)](#5-로컬-실행-docker-compose)
6. [라이브 로그 생성](#6-라이브-로그-생성)
7. [AWS 배포 (Terraform)](#7-aws-배포-terraform)
8. [Makefile 명령어 레퍼런스](#8-makefile-명령어-레퍼런스)
9. [AUTH 룰 커버리지 확인](#9-auth-룰-커버리지-확인)
10. [트러블슈팅](#10-트러블슈팅)

---

## 1. 시스템 개요

InfraRed는 서버의 `auth.log`를 실시간으로 수집하여 보안 위협을 탐지하는 SIEM 시스템입니다.

```
[서버 auth.log]
      │
      ▼
 Agent (수집/마스킹/Envelope)
      │  JWT + HTTPS
      ▼
 Ingestion API (검증/XADD)
      │
      ▼
 Redis Stream: tenant:{tid}:stream:events:raw
      │
      ▼ (역할 B 이후)
 Detection → Enrichment → Correlation → Incident
```

### 역할 분담

| 역할 | 담당 | 핵심 경로 |
|---|---|---|
| **A (본 문서)** | 수집·전송·인프라 | `agent/`, `backend/app/ingestion/`, `backend/app/redis_kv/`, `infra/`, `docker-compose.yml` |
| B | 탐지·분석 엔진 | `backend/app/workers/detection/`, `enrichment/`, `correlation/`, `db/` |
| C | AI·알림·프론트엔드 | `backend/app/workers/llm/`, `dispatcher/`, `iam/`, `frontend/` |

---

## 2. 디렉토리 구조

```
InfraRed-main/
├── agent/
│   └── infrared_agent/
│       ├── main.py          # 메인 루프 (poll + heartbeat)
│       ├── tailer.py        # auth.log 읽기 + Envelope 생성
│       ├── masking.py       # 민감정보 마스킹 (password, token 등)
│       ├── offset_store.py  # SQLite 기반 읽기 위치 저장
│       ├── client.py        # Ingestion API HTTP 클라이언트
│       └── config.py        # 환경변수 설정
│
├── backend/
│   └── app/
│       ├── ingestion/
│       │   └── routes.py    # POST /ingest, POST /heartbeat
│       ├── redis_kv/
│       │   ├── streams.py   # Stream 이름 규칙 (멀티테넌시)
│       │   ├── client.py    # Redis 연결 + Consumer Group 생성
│       │   └── keys.py      # KV 키 이름 규칙
│       ├── models/
│       │   ├── envelope.py  # RawEventEnvelope (A↔B 계약)
│       │   ├── heartbeat.py # Heartbeat 모델
│       │   └── dead_letter.py # Dead Letter 모델
│       ├── iam/
│       │   └── security.py  # JWT 생성/검증
│       ├── db/
│       │   ├── schema.sql   # PostgreSQL 스키마
│       │   ├── seed.sql     # 초기 데이터 (tenant, agent, rules)
│       │   └── migrate.py   # AWS RDS 마이그레이션 러너
│       └── config.py        # 전체 설정 (Settings)
│
├── infra/
│   ├── docker/
│   │   ├── agent.Dockerfile    # 비루트 유저, HEALTHCHECK 포함
│   │   └── backend.Dockerfile
│   ├── redis/
│   │   └── redis.conf          # maxmemory 256MB, LRU
│   ├── sample-logs/
│   │   └── auth.log            # AUTH-001~005 전 패턴 포함 (46줄)
│   └── terraform/              # AWS 배포 (아래 섹션 참고)
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       ├── vpc.tf
│       ├── security_groups.tf
│       ├── ecr.tf
│       ├── secrets.tf
│       ├── iam.tf
│       ├── cloudwatch.tf
│       ├── rds.tf
│       ├── elasticache.tf
│       ├── alb.tf
│       ├── ecs.tf
│       └── terraform.tfvars.example
│
├── scripts/
│   ├── generate_jwt.py      # AGENT_TOKEN 발급 도구
│   ├── send_test_event.py   # 샘플 이벤트 전송 테스트
│   ├── generate_logs.py     # 실시간 로그 생성기 (신규)
│   └── aws-deploy.sh        # AWS 전체 배포 자동화 (신규)
│
├── docker-compose.yml       # 로컬 전체 스택
├── Makefile                 # 개발 편의 명령어
└── .env.example             # 환경변수 템플릿
```

---

## 3. 데이터 흐름

### 이벤트 수집 흐름

```
auth.log 새 줄 감지 (2초 poll)
    │
    ├─► inode 확인 → log rotation 감지 → offset 리셋
    │
    ▼
mask_line()
    password= → ***
    token=    → ***
    secret=   → ***
    Bearer    → ***
    │
    ▼
event_id = SHA256(agent_id:path:inode:offset:line)[:32]
    │  (동일 줄 재전송 시 같은 ID → B에서 Dedup 가능)
    │
    ▼
RawEventEnvelope {
    event_id, tenant_id, agent_id, asset_id,
    timestamp, raw_source, raw_line,
    file_inode, file_offset
}
    │
    ▼
POST /ingest  (Authorization: Bearer <JWT>)
    │
    ├─► JWT 검증 (role=agent, tenant_id 일치)
    ├─► 페이로드 크기 확인 (≤ 65KB)
    ├─► Pydantic 스키마 검증
    ├─► 이벤트 시간 확인 (24시간 초과 → Dead Letter)
    │
    ▼
Redis XADD tenant:{tid}:stream:events:raw
    │
    ├─ 실패 시 → tenant:{tid}:stream:events:deadletter
    │
    ▼
202 Accepted  →  offset 저장 (SQLite)
```

### Redis Stream 구조

| Stream 키 | 생산자 | 소비자 |
|---|---|---|
| `tenant:{tid}:stream:events:raw` | Ingestion API | Detection Worker (역할 B) |
| `tenant:{tid}:stream:events:deadletter` | Ingestion API | 수동 재처리 |
| `tenant:{tid}:stream:signals:matched` | Detection | Enrichment |
| `tenant:{tid}:stream:signals:enriched` | Enrichment | Correlation |
| `tenant:{tid}:stream:incidents:new` | Correlation | LLM Worker (역할 C) |

---

## 4. 컴포넌트 상세

### 4.1 Agent — `agent/infrared_agent/`

#### `config.py` 주요 설정

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `AGENT_TOKEN` | (필수) | JWT 토큰 (`scripts/generate_jwt.py`로 발급) |
| `BACKEND_URL` | `http://ingestion:8000/ingest` | 이벤트 전송 엔드포인트 |
| `HEARTBEAT_URL` | `http://ingestion:8000/heartbeat` | 생존신호 엔드포인트 |
| `AGENT_AUTH_LOG_PATH` | `/host/var/log/auth.log` | 감시할 로그 파일 |
| `POLL_INTERVAL_SEC` | `2.0` | 새 줄 확인 주기 (초) |
| `HEARTBEAT_INTERVAL_SEC` | `30` | 생존신호 전송 주기 (초) |
| `AGENT_OFFSET_DB` | `/var/lib/infrared/offset.sqlite` | offset 저장 SQLite 경로 |

#### `offset_store.py` — 중복 방지

- 파일 경로 + **inode** + offset을 SQLite에 저장
- inode가 바뀌면 log rotation으로 판단 → offset 0으로 리셋
- 에이전트 재시작 후에도 이미 전송한 줄은 건너뜀

#### `masking.py` — 마스킹 패턴

```python
(re.compile(r"(?i)(password=)[^\s]+"), r"\1***"),
(re.compile(r"(?i)(token=)[^\s]+"),    r"\1***"),
(re.compile(r"(?i)(secret=)[^\s]+"),   r"\1***"),
(re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1***"),
```

### 4.2 Ingestion API — `backend/app/ingestion/routes.py`

#### `POST /ingest`

```
검증 순서:
1. JWT 검증 (verify_agent_token) → 401/403
2. 페이로드 크기 > 65KB → 413
3. JSON 파싱 + Pydantic 검증 실패 → 422 + Dead Letter
4. tenant_id 불일치 → 403 + Dead Letter
5. 이벤트 시간 > 24h → 422 + Dead Letter
6. Redis XADD (events:raw)
7. 202 Accepted
```

#### `POST /heartbeat`

- JWT 검증 후 `agents.last_heartbeat` 갱신
- 에이전트 상태 모니터링에 사용 (역할 C의 대시보드)

### 4.3 Redis 스트림 — `backend/app/redis_kv/`

**멀티테넌시 격리**: 모든 스트림 키가 `tenant:{tid}:` 접두사를 가져서 테넌트 간 데이터가 섞이지 않습니다.

**Consumer Group**: `detection-workers`, `enrichment-workers` 등으로 나뉘어, 여러 Worker 인스턴스가 메시지를 중복 없이 나눠 처리합니다.

### 4.4 Dead Letter — `backend/app/models/dead_letter.py`

실패한 이벤트가 저장되는 스트림입니다.

| `reason` 값 | 원인 |
|---|---|
| `schema_validation_failed` | Pydantic 검증 오류 |
| `tenant_mismatch` | JWT 테넌트 ≠ envelope 테넌트 |
| `event_too_old` | timestamp 기준 24시간 초과 |

### 4.5 JWT — `backend/app/iam/security.py`

```bash
# 에이전트 토큰 발급 (로컬)
python scripts/generate_jwt.py --role agent

# 관리자 토큰 (개발용)
python scripts/generate_jwt.py --role admin
```

페이로드 구조:
```json
{
  "sub": "agent-001",
  "tenant_id": "company-a",
  "agent_id": "agent-001",
  "role": "agent",
  "iss": "infrared",
  "aud": "infrared-ingest",
  "iat": 1234567890,
  "exp": 1234654290
}
```

---

## 5. 로컬 실행 (Docker Compose)

### 사전 조건

- Docker Desktop 실행 중
- Python 3.11+
- `make` (macOS: Xcode CLT에 포함)

### 초기 설정

```bash
# 1. 환경변수 파일 생성 + AGENT_TOKEN 자동 발급
make setup

# 발급된 토큰이 .env의 AGENT_TOKEN에 자동 저장됨
```

### 실행

```bash
# 전체 스택 백그라운드 실행 (빌드 포함)
make up
```

실행되는 컨테이너:

| 컨테이너 | 설명 | 포트 |
|---|---|---|
| `infrared-postgres` | PostgreSQL 16 | 5432 |
| `infrared-redis` | Redis 7 | 6379 |
| `infrared-ingestion` | Ingestion API | 8000 |
| `infrared-agent` | auth.log 수집 에이전트 | — |
| `infrared-detection` | Detection Worker | — |
| `infrared-enrichment` | Enrichment Worker | — |
| `infrared-correlation` | Correlation Worker | — |
| `infrared-llm` | LLM Worker | — |
| `infrared-frontend` | React 대시보드 | 3000 |
| `infrared-prometheus` | Prometheus | 9090 |
| `infrared-grafana` | Grafana | 3001 |

### 동작 확인

```bash
# API 헬스체크
make healthz
# → {"status": "ok", "env": "local"}

# Incident 목록 조회 (B가 탐지한 결과)
make incidents

# Redis Stream 적재량 확인
make redis-streams

# 에이전트 로그
make logs-agent

# Ingestion API 로그
make logs-ingestion
```

### 샘플 이벤트 직접 전송 (에이전트 없이 테스트)

```bash
make test
# 또는
python scripts/send_test_event.py
```

### 종료

```bash
make down        # 컨테이너만 종료 (볼륨 유지)
make clean       # 컨테이너 + 볼륨 전체 삭제 (데이터 초기화)
make clean-logs  # auth.log를 git 원본으로 복원
```

---

## 6. 라이브 로그 생성

정적 `auth.log`는 에이전트가 한 번 다 읽으면 더 이상 이벤트가 없습니다.  
`generate_logs.py`는 실시간으로 줄을 추가하여 에이전트가 지속적으로 이벤트를 전송하게 합니다.

### 실행 방법

```bash
# 기본: 공격 + 정상 혼합, 5초 간격
make live-logs

# 공격 패턴만, 2초 간격 (빠른 탐지 테스트)
make live-logs-attack

# 직접 실행 (경로·간격·모드 커스텀)
python scripts/generate_logs.py \
  --output infra/sample-logs/auth.log \
  --interval 5 \
  --mode mixed    # attack | normal | mixed
```

### 생성 모드

| 모드 | 설명 |
|---|---|
| `attack` | 무차별 대입, 루트 공격, Invalid user 열거만 생성 |
| `normal` | 내부 IP 정상 로그인만 생성 |
| `mixed` | 공격 + 정상 혼합 (기본값) |

### 생성되는 패턴

- **AUTH-001** Brute Force: 5회↑ `Failed password` from 동일 IP
- **AUTH-002** Root Login: `root` 계정 시도
- **AUTH-003** Invalid User: `Invalid user` 열거
- **AUTH-004** Failed→Success: 실패 후 동일 IP 로그인 성공
- **AUTH-005** Suspicious: 공격 이력 IP에서 로그인 성공

> Ctrl+C로 중지합니다. `make clean-logs`로 auth.log를 원상 복구할 수 있습니다.

---

## 7. AWS 배포 (Terraform)

### 아키텍처

```
인터넷
  │
  ▼
ALB (ap-northeast-2)
  ├─ :80   → ECS Fargate: Ingestion API
  └─ :3000 → ECS Fargate: Frontend

ECS Fargate 클러스터
  ├─ infrared-dev-ingestion
  ├─ infrared-dev-frontend
  ├─ infrared-dev-detection-worker   ─┐
  ├─ infrared-dev-enrichment-worker   ├─ Redis 소비
  ├─ infrared-dev-correlation-worker  │
  └─ infrared-dev-llm-worker         ─┘

데이터 계층 (SG로 ECS만 접근)
  ├─ RDS PostgreSQL 16 (db.t3.micro)
  └─ ElastiCache Redis 7 (cache.t3.micro)

보조
  ├─ ECR: backend / frontend / agent 이미지
  ├─ Secrets Manager: JWT 비밀키, DB 비밀번호
  ├─ CloudWatch: /infrared/dev/* 로그 그룹
  └─ IAM: ECS 실행 역할 + 태스크 역할 (Bedrock 포함)

모니터링 대상 서버 (ECR에서 Agent 이미지 pull)
  └─ Docker: infrared-agent → ALB/ingest 로 이벤트 전송
```

### 사전 조건

```bash
# 1. AWS CLI 설치 (macOS)
brew install awscli

# 2. Terraform 설치 (macOS)
brew tap hashicorp/tap
brew install hashicorp/tap/terraform

# 3. AWS 자격증명 설정
aws configure
# AWS Access Key ID:     AKIA...
# AWS Secret Access Key: xxxxxxxx
# Default region name:   ap-northeast-2
# Default output format: json

# 4. 자격증명 확인
aws sts get-caller-identity
```

### Terraform 변수 파일 준비

```bash
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
```

`terraform.tfvars`에서 반드시 변경해야 하는 항목:

```hcl
db_password = "강한-비밀번호-8자-이상"
jwt_secret  = "최소-32자-이상의-랜덤-비밀키"
```

> `terraform.tfvars`는 `.gitignore`에 포함되어 있어 절대 커밋되지 않습니다.

### 전체 자동 배포

```bash
make aws-deploy
```

내부 실행 순서:

1. `terraform init` + `terraform plan` (확인 후 진행)
2. `terraform apply` (VPC, RDS, Redis, ECS 등 생성 — 약 10분)
3. ECR 로그인
4. Docker 이미지 빌드 & ECR 푸시 (backend, frontend, agent)
5. DB 마이그레이션 실행 (`backend/app/db/migrate.py`)
6. ECS 서비스 롤링 업데이트

### 단계별 배포

```bash
make aws-init    # terraform init
make aws-plan    # 변경사항 미리보기
make aws-apply   # 인프라 생성/변경
make aws-push    # 이미지만 빌드 & 푸시
make aws-migrate # DB 스키마 + Seed 초기화
```

### 배포 결과 확인

```bash
# ALB URL, ECR URI, 마이그레이션 명령 등 출력
make aws-output

# 예시 출력:
# ingestion_api_url = "http://infrared-dev-alb-xxx.ap-northeast-2.elb.amazonaws.com"
# dashboard_url     = "http://...:3000"
# ecr_backend_uri   = "123456789.dkr.ecr.ap-northeast-2.amazonaws.com/infrared-dev-backend"
```

### 모니터링 대상 서버에 Agent 배포

`terraform output agent_deploy_hint`로 출력되는 명령을 모니터링 대상 서버에서 실행합니다:

```bash
# 모니터링 대상 서버에서
docker pull <ECR_AGENT_URI>:latest

docker run -d \
  --name infrared-agent \
  --restart unless-stopped \
  -e AGENT_TOKEN="$(python scripts/generate_jwt.py --role agent)" \
  -e BACKEND_URL="http://<ALB_DNS>/ingest" \
  -e HEARTBEAT_URL="http://<ALB_DNS>/heartbeat" \
  -e TENANT_ID="company-a" \
  -e AGENT_ID="agent-001" \
  -e ASSET_ID="asset-001" \
  -v /var/log:/host/var/log:ro \
  -v infrared-state:/var/lib/infrared \
  <ECR_AGENT_URI>:latest
```

### 로그 / 디버그

```bash
# CloudWatch 로그 실시간 조회
make aws-logs                         # Ingestion API
make aws-logs SERVICE=detection-worker

# ECS 태스크 목록
make aws-tasks

# ECS 컨테이너 접속 (디버그)
make aws-exec SERVICE=ingestion
```

### 인프라 삭제

```bash
make aws-destroy   # ⚠ 모든 AWS 리소스 삭제 (데이터 포함)
```

### 예상 비용 (ap-northeast-2, dev 환경)

| 서비스 | 사양 | 월 비용 |
|---|---|---|
| RDS PostgreSQL | db.t3.micro, 20GB | ~$15 |
| ElastiCache Redis | cache.t3.micro | ~$12 |
| ECS Fargate | 6 태스크 (256~512 CPU) | ~$25 |
| ALB | 1개 | ~$16 |
| ECR + CloudWatch + Secrets | 소량 | ~$5 |
| **합계** | | **~$73/월** |

---

## 8. Makefile 명령어 레퍼런스

```bash
make help   # 전체 명령어 목록 출력
```

### 로컬 개발

| 명령어 | 설명 |
|---|---|
| `make setup` | `.env` 생성 + `AGENT_TOKEN` 자동 발급 |
| `make up` | 전체 스택 빌드 & 백그라운드 실행 |
| `make down` | 스택 종료 (볼륨 유지) |
| `make restart` | 스택 재시작 |
| `make logs` | 전체 로그 스트리밍 |
| `make logs-agent` | 에이전트 로그만 |
| `make logs-ingestion` | Ingestion API 로그만 |
| `make test` | 샘플 이벤트 일괄 전송 |
| `make live-logs` | 실시간 로그 생성 (혼합, 5초) |
| `make live-logs-attack` | 공격 패턴 집중 생성 (2초) |
| `make healthz` | API 헬스체크 |
| `make incidents` | Incident 목록 조회 |
| `make redis-streams` | Redis Stream 길이 확인 |
| `make shell-redis` | Redis CLI 접속 |
| `make shell-db` | psql 접속 |
| `make clean` | 컨테이너 + 볼륨 삭제 |
| `make clean-logs` | auth.log 초기화 (git checkout) |

### AWS 배포

| 명령어 | 설명 |
|---|---|
| `make aws-init` | Terraform 초기화 |
| `make aws-plan` | 변경사항 미리보기 |
| `make aws-apply` | 인프라 생성/변경 |
| `make aws-deploy` | 전체 자동 배포 |
| `make aws-push` | 이미지 빌드 & ECR 푸시만 |
| `make aws-migrate` | DB 마이그레이션 실행 |
| `make aws-output` | 배포 결과 (URL, URI 등) |
| `make aws-logs` | CloudWatch 로그 (SERVICE=xxx) |
| `make aws-tasks` | ECS 태스크 목록 |
| `make aws-exec` | ECS 컨테이너 접속 (SERVICE=xxx) |
| `make aws-destroy` | ⚠ 전체 AWS 리소스 삭제 |

---

## 9. AUTH 룰 커버리지 확인

`infra/sample-logs/auth.log`는 다음 5가지 패턴을 모두 포함합니다.

| 룰 | 내용 | 공격 IP | 횟수 |
|---|---|---|---|
| AUTH-001 | Brute Force (5회↑ 실패) | 185.12.34.56 | 7회 |
| AUTH-001 | Brute Force | 103.44.21.89 | 6회 |
| AUTH-001 | Brute Force | 91.200.12.5 | 5회 |
| AUTH-001 | Brute Force | 45.33.32.156 | 5회 |
| AUTH-002 | root 계정 시도 | 185.12.34.56 외 | 13건 |
| AUTH-003 | Invalid user 열거 (3건↑) | 185.12.34.56 | 4건 |
| AUTH-003 | Invalid user 열거 | 91.200.12.5 | 3건 |
| AUTH-004 | 실패 후 성공 | 4개 IP 전부 | ✔ |
| AUTH-005 | 공격 IP 로그인 성공 | 4개 IP 전부 | ✔ |

공격 Wave 시나리오:
- **Wave 1** (03:12): 185.12.34.56 — 무차별 대입 + 루트 공격 → 03:14 침투 성공
- **Wave 2** (08:00): 103.44.21.89 — admin 브루트포스 → ubuntu 계정 침투
- **Wave 3** (09:30): 정상 내부 로그인 (알람 없어야 함)
- **Wave 4** (14:22): 91.200.12.5 — 루트 직접 공략 → 침투 성공
- **Wave 5** (23:55): 45.33.32.156 — 심야 의심 로그인 → ubuntu 침투

---

## 10. 트러블슈팅

### `AGENT_TOKEN` 관련 오류

```
HTTPStatusError: 401 Unauthorized
```
→ `.env`의 `AGENT_TOKEN`이 `replace-with-...` 상태입니다.

```bash
make setup   # 또는
make token   # 토큰만 출력 → .env에 수동 붙여넣기
```

### 에이전트가 이벤트를 보내지 않음

```bash
make logs-agent
```

- `auth log not found`: `AGENT_AUTH_LOG_PATH` 경로 확인
- `event send loop failed`: Ingestion API 미실행 → `make logs-ingestion`

### Redis Stream이 쌓이지 않음

```bash
make redis-streams
```

값이 0이면 에이전트가 Ingestion API에 도달하지 못하는 것입니다.

```bash
make healthz   # API가 응답하는지 확인
```

### DB 연결 오류 (workers)

```bash
make shell-db  # psql 접속 확인
```

스키마가 없으면:
```bash
# 로컬
docker compose exec postgres psql -U infrared -d infrared -f /docker-entrypoint-initdb.d/01-schema.sql

# AWS
make aws-migrate
```

### AWS 배포: `aws 가 설치되어 있지 않습니다`

```bash
brew install awscli
aws configure   # 액세스 키 설정
```

### AWS 배포: `terraform.tfvars 파일이 없습니다`

```bash
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# 파일 열어서 db_password, jwt_secret 변경
```

### ECS 태스크가 계속 재시작됨

```bash
make aws-logs SERVICE=ingestion   # 에러 메시지 확인
```

주요 원인:
- DB 마이그레이션 미실행 → `make aws-migrate`
- `JWT_SECRET` 미설정 → Secrets Manager 확인
- RDS SG에서 ECS SG 허용 안 됨 → `security_groups.tf` 확인
