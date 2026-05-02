# InfraRed — SIEM 보안 이벤트 수집 및 탐지 시스템

> 서버 auth 로그를 실시간으로 수집하고, 침입 패턴을 탐지하여 알림을 발송하는 경량 SIEM 플랫폼.

---

## 시스템 개요

InfraRed는 3개 역할로 구성된 분산 SIEM 파이프라인입니다.

| 역할 | 담당 | 주요 컴포넌트 |
|------|------|--------------|
| **A — 수집** | 로그 수집 · Ingestion API · Redis 스트림 · 인프라 | Agent, FastAPI, Terraform |
| **B — 탐지** | 패턴 매칭 · 이벤트 보강 · 인시던트 상관분석 | Detection/Enrichment/Correlation Worker |
| **C — 알림** | LLM 분석 · 대시보드 · 알림 발송 | LLM Worker, React Frontend |

### 데이터 흐름

```
auth.log
  └─► Agent (poll 2초, SHA256 중복제거, 민감정보 마스킹)
        └─► POST /ingest  (JWT 인증)
              └─► Redis Stream  tenant:{tid}:stream:events:raw
                    ├─► Detection Worker  →  signals:matched
                    │       └─► Enrichment Worker  →  signals:enriched
                    │               └─► Correlation Worker  →  incidents:new
                    └─► LLM Worker (Bedrock)  →  이메일·Slack 알림
```

---

## 디렉토리 구조

```
InfraRed-main/
├── agent/                        # 로그 수집 에이전트 (Role A)
│   └── infrared_agent/
│       ├── main.py               # 메인 이벤트 루프 (poll + heartbeat)
│       ├── tailer.py             # auth.log 읽기 + 이벤트 엔벨로프 생성
│       ├── masking.py            # password/token/Bearer 마스킹
│       ├── offset_store.py       # SQLite 오프셋 저장 (로그 로테이션 감지)
│       ├── client.py             # HTTP 클라이언트 → Ingestion API
│       └── config.py             # 환경변수 설정
│
├── backend/                      # 백엔드 서비스
│   └── app/
│       ├── main.py               # FastAPI 진입점
│       ├── ingestion/routes.py   # POST /ingest, POST /heartbeat
│       ├── models/               # RawEventEnvelope, Signal, Incident 등
│       ├── redis_kv/             # Redis Stream 클라이언트 + Consumer Group
│       ├── db/
│       │   ├── schema.sql        # PostgreSQL DDL
│       │   ├── seed.sql          # 초기 테넌트·에이전트·룰 데이터
│       │   └── migrate.py        # AWS RDS 마이그레이션 러너
│       ├── iam/                  # JWT 발급·검증, RBAC
│       ├── workers/
│       │   ├── detection/        # AUTH-001~005 룰 매칭 (Role B)
│       │   ├── enrichment/       # IP 평판·지오로케이션 보강 (Role B)
│       │   ├── correlation/      # 인시던트 상관분석 (Role B)
│       │   └── llm/              # AWS Bedrock LLM 분석 (Role C)
│       └── dispatcher/           # Slack·이메일 알림
│
├── frontend/                     # React 대시보드 (Role C)
│   └── src/
│       ├── pages/Dashboard.tsx
│       └── components/           # IncidentTable, EvidenceTimeline
│
├── infra/
│   ├── docker/
│   │   ├── agent.Dockerfile      # 비루트 유저, 헬스체크 포함
│   │   ├── backend.Dockerfile
│   │   └── frontend.Dockerfile
│   ├── sample-logs/auth.log      # 테스트용 샘플 로그 (AUTH-001~005 전체 포함)
│   ├── prometheus/prometheus.yml
│   ├── grafana/                  # 대시보드 + 데이터소스 자동 프로비저닝
│   └── terraform/                # AWS 인프라 IaC
│       ├── vpc.tf, security_groups.tf, ecr.tf
│       ├── rds.tf, elasticache.tf, alb.tf, ecs.tf
│       ├── iam.tf, secrets.tf, cloudwatch.tf
│       └── terraform.tfvars.example
│
├── scripts/
│   ├── generate_jwt.py           # AGENT_TOKEN 발급
│   ├── send_test_event.py        # 샘플 이벤트 전송
│   └── generate_logs.py          # 실시간 로그 생성기
│
├── docker-compose.yml            # 로컬 개발 스택 (11개 컨테이너)
└── Makefile                      # 30+ 개발·배포 명령어
```

---

## 사전 조건 설치

### macOS

```bash
# Homebrew (없을 경우)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 필수 도구
brew install python@3.11 make awscli terraform

# Docker Desktop
# https://www.docker.com/products/docker-desktop/ 에서 설치
```

### Windows

PowerShell을 **관리자 권한**으로 실행합니다.

```powershell
# Chocolatey (없을 경우)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 필수 도구
choco install python311 make awscli terraform -y

# Docker Desktop
# https://www.docker.com/products/docker-desktop/ 에서 설치 후 재부팅
```

> Windows에서 `make`가 동작하지 않을 경우 Git Bash 또는 WSL2 환경을 권장합니다.

---

## 빠른 시작 (로컬 Docker)

### 1단계 — 환경 설정

**macOS / Linux**
```bash
make setup
```

**Windows (PowerShell)**
```powershell
make setup
# 또는 make가 없을 경우:
python scripts/generate_jwt.py --role agent
# 출력된 토큰을 .env 파일의 AGENT_TOKEN에 복사
```

**Windows (.env 파일 직접 생성)**
```powershell
Copy-Item .env.example .env
# 메모장 또는 VS Code로 .env 열어서 AGENT_TOKEN 값 입력
notepad .env
```

`.env` 파일을 생성하고 `AGENT_TOKEN`을 발급합니다.

---

### 2단계 — 전체 스택 실행

**macOS / Windows 공통**
```bash
make up
```

**Windows (make 없을 경우)**
```powershell
docker compose up --build -d
```

컨테이너 11개가 순서에 맞게 기동됩니다. 완료 후 접속 주소:

| 서비스 | 주소 |
|--------|------|
| Ingestion API | http://localhost:8000 |
| Dashboard | http://localhost:3000 |
| Grafana | http://localhost:3001 (admin/admin) |
| Prometheus | http://localhost:9090 |

---

### 3단계 — 동작 확인

**macOS**
```bash
make healthz        # API 헬스체크 → {"status":"ok"}
make redis-streams  # 스트림별 이벤트 수 확인
make logs-agent     # 에이전트 로그
make incidents      # 탐지된 인시던트 조회
```

**Windows (PowerShell)**
```powershell
# make 사용 시
make healthz
make redis-streams

# make 없을 경우
curl http://localhost:8000/healthz
docker compose logs -f agent
docker compose exec redis redis-cli XLEN "tenant:company-a:stream:events:raw"
```

---

### 4단계 — 실시간 로그 생성 (별도 터미널)

**macOS**
```bash
make live-logs          # 공격 + 정상 혼합 (5초 간격)
make live-logs-attack   # 공격 패턴만 집중 생성 (2초 간격)
```

**Windows (PowerShell)**
```powershell
# make 사용 시
make live-logs

# make 없을 경우
python scripts/generate_logs.py --output infra/sample-logs/auth.log --interval 5 --mode mixed
python scripts/generate_logs.py --output infra/sample-logs/auth.log --interval 2 --mode attack
```

---

## AUTH 탐지 룰

| 룰 ID | 패턴 | 조건 | 예시 |
|-------|------|------|------|
| AUTH-001 | Brute Force | 같은 IP에서 5회 이상 패스워드 실패 | 185.12.34.56 (7회) |
| AUTH-002 | Root 로그인 시도 | root 계정 접속 시도 | root 13회 |
| AUTH-003 | 사용자 열거 | 같은 IP에서 Invalid user 3회 이상 | 185.12.34.56 (4회) |
| AUTH-004 | 실패→성공 패턴 | 실패 후 같은 IP에서 로그인 성공 | 4개 공격 IP 전체 |
| AUTH-005 | 의심 성공 로그인 | 공격 이력 있는 IP의 로그인 성공 | 4개 공격 IP 전체 |

---

## Make 명령어 목록

### 로컬 개발

```bash
make setup              # .env + AGENT_TOKEN 생성
make up                 # 전체 스택 빌드 & 실행
make down               # 스택 종료 (볼륨 유지)
make logs               # 전체 로그 스트리밍
make logs-agent         # 에이전트 로그
make logs-ingestion     # Ingestion API 로그
make healthz            # API 헬스체크
make incidents          # 인시던트 목록 조회
make redis-streams      # Redis Stream 현황
make shell-redis        # Redis CLI 접속
make shell-db           # PostgreSQL psql 접속
make test               # 샘플 이벤트 전송
make live-logs          # 실시간 로그 생성 (mixed)
make live-logs-attack   # 실시간 로그 생성 (attack only)
make clean              # 컨테이너 + 볼륨 전체 삭제
make clean-logs         # sample auth.log 초기화
```

### AWS 배포

```bash
make aws-init           # Terraform 초기화
make aws-plan           # 변경사항 미리보기
make aws-apply          # 인프라 생성·변경
make aws-push           # 이미지 빌드 & ECR 푸시
make aws-migrate        # DB 스키마 + Seed 적용
make aws-output         # ALB URL, ECR URI 등 출력
make aws-logs           # CloudWatch 로그 스트리밍
make aws-tasks          # ECS 태스크 목록
make aws-destroy        # 모든 AWS 리소스 삭제
```

---

## AWS 배포

### 사전 조건

**macOS**
```bash
brew install awscli terraform
aws configure
# AWS Access Key ID, Secret, region=ap-northeast-2, output=json
```

**Windows (PowerShell)**
```powershell
choco install awscli terraform -y
aws configure
# AWS Access Key ID, Secret, region=ap-northeast-2, output=json
```

### 배포 절차

**macOS**
```bash
# 1. tfvars 파일 생성
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# db_password, jwt_secret 값 수정

# 2. Terraform 초기화
make aws-init

# 3. 전체 배포
make aws-deploy
```

**Windows (PowerShell)**
```powershell
# 1. tfvars 파일 생성
Copy-Item infra\terraform\terraform.tfvars.example infra\terraform\terraform.tfvars
# 메모장으로 열어서 db_password, jwt_secret 수정
notepad infra\terraform\terraform.tfvars

# 2. Terraform 초기화
cd infra\terraform
terraform init -upgrade

# 3. 인프라 생성
terraform apply

# 4. 이미지 빌드 & ECR 푸시
cd ..\..
$env:AWS_REGION = "ap-northeast-2"
$ECR_BACKEND = terraform -chdir=infra/terraform output -raw ecr_backend_uri
docker build -f infra/docker/backend.Dockerfile -t "${ECR_BACKEND}:latest" ./backend
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin "$ECR_BACKEND"
docker push "${ECR_BACKEND}:latest"

# 5. DB 마이그레이션
pip install asyncpg
make aws-migrate
```

### 생성되는 AWS 리소스

| 리소스 | 사양 | 월 비용 (예상) |
|--------|------|--------------|
| RDS PostgreSQL 16 | db.t3.micro, 20GB | ~$15 |
| ElastiCache Redis 7 | cache.t3.micro | ~$12 |
| ALB | Application Load Balancer | ~$16 |
| ECS Fargate | 6개 서비스 | ~$25 |
| ECR | 3개 레포지터리 | ~$1 |
| CloudWatch | 7개 로그 그룹, 30일 보존 | ~$4 |
| **합계** | ap-northeast-2, dev 환경 | **~$73/월** |

> NAT Gateway 없음 — ECS 태스크에 Public IP 직접 할당하여 비용 절감

---

## 에이전트 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AGENT_TOKEN` | (필수) | JWT 인증 토큰 |
| `BACKEND_URL` | `http://ingestion:8000/ingest` | Ingestion API 주소 |
| `HEARTBEAT_URL` | `http://ingestion:8000/heartbeat` | Heartbeat 주소 |
| `AGENT_AUTH_LOG_PATH` | `/host/var/log/auth.log` | 모니터링할 로그 파일 |
| `TENANT_ID` | `company-a` | 멀티테넌트 식별자 |
| `AGENT_ID` | `agent-001` | 에이전트 식별자 |
| `ASSET_ID` | `asset-001` | 자산 식별자 |
| `POLL_INTERVAL_SEC` | `2.0` | 로그 polling 간격(초) |
| `HEARTBEAT_INTERVAL_SEC` | `30` | Heartbeat 간격(초) |

---

## Redis Stream 구조

```
tenant:{tenant_id}:stream:events:raw          # 에이전트 수집 이벤트
tenant:{tenant_id}:stream:events:deadletter   # 처리 실패 이벤트
tenant:{tenant_id}:stream:signals:matched     # Detection Worker 출력
tenant:{tenant_id}:stream:signals:enriched    # Enrichment Worker 출력
tenant:{tenant_id}:stream:incidents:new       # Correlation Worker 출력
```

---

## 트러블슈팅

**에이전트가 시작 직후 계속 재시작됨**

Ingestion API healthcheck가 통과될 때까지 의도적으로 대기합니다 (`depends_on: service_healthy`). `make logs-ingestion`으로 API 기동 상태를 확인하세요.

**redis-streams 카운트가 0임**

`make healthz`로 API 응답을 확인하고, `make logs-ingestion`에서 JWT 인증 실패 여부를 확인하세요. 토큰이 만료됐을 경우 `make setup`으로 재발급합니다.

**AWS 배포 중 "already exists" 에러**

이전 실패로 일부 리소스가 남아있는 경우입니다. `terraform import`로 기존 리소스를 state에 등록한 후 재시도하세요.

```bash
cd infra/terraform
terraform import aws_ecr_repository.backend infrared-dev-backend
```

**DB 마이그레이션 실패 (asyncpg not found)**

macOS:
```bash
pip install asyncpg --break-system-packages
make aws-migrate
```

Windows:
```powershell
pip install asyncpg
make aws-migrate
```

**Windows에서 `make` 명령어를 찾을 수 없음**

```powershell
choco install make -y
# 또는 Git Bash / WSL2 사용
```

**Windows에서 Docker Compose 볼륨 마운트 오류**

Docker Desktop → Settings → Resources → File Sharing 에서 프로젝트 경로가 공유 목록에 포함되어 있는지 확인하세요.

---

## 라이선스

MIT
