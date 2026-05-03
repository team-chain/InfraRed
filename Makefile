# ============================================================
# InfraRed — 개발 편의 명령어
# ============================================================
# 사용법:
#   make help        명령어 목록
#   make setup       .env 생성 + JWT 토큰 발급
#   make up          전체 스택 빌드 & 실행
#   make down        스택 종료
#   make logs        전체 로그 스트리밍
#   make test        샘플 이벤트 전송
#   make live-logs   실시간 로그 생성 (별도 터미널에서 실행)
#   make clean       컨테이너 + 볼륨 전체 삭제

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ── 색상 ────────────────────────────────────────────────────
BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[32m
CYAN  := \033[36m
YELLOW := \033[33m

# ── 기본 변수 ────────────────────────────────────────────────
COMPOSE         := docker compose
PYTHON          := python3
SAMPLE_LOG      := infra/sample-logs/auth.log
INGESTION_URL   := http://localhost:8000

# ============================================================
.PHONY: help
help: ## 사용 가능한 명령어 목록
	@echo ""
	@echo "$(BOLD)InfraRed 개발 명령어$(RESET)"
	@echo "──────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-18s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ============================================================
# 초기 설정
# ============================================================
.PHONY: setup
setup: ## .env 생성 + AGENT_TOKEN 자동 발급
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✔ .env 파일 생성됨$(RESET)"; \
	else \
		echo "$(YELLOW)! .env 이미 존재 — 건너뜀$(RESET)"; \
	fi
	@echo ""
	@echo "$(BOLD)AGENT_TOKEN 발급 중...$(RESET)"
	@TOKEN=$$($(PYTHON) scripts/generate_jwt.py --role agent 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then \
		echo "오류: JWT 생성 실패. Python 환경을 확인하세요."; exit 1; \
	fi; \
	if grep -q "^AGENT_TOKEN=" .env; then \
		sed -i.bak "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$$TOKEN|" .env && rm -f .env.bak; \
	else \
		echo "AGENT_TOKEN=$$TOKEN" >> .env; \
	fi; \
	echo "$(GREEN)✔ AGENT_TOKEN .env에 저장됨$(RESET)"; \
	echo "  토큰 앞 40자: $${TOKEN:0:40}..."

.PHONY: token
token: ## AGENT_TOKEN만 새로 발급 (화면 출력)
	@$(PYTHON) scripts/generate_jwt.py --role agent

# ============================================================
# Docker 스택
# ============================================================
.PHONY: up
up: ## 전체 스택 빌드 & 백그라운드 실행
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)⚠ .env 없음 — make setup 먼저 실행하세요$(RESET)"; exit 1; \
	fi
	$(COMPOSE) up --build -d
	@echo ""
	@echo "$(GREEN)✔ 스택 실행 중$(RESET)"
	@echo "  Ingestion API : $(INGESTION_URL)"
	@echo "  Dashboard     : http://localhost:3000"
	@echo "  Grafana       : http://localhost:3001  (admin/admin)"
	@echo "  Prometheus    : http://localhost:9090"

.PHONY: down
down: ## 스택 종료 (볼륨 유지)
	$(COMPOSE) down

.PHONY: restart
restart: ## 스택 재시작
	$(COMPOSE) restart

.PHONY: build
build: ## 이미지만 빌드 (실행 없음)
	$(COMPOSE) build

# ── 서비스별 재시작 ──────────────────────────────────────────
.PHONY: restart-agent
restart-agent: ## 에이전트 컨테이너만 재시작
	$(COMPOSE) restart agent

.PHONY: restart-ingestion
restart-ingestion: ## Ingestion API 컨테이너만 재시작
	$(COMPOSE) restart ingestion

# ============================================================
# 로그 확인
# ============================================================
.PHONY: logs
logs: ## 전체 서비스 로그 스트리밍
	$(COMPOSE) logs -f

.PHONY: logs-agent
logs-agent: ## 에이전트 로그만
	$(COMPOSE) logs -f agent

.PHONY: logs-ingestion
logs-ingestion: ## Ingestion API 로그만
	$(COMPOSE) logs -f ingestion

.PHONY: logs-detection
logs-detection: ## Detection Worker 로그만
	$(COMPOSE) logs -f detection-worker

# ============================================================
# 테스트 & 디버그
# ============================================================
.PHONY: test
test: ## 샘플 auth.log 이벤트 일괄 전송
	$(PYTHON) scripts/send_test_event.py

.PHONY: live-logs
live-logs: ## 실시간 로그 생성기 실행 (Ctrl+C로 중지)
	@echo "$(BOLD)라이브 로그 생성 시작 → $(SAMPLE_LOG)$(RESET)"
	@echo "공격 + 정상 이벤트를 5초 간격으로 추가합니다."
	@echo ""
	$(PYTHON) scripts/generate_logs.py \
		--output $(SAMPLE_LOG) \
		--interval 5 \
		--mode mixed

.PHONY: live-logs-attack
live-logs-attack: ## 공격 패턴 집중 생성 (2초 간격)
	$(PYTHON) scripts/generate_logs.py \
		--output $(SAMPLE_LOG) \
		--interval 2 \
		--mode attack

.PHONY: healthz
healthz: ## Ingestion API 헬스 체크
	@curl -sf $(INGESTION_URL)/healthz | python3 -m json.tool || echo "응답 없음"

.PHONY: incidents
incidents: ## 현재 Incident 목록 조회
	@curl -sf "$(INGESTION_URL)/incidents" | python3 -m json.tool || echo "응답 없음"

.PHONY: shell-redis
shell-redis: ## Redis CLI 접속
	$(COMPOSE) exec redis redis-cli

.PHONY: shell-db
shell-db: ## PostgreSQL psql 접속
	$(COMPOSE) exec postgres psql -U infrared -d infrared

.PHONY: redis-streams
redis-streams: ## Redis Stream 현황 확인
	@echo "=== events:raw ==="
	$(COMPOSE) exec redis redis-cli XLEN "tenant:company-a:stream:events:raw"
	@echo "=== events:deadletter ==="
	$(COMPOSE) exec redis redis-cli XLEN "tenant:company-a:stream:events:deadletter"
	@echo "=== signals:matched ==="
	$(COMPOSE) exec redis redis-cli XLEN "tenant:company-a:stream:signals:matched"
	@echo "=== incidents:new ==="
	$(COMPOSE) exec redis redis-cli XLEN "tenant:company-a:stream:incidents:new"

# ============================================================
# 정리
# ============================================================
.PHONY: clean
clean: ## 컨테이너 + 볼륨 전체 삭제 (데이터 초기화)
	@echo "$(YELLOW)⚠ 모든 데이터가 삭제됩니다. 계속하려면 Enter, 취소하려면 Ctrl+C$(RESET)"
	@read confirm
	$(COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)✔ 정리 완료$(RESET)"

.PHONY: clean-logs
clean-logs: ## 샘플 auth.log를 초기 상태로 되돌림 (git checkout)
	git checkout -- $(SAMPLE_LOG)
	@echo "$(GREEN)✔ 로그 초기화 완료$(RESET)"

# ============================================================
# 상태 확인
# ============================================================
.PHONY: ps
ps: ## 실행 중인 컨테이너 상태
	$(COMPOSE) ps

.PHONY: stats
stats: ## 컨테이너 리소스 사용량
	docker stats --no-stream $$($(COMPOSE) ps -q)

# ============================================================
# AWS 배포 (Terraform + ECS)
# ============================================================
TF_DIR      := infra/terraform
AWS_REGION  ?= ap-northeast-2
ECS_CLUSTER ?= infrared-dev-cluster

.PHONY: aws-init
aws-init: ## Terraform 초기화
	cd $(TF_DIR) && terraform init -upgrade

.PHONY: aws-plan
aws-plan: ## Terraform Plan (변경사항 미리보기)
	cd $(TF_DIR) && terraform plan

.PHONY: aws-apply
aws-apply: ## Terraform Apply (인프라 생성/변경)
	cd $(TF_DIR) && terraform apply

.PHONY: aws-destroy
aws-destroy: ## ⚠ Terraform Destroy (모든 AWS 리소스 삭제)
	@echo "$(YELLOW)⚠ 모든 AWS 리소스가 삭제됩니다. 계속하려면 Enter$(RESET)"
	@read confirm
	cd $(TF_DIR) && terraform destroy

.PHONY: aws-output
aws-output: ## Terraform 출력값 확인 (URL, ECR URI 등)
	cd $(TF_DIR) && terraform output

.PHONY: aws-deploy
aws-deploy: ## 전체 배포 (Terraform + 빌드 + 푸시 + 마이그레이션)
	chmod +x scripts/aws-deploy.sh
	./scripts/aws-deploy.sh

.PHONY: aws-push
aws-push: ## 이미지 빌드 & ECR 푸시만 (Terraform 제외)
	./scripts/aws-deploy.sh --push-only

.PHONY: aws-migrate
aws-migrate: ## DB 스키마 + Seed 마이그레이션 실행
	@DB_URL=$$(cd $(TF_DIR) && terraform output -raw database_url 2>/dev/null); \
	if [ -z "$$DB_URL" ]; then \
		echo "Terraform output에서 database_url을 찾을 수 없습니다."; exit 1; \
	fi; \
	DATABASE_URL="$$DB_URL" $(PYTHON) backend/app/db/migrate.py

.PHONY: aws-logs
aws-logs: ## CloudWatch 로그 스트리밍 (SERVICE=ingestion)
	aws logs tail "/infrared/dev/$${SERVICE:-ingestion}" --follow --region $(AWS_REGION)

.PHONY: aws-tasks
aws-tasks: ## 실행 중인 ECS 태스크 목록
	aws ecs list-tasks --cluster $(ECS_CLUSTER) --region $(AWS_REGION)

.PHONY: aws-exec
aws-exec: ## ECS 컨테이너 셸 접속 (SERVICE=ingestion)
	@TASK_ARN=$$(aws ecs list-tasks --cluster $(ECS_CLUSTER) \
		--service-name "infrared-dev-$${SERVICE:-ingestion}" \
		--query 'taskArns[0]' --output text --region $(AWS_REGION)); \
	aws ecs execute-command \
		--cluster $(ECS_CLUSTER) \
		--task "$$TASK_ARN" \
		--container "$${SERVICE:-ingestion}" \
		--interactive \
		--command "/bin/bash" \
		--region $(AWS_REGION)
