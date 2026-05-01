#!/usr/bin/env bash
# ============================================================
# InfraRed AWS 배포 스크립트
# ============================================================
# 순서:
#   1. 사전 조건 확인 (aws, docker, terraform)
#   2. terraform init & apply
#   3. ECR 로그인
#   4. Docker 이미지 빌드 & ECR 푸시 (backend, frontend, agent)
#   5. DB 마이그레이션 실행
#   6. ECS 서비스 강제 롤링 업데이트
#   7. 배포 결과 출력
#
# 사용법:
#   chmod +x scripts/aws-deploy.sh
#   ./scripts/aws-deploy.sh              # 전체 배포
#   ./scripts/aws-deploy.sh --push-only  # 이미지 빌드+푸시만
#   ./scripts/aws-deploy.sh --tf-only    # Terraform만
# ============================================================
set -euo pipefail

# ── 색상 ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── 옵션 파싱 ────────────────────────────────────────────────
PUSH_ONLY=false
TF_ONLY=false
SKIP_MIGRATE=false

for arg in "$@"; do
  case $arg in
    --push-only)   PUSH_ONLY=true ;;
    --tf-only)     TF_ONLY=true ;;
    --skip-migrate) SKIP_MIGRATE=true ;;
    --help|-h)
      echo "사용법: $0 [--push-only] [--tf-only] [--skip-migrate]"
      exit 0 ;;
  esac
done

# ── 스크립트 실행 위치 (프로젝트 루트) ───────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$ROOT_DIR/infra/terraform"

cd "$ROOT_DIR"
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  InfraRed AWS 배포                     ${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo ""

# ── 1. 사전 조건 확인 ────────────────────────────────────────
info "사전 조건 확인 중..."

for cmd in aws docker terraform python3; do
  if ! command -v "$cmd" &>/dev/null; then
    error "$cmd 가 설치되어 있지 않습니다."
  fi
done

# AWS 자격증명 확인
if ! aws sts get-caller-identity &>/dev/null; then
  error "AWS 자격증명이 설정되지 않았습니다. 'aws configure' 또는 환경변수를 확인하세요."
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region 2>/dev/null || echo "ap-northeast-2")
ok "AWS 계정: $AWS_ACCOUNT_ID  리전: $AWS_REGION"

# tfvars 확인
if [ ! -f "$TF_DIR/terraform.tfvars" ]; then
  warn "terraform.tfvars 파일이 없습니다."
  echo "  cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars"
  echo "  후 값을 채우세요."
  exit 1
fi

# ── 2. Terraform ──────────────────────────────────────────────
if [ "$PUSH_ONLY" = false ]; then
  info "Terraform 초기화 중..."
  cd "$TF_DIR"
  terraform init -upgrade -input=false

  info "Terraform Plan..."
  terraform plan -out=tfplan -input=false

  echo ""
  read -rp "위 Plan을 적용하시겠습니까? (yes/no): " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    error "배포가 취소되었습니다."
  fi

  info "Terraform Apply 실행 중..."
  terraform apply tfplan
  rm -f tfplan
  ok "Terraform Apply 완료"
  cd "$ROOT_DIR"
fi

if [ "$TF_ONLY" = true ]; then
  ok "Terraform 전용 배포 완료"
  exit 0
fi

# ── 3. Terraform 출력값 읽기 ─────────────────────────────────
info "배포 정보 로드 중..."
cd "$TF_DIR"

ECR_BACKEND=$(terraform output -raw ecr_backend_uri)
ECR_FRONTEND=$(terraform output -raw ecr_frontend_uri)
ECR_AGENT=$(terraform output -raw ecr_agent_uri)
ECS_CLUSTER=$(terraform output -raw ecs_cluster_name)
RDS_HOST=$(terraform output -raw rds_endpoint)
ALB_URL=$(terraform output -raw ingestion_api_url)

cd "$ROOT_DIR"

ok "ECR Backend : $ECR_BACKEND"
ok "ECR Frontend: $ECR_FRONTEND"
ok "ECR Agent   : $ECR_AGENT"
ok "ECS Cluster : $ECS_CLUSTER"
ok "ALB URL     : $ALB_URL"

# ── 4. ECR 로그인 & 이미지 빌드/푸시 ────────────────────────
info "ECR 로그인 중..."
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin \
    "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

ok "ECR 로그인 완료"

# Backend 이미지 빌드 & 푸시
info "Backend 이미지 빌드 중..."
docker build \
  -f infra/docker/backend.Dockerfile \
  -t "${ECR_BACKEND}:latest" \
  -t "${ECR_BACKEND}:$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')" \
  ./backend
docker push "${ECR_BACKEND}:latest"
ok "Backend 이미지 푸시 완료"

# Frontend 이미지 빌드 & 푸시
info "Frontend 이미지 빌드 중..."
docker build \
  -f infra/docker/frontend.Dockerfile \
  --build-arg VITE_API_BASE_URL="$ALB_URL" \
  -t "${ECR_FRONTEND}:latest" \
  ./frontend
docker push "${ECR_FRONTEND}:latest"
ok "Frontend 이미지 푸시 완료"

# Agent 이미지 빌드 & 푸시
info "Agent 이미지 빌드 중..."
docker build \
  -f infra/docker/agent.Dockerfile \
  -t "${ECR_AGENT}:latest" \
  ./agent
docker push "${ECR_AGENT}:latest"
ok "Agent 이미지 푸시 완료"

# ── 5. DB 마이그레이션 ────────────────────────────────────────
if [ "$SKIP_MIGRATE" = false ]; then
  info "DB 마이그레이션 실행 중..."

  # tfvars에서 DB 정보 읽기
  DB_USER=$(grep 'db_username' "$TF_DIR/terraform.tfvars" | head -1 | sed 's/.*=\s*"\(.*\)"/\1/')
  DB_PASS=$(grep 'db_password' "$TF_DIR/terraform.tfvars" | head -1 | sed 's/.*=\s*"\(.*\)"/\1/')
  DB_NAME=$(grep '^db_name'   "$TF_DIR/terraform.tfvars" | head -1 | sed 's/.*=\s*"\(.*\)"/\1/')
  DB_NAME=${DB_NAME:-infrared}

  DB_URL="postgresql+asyncpg://${DB_USER}:${DB_PASS}@${RDS_HOST}:5432/${DB_NAME}"

  if command -v python3 &>/dev/null; then
    DATABASE_URL="$DB_URL" python3 backend/app/db/migrate.py && ok "마이그레이션 완료"
  elif command -v psql &>/dev/null; then
    PSQL_URL="postgresql://${DB_USER}:${DB_PASS}@${RDS_HOST}:5432/${DB_NAME}"
    psql "$PSQL_URL" -f backend/app/db/schema.sql
    psql "$PSQL_URL" -f infra/postgres/seed.sql
    ok "마이그레이션 완료 (psql)"
  else
    warn "psql/python3 마이그레이션 불가 — Docker로 시도합니다..."
    PSQL_URL="postgresql://${DB_USER}:${DB_PASS}@${RDS_HOST}:5432/${DB_NAME}"
    docker run --rm \
      -v "$ROOT_DIR/backend/app/db:/sql:ro" \
      postgres:16-alpine \
      sh -c "psql '$PSQL_URL' -f /sql/schema.sql && psql '$PSQL_URL' -f /sql/seed.sql"
    ok "마이그레이션 완료 (Docker psql)"
  fi
else
  warn "마이그레이션 건너뜀 (--skip-migrate)"
fi

# ── 6. ECS 서비스 롤링 업데이트 ─────────────────────────────
info "ECS 서비스 업데이트 트리거 중..."

SERVICES=(
  "infrared-dev-ingestion"
  "infrared-dev-frontend"
  "infrared-dev-detection-worker"
  "infrared-dev-enrichment-worker"
  "infrared-dev-correlation-worker"
  "infrared-dev-llm-worker"
)

for SVC in "${SERVICES[@]}"; do
  if aws ecs describe-services \
      --cluster "$ECS_CLUSTER" \
      --services "$SVC" \
      --query 'services[0].status' \
      --output text 2>/dev/null | grep -q "ACTIVE"; then
    aws ecs update-service \
      --cluster "$ECS_CLUSTER" \
      --service "$SVC" \
      --force-new-deployment \
      --output json > /dev/null
    ok "  $SVC → 롤링 업데이트 트리거됨"
  else
    warn "  $SVC → 서비스 없음 (건너뜀)"
  fi
done

# ── 7. 결과 출력 ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  배포 완료!${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}Ingestion API${RESET} : ${ALB_URL}"
echo -e "  ${BOLD}Dashboard${RESET}     : ${ALB_URL/http:\/\//http://}:3000"
echo ""
echo -e "  ECS 서비스 상태 확인:"
echo -e "  ${CYAN}aws ecs list-tasks --cluster ${ECS_CLUSTER}${RESET}"
echo ""
echo -e "  CloudWatch 로그:"
echo -e "  ${CYAN}aws logs tail /infrared/dev/ingestion --follow${RESET}"
echo ""
echo -e "  에이전트 배포 명령:"
echo -e "  ${CYAN}terraform -chdir=infra/terraform output agent_deploy_hint${RESET}"
echo ""
