#!/usr/bin/env bash
# ============================================================
# InfraRed 프리티어 → 유료 인프라 Terraform 전환 스크립트
# 프리티어 설계서 v1.0 §5.2 Terraform 전환 명령
# ============================================================
# 목적: 프리티어 단일 EC2 → 엔터프라이즈 멀티 AZ 전환
#
# 전환 가능 경로:
#   1. freetier → small   : EC2 t2.micro → t3.small (가장 간단)
#   2. freetier → standard: + RDS t3.micro + ElastiCache t3.micro
#   3. freetier → enterprise: 전체 엔터프라이즈 인프라 (RDS Multi-AZ, ALB, ASG)
# ============================================================
set -euo pipefail

TERRAFORM_DIR="${TERRAFORM_DIR:-./infra/terraform}"
BACKUP_DIR="${BACKUP_DIR:-./infra/terraform/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 현재 상태 확인 ────────────────────────────────────────
check_current_tier() {
    log_step "현재 인프라 티어 확인..."
    if [[ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]]; then
        log_error "terraform.tfvars를 찾을 수 없습니다: $TERRAFORM_DIR/terraform.tfvars"
    fi
    local CURRENT_TIER
    CURRENT_TIER=$(grep -oP 'tier\s*=\s*"\K[^"]+' "$TERRAFORM_DIR/terraform.tfvars" || echo "unknown")
    echo "현재 티어: $CURRENT_TIER"
    echo "$CURRENT_TIER"
}

# ── tfvars 백업 ───────────────────────────────────────────
backup_tfvars() {
    mkdir -p "$BACKUP_DIR"
    cp "$TERRAFORM_DIR/terraform.tfvars" \
       "$BACKUP_DIR/terraform.tfvars.${TIMESTAMP}.bak"
    log_info "tfvars 백업 완료: $BACKUP_DIR/terraform.tfvars.${TIMESTAMP}.bak"
}

# ── 티어별 변수 적용 ──────────────────────────────────────
apply_tier_vars() {
    local TARGET_TIER="$1"

    case "$TARGET_TIER" in
        freetier)
            cat > "$TERRAFORM_DIR/terraform.tfvars" << 'VARS'
# 프리티어 설정 — AWS Free Tier 한도 내
tier                = "freetier"

# EC2
ec2_instance_type   = "t2.micro"
ec2_root_volume_gb  = 20

# RDS (프리티어: db.t3.micro 750시간/월)
use_rds             = false          # 프리티어: EC2 내 PostgreSQL
rds_instance_class  = "db.t3.micro"
rds_allocated_gb    = 20
rds_multi_az        = false

# ElastiCache (프리티어: cache.t3.micro 750시간/월)
use_elasticache     = false          # 프리티어: EC2 내 Redis
elasticache_class   = "cache.t3.micro"

# 인증서 (step-ca — 무료)
use_acm             = false
step_ca_url         = ""

# AI 처리 (Lambda 무료 한도 내)
use_ai_lambda       = true
lambda_memory_mb    = 256
lambda_timeout_sec  = 30

# ALB (프리티어 미포함 — 비활성화)
use_alb             = false

# S3
s3_log_retention_days = 30

# SQS (프리티어: 100만 요청/월 무료)
use_sqs             = true
VARS
            ;;

        small)
            cat > "$TERRAFORM_DIR/terraform.tfvars" << 'VARS'
# 스몰 플랜 — 월 ~$30
tier                = "small"

ec2_instance_type   = "t3.small"
ec2_root_volume_gb  = 30

use_rds             = false
rds_instance_class  = "db.t3.micro"
rds_allocated_gb    = 20
rds_multi_az        = false

use_elasticache     = false

use_acm             = true
step_ca_url         = ""

use_ai_lambda       = true
lambda_memory_mb    = 512
lambda_timeout_sec  = 60

use_alb             = false
s3_log_retention_days = 90
use_sqs             = true
VARS
            ;;

        standard)
            cat > "$TERRAFORM_DIR/terraform.tfvars" << 'VARS'
# 스탠다드 플랜 — 월 ~$80
tier                = "standard"

ec2_instance_type   = "t3.medium"
ec2_root_volume_gb  = 50

use_rds             = true
rds_instance_class  = "db.t3.micro"
rds_allocated_gb    = 50
rds_multi_az        = false

use_elasticache     = true
elasticache_class   = "cache.t3.micro"

use_acm             = true
step_ca_url         = ""

use_ai_lambda       = true
lambda_memory_mb    = 1024
lambda_timeout_sec  = 120

use_alb             = false
s3_log_retention_days = 180
use_sqs             = true
VARS
            ;;

        enterprise)
            cat > "$TERRAFORM_DIR/terraform.tfvars" << 'VARS'
# 엔터프라이즈 플랜 — 월 ~$250+
tier                = "enterprise"

ec2_instance_type   = "t3.large"
ec2_root_volume_gb  = 100

use_rds             = true
rds_instance_class  = "db.r6g.large"
rds_allocated_gb    = 100
rds_multi_az        = true

use_elasticache     = true
elasticache_class   = "cache.r6g.large"

use_acm             = true
step_ca_url         = ""

use_ai_lambda       = true
lambda_memory_mb    = 3008
lambda_timeout_sec  = 300

use_alb             = true
s3_log_retention_days = 365
use_sqs             = true
VARS
            ;;

        *)
            log_error "알 수 없는 티어: $TARGET_TIER (freetier|small|standard|enterprise)"
            ;;
    esac

    log_info "티어 '$TARGET_TIER' 변수 파일 적용 완료"
}

# ── Terraform 계획 확인 ────────────────────────────────────
plan_migration() {
    local TARGET_TIER="$1"
    log_step "Terraform 계획 실행 중 (티어: $TARGET_TIER)..."

    cd "$TERRAFORM_DIR"

    terraform init -upgrade -reconfigure 2>&1 | tail -5

    terraform plan \
        -var-file="terraform.tfvars" \
        -out="migration_plan_${TARGET_TIER}_${TIMESTAMP}.tfplan" \
        2>&1

    log_info "계획 파일 저장: migration_plan_${TARGET_TIER}_${TIMESTAMP}.tfplan"
    echo ""
    log_warn "위 계획을 검토한 후 apply 명령을 실행하세요:"
    echo "  terraform apply migration_plan_${TARGET_TIER}_${TIMESTAMP}.tfplan"
}

# ── 실제 마이그레이션 적용 ────────────────────────────────
apply_migration() {
    local PLAN_FILE="$1"
    log_step "Terraform 적용 중: $PLAN_FILE"

    cd "$TERRAFORM_DIR"

    if [[ ! -f "$PLAN_FILE" ]]; then
        log_error "계획 파일을 찾을 수 없습니다: $PLAN_FILE"
    fi

    terraform apply "$PLAN_FILE"
    log_info "✅ Terraform 적용 완료"

    # 새 엔드포인트 출력
    echo ""
    log_info "새 인프라 엔드포인트:"
    terraform output 2>/dev/null || true
}

# ── 롤백 ─────────────────────────────────────────────────
rollback() {
    local BACKUP_FILE="${BACKUP_DIR}/$(ls -t "$BACKUP_DIR" | head -1)"
    if [[ -z "$BACKUP_FILE" || ! -f "$BACKUP_FILE" ]]; then
        log_error "백업 파일을 찾을 수 없습니다"
    fi

    log_warn "롤백 중: $BACKUP_FILE → terraform.tfvars"
    cp "$BACKUP_FILE" "$TERRAFORM_DIR/terraform.tfvars"
    log_info "롤백 완료. plan 후 apply 를 실행하세요."
}

# ── 비용 예상 ────────────────────────────────────────────
estimate_cost() {
    local TIER="$1"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  티어별 예상 월 비용 (2026년 기준, ap-northeast-2)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  freetier  : $0     (12개월 Free Tier 한도 내)"
    echo "  small     : ~$25   (t3.small EC2 + ACM + Lambda)"
    echo "  standard  : ~$80   (+ RDS db.t3.micro + Redis)"
    echo "  enterprise: ~$250+ (+ ALB + RDS Multi-AZ + ASG)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "현재 선택: $TIER"
    echo "AWS Cost Calculator: https://calculator.aws/pricing/2/estimator"
    echo ""
}

# ── 메인 ─────────────────────────────────────────────────
usage() {
    echo "사용법:"
    echo "  $0 plan <tier>         — 특정 티어로 계획만 실행"
    echo "  $0 apply <plan_file>   — 계획 파일로 실제 적용"
    echo "  $0 rollback            — 이전 tfvars로 롤백"
    echo "  $0 estimate [tier]     — 티어별 비용 예상"
    echo ""
    echo "티어: freetier | small | standard | enterprise"
    echo ""
    echo "예시:"
    echo "  $0 plan standard       — 스탠다드 티어로 마이그레이션 계획"
    echo "  $0 apply migration_plan_standard_20260101_120000.tfplan"
    echo "  $0 rollback            — 이전 설정으로 복원"
}

case "${1:-help}" in
    plan)
        TARGET="${2:-}"
        [[ -z "$TARGET" ]] && { usage; exit 1; }
        backup_tfvars
        apply_tier_vars "$TARGET"
        plan_migration "$TARGET"
        estimate_cost "$TARGET"
        ;;
    apply)
        PLAN="${2:-}"
        [[ -z "$PLAN" ]] && { usage; exit 1; }
        apply_migration "$PLAN"
        ;;
    rollback)
        rollback
        ;;
    estimate)
        estimate_cost "${2:-all}"
        ;;
    *)
        usage
        ;;
esac
