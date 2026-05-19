# ============================================================
# InfraRed — Terraform 진입점 (AWS 프리티어 최적화)
# ============================================================
# 프리티어 활용 전략:
#   EC2 t2.micro  : 750시간/월 무료 (1년) → 모든 컨테이너를 단일 인스턴스에서 실행
#   RDS db.t3.micro: 750시간/월 무료 (1년) → PostgreSQL
#   S3            : 5GB 무료 (1년) → 로그 보관, 리포트
#   ECR           : 500MB/월 무료 → Docker 이미지
#   CloudWatch    : 10개 메트릭, 5GB 로그 무료 (1년)
#   SSM Parameter Store: 표준 파라미터 무료 → Secrets Manager 대체
#
# 프리티어 없는 서비스 → 제거:
#   ECS Fargate   : 프리티어 없음 → EC2 + Docker Compose로 대체
#   ALB           : 프리티어 없음 → EC2 Security Group으로 직접 노출
#   ElastiCache   : 프리티어 없음 → EC2 내 Redis 컨테이너로 대체
#   Secrets Manager: 유료 → SSM Parameter Store(무료)로 대체
#   NAT Gateway   : 유료 → 퍼블릭 서브넷 + 퍼블릭 IP로 대체
#
# 아키텍처:
#   EC2 t2.micro (단일 인스턴스)
#   └── Docker Compose
#       ├── ingestion (FastAPI :8000)
#       ├── detection-worker
#       ├── enrichment-worker
#       ├── incident-worker
#       ├── llm-worker
#       ├── cleanup-worker
#       ├── frontend (React :3000)
#       └── redis (컨테이너, :6379)
#   RDS db.t3.micro (PostgreSQL, 프리티어)
#   S3 (로그 보관, 프리티어 5GB)
#   ECR (이미지 레지스트리, 프리티어 500MB)
#
# 시작 방법:
#   cp terraform.tfvars.example terraform.tfvars  # 값 채우기
#   terraform init
#   terraform plan
#   terraform apply
# ============================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # ── S3 원격 상태 (팀 협업 시 활성화) ─────────────────────
  # backend "s3" {
  #   bucket         = "infrared-tfstate-<account-id>"
  #   key            = "dev/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "infrared-tfstate-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.env
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.project}-${var.env}"
  ecr_base    = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}
