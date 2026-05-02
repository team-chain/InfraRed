# ============================================================
# InfraRed — Terraform 진입점
# ============================================================
# 요구 사항:
#   terraform >= 1.5
#   AWS CLI 설정 완료 (aws configure 또는 환경변수)
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

# 현재 AWS 계정 정보 (ECR URI 구성에 사용)
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.project}-${var.env}"
  ecr_base    = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.amazonaws.com"
  common_tags = {
    Project     = var.project
    Environment = var.env
  }
}
