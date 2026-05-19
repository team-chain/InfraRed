# ============================================================
# Amazon ECR — Docker 이미지 레지스트리 (프리티어)
# ============================================================
# 프리티어: 500MB/월 무료 (1년)
# 주의: 이미지 크기 관리 필요 → 수명 주기 정책으로 최근 2개만 보관
# ============================================================

resource "aws_ecr_repository" "backend" {
  name                 = "${local.name_prefix}-backend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false  # 스캔은 무료지만 결과 저장 공간 절약
  }

  tags = { Name = "${local.name_prefix}-backend" }
}

resource "aws_ecr_repository" "frontend" {
  name                 = "${local.name_prefix}-frontend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = { Name = "${local.name_prefix}-frontend" }
}

resource "aws_ecr_repository" "agent" {
  name                 = "${local.name_prefix}-agent"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = { Name = "${local.name_prefix}-agent" }
}

# ── 수명 주기 정책: 최근 2개 이미지만 보관 (500MB 한도 보호) ─
locals {
  ecr_lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최근 2개 이미지만 보관 (프리티어 500MB 보호)"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 2
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "backend" {
  repository = aws_ecr_repository.backend.name
  policy     = local.ecr_lifecycle_policy
}

resource "aws_ecr_lifecycle_policy" "frontend" {
  repository = aws_ecr_repository.frontend.name
  policy     = local.ecr_lifecycle_policy
}

resource "aws_ecr_lifecycle_policy" "agent" {
  repository = aws_ecr_repository.agent.name
  policy     = local.ecr_lifecycle_policy
}
