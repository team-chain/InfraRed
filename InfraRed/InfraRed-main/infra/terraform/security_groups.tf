# ============================================================
# 보안 그룹
# ============================================================
# alb_sg    : 인터넷 → ALB (80, 3000)
# ecs_sg    : ALB → ECS 태스크 + ECS 간 내부 통신
# rds_sg    : ECS → PostgreSQL (5432)
# redis_sg  : ECS → Redis (6379)
# ============================================================

# ── ALB Security Group ───────────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "InfraRed ALB — 인터넷 수신"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP Ingestion API"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Frontend"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-alb-sg" }
}

# ── ECS Tasks Security Group ─────────────────────────────────
resource "aws_security_group" "ecs" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "InfraRed ECS 태스크 — ALB + 내부 통신"
  vpc_id      = aws_vpc.main.id

  # ALB → Ingestion API
  ingress {
    description     = "Ingestion API from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # ALB → Frontend
  ingress {
    description     = "Frontend from ALB"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # ECS 내부 통신 (workers ↔ workers — 향후 확장 대비)
  ingress {
    description = "ECS 내부 통신"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  # 외부 전체 허용 (ECR pull, Bedrock, Secrets Manager 등)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-ecs-sg" }
}

# ── RDS Security Group ───────────────────────────────────────
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "InfraRed RDS — ECS 태스크만 허용"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  # 개발용: 로컬 머신에서 직접 접속 (배포 후 마이그레이션용)
  ingress {
    description = "PostgreSQL from anywhere (dev only)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-rds-sg" }
}

# ── ElastiCache Security Group ───────────────────────────────
resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "InfraRed Redis — ECS 태스크만 허용"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-redis-sg" }
}
