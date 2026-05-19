# ============================================================
# Amazon RDS — PostgreSQL 16 (프리티어)
# ============================================================
# 프리티어 조건:
#   - db.t3.micro (또는 db.t2.micro)
#   - 20GB gp2 스토리지
#   - 750시간/월 (1년)
#   - 자동 백업 0일 (백업도 스토리지 소비 → 프리티어 한도 주의)
# ============================================================

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet"
  subnet_ids = aws_subnet.public[*].id

  tags = { Name = "${local.name_prefix}-db-subnet" }
}

resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class  # db.t3.micro

  # 프리티어: 20GB gp2
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage  # 자동 확장 비활성 (비용 방지)
  storage_type          = "gp2"
  storage_encrypted     = false  # 프리티어: 암호화 비활성 (추가 비용 없지만 일부 인스턴스 제한)

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false  # EC2를 통해서만 접근

  multi_az          = false  # 프리티어: Single AZ
  availability_zone = var.availability_zones[0]

  # 프리티어: 백업 최소화 (스토리지 절약)
  backup_retention_period = 0  # 자동 백업 비활성
  skip_final_snapshot     = true
  deletion_protection     = false

  performance_insights_enabled = false  # 유료 기능 비활성

  tags = { Name = "${local.name_prefix}-postgres" }
}
