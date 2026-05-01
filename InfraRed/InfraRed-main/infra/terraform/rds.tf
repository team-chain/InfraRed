# ============================================================
# Amazon RDS — PostgreSQL 16
# ============================================================
# dev 설정:
#   - db.t3.micro, 20GB gp2
#   - Single AZ (Multi-AZ 비용 절약)
#   - publicly_accessible = true (로컬 마이그레이션용)
#   - 자동 백업 1일 보존
# ============================================================

# DB 서브넷 그룹 (RDS는 최소 2개 AZ 서브넷 필요)
resource "aws_db_subnet_group" "main" {
  name        = "${local.name_prefix}-db-subnet"
  subnet_ids  = aws_subnet.public[*].id
  description = "InfraRed RDS 서브넷 그룹"

  tags = { Name = "${local.name_prefix}-db-subnet" }
}

resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-postgres"

  # 엔진
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  # 스토리지
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true

  # 접속 정보
  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  # 네트워크
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = true  # dev: 로컬 마이그레이션용

  # 가용성 (dev: Single AZ)
  multi_az            = false
  availability_zone   = var.availability_zones[0]

  # 백업
  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # 삭제 보호 (dev: 비활성)
  deletion_protection       = false
  skip_final_snapshot       = true
  final_snapshot_identifier = null

  # 모니터링
  performance_insights_enabled = false

  tags = { Name = "${local.name_prefix}-postgres" }
}
