# ============================================================
# AWS Secrets Manager — 민감 정보 관리
# ============================================================

# ── JWT 비밀키 ────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "${local.name_prefix}/jwt-secret"
  description             = "InfraRed JWT 서명 비밀키"
  recovery_window_in_days = 0  # dev: 즉시 삭제 가능

  tags = { Name = "${local.name_prefix}-jwt-secret" }
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret
}

# ── DB 비밀번호 ───────────────────────────────────────────────
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${local.name_prefix}/db-password"
  description             = "InfraRed PostgreSQL 마스터 비밀번호"
  recovery_window_in_days = 0

  tags = { Name = "${local.name_prefix}-db-password" }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.db_password
}
