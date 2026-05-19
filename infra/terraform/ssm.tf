# ============================================================
# SSM Parameter Store — 시크릿 관리 (Secrets Manager 대체)
# ============================================================
# Secrets Manager: $0.40/시크릿/월 -> 유료
# SSM Parameter Store 표준 파라미터: 무료
# SecureString 타입으로 KMS 암호화 (기본 KMS 키 사용 -> 무료)
# ============================================================

# ── JWT 비밀키 ────────────────────────────────────────────────
resource "aws_ssm_parameter" "jwt_secret" {
  name        = "/${local.name_prefix}/jwt-secret"
  description = "InfraRed JWT 서명 비밀키"
  type        = "SecureString"
  value       = var.jwt_secret
  tags        = { Name = "${local.name_prefix}-jwt-secret" }
}

# ── DB 비밀번호 ───────────────────────────────────────────────
resource "aws_ssm_parameter" "db_password" {
  name        = "/${local.name_prefix}/db-password"
  description = "InfraRed PostgreSQL 비밀번호"
  type        = "SecureString"
  value       = var.db_password
  tags        = { Name = "${local.name_prefix}-db-password" }
}

# ── Agent JWT 토큰 ────────────────────────────────────────────
resource "aws_ssm_parameter" "agent_token" {
  name        = "/${local.name_prefix}/agent-token"
  description = "InfraRed 에이전트 JWT 토큰"
  type        = "SecureString"
  value       = var.agent_token
  tags        = { Name = "${local.name_prefix}-agent-token" }
}

# ── Discord Webhook (선택) ────────────────────────────────────
resource "aws_ssm_parameter" "discord_webhook_url" {
  name        = "/${local.name_prefix}/discord-webhook-url"
  description = "Discord Webhook URL"
  type        = "SecureString"
  value       = var.discord_webhook_url != "" ? var.discord_webhook_url : "disabled"
  tags        = { Name = "${local.name_prefix}-discord-webhook" }
}

# ── Slack Webhook (선택) — v3.0 ──────────────────────────────
resource "aws_ssm_parameter" "slack_webhook_url" {
  name        = "/${local.name_prefix}/slack-webhook-url"
  description = "Slack Webhook URL (v3.0 선택)"
  type        = "SecureString"
  value       = var.slack_webhook_url != "" ? var.slack_webhook_url : "disabled"
  tags        = { Name = "${local.name_prefix}-slack-webhook" }
}

# ── AbuseIPDB API Key (선택, OTX fallback) ───────────────────
resource "aws_ssm_parameter" "abuseipdb_api_key" {
  name        = "/${local.name_prefix}/abuseipdb-api-key"
  description = "AbuseIPDB API Key (OTX 없을 때 fallback CTI)"
  type        = "SecureString"
  value       = var.abuseipdb_api_key != "" ? var.abuseipdb_api_key : "disabled"
  tags        = { Name = "${local.name_prefix}-abuseipdb-key" }
}

# ── AlienVault OTX API Key — v3.0 CTI ────────────────────────
resource "aws_ssm_parameter" "otx_api_key" {
  name        = "/${local.name_prefix}/otx-api-key"
  description = "AlienVault OTX API Key (v3.0 CTI 연동)"
  type        = "SecureString"
  value       = var.otx_api_key != "" ? var.otx_api_key : "disabled"
  tags        = { Name = "${local.name_prefix}-otx-api-key" }
}

# ── Agent Command HMAC Secret — v3.0 block_ip 서명 ───────────
resource "aws_ssm_parameter" "agent_command_secret" {
  name        = "/${local.name_prefix}/agent-command-secret"
  description = "block_ip 명령 HMAC 서명 비밀키 (v3.0)"
  type        = "SecureString"
  value       = var.agent_command_secret
  tags        = { Name = "${local.name_prefix}-agent-command-secret" }
}
