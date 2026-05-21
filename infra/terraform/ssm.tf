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

# ── step-ca Root CA 비밀번호 — v3.0 PKI ──────────────────────
# ec2.tf user_data에서 $SSM_PREFIX/step-ca-password 로 참조함.
# 비워두면 EC2 초기화 시 openssl rand -hex 32 로 자동 생성하지만
# 재배포/재부팅 시 CA 비밀번호 불일치 문제가 생길 수 있으므로
# terraform.tfvars에 명시적으로 지정하는 것을 권장.
resource "aws_ssm_parameter" "step_ca_password" {
  name        = "/${local.name_prefix}/step-ca-password"
  description = "step-ca Root CA 비밀번호 (v3.0 에이전트 mTLS PKI)"
  type        = "SecureString"
  value       = var.step_ca_password != "" ? var.step_ca_password : "change-me-set-in-tfvars"
  tags        = { Name = "${local.name_prefix}-step-ca-password" }
}

# ── Watchdog JWT 토큰 — v3.0 AgentWatchdog ───────────────────
# agent/infrared_agent/watchdog.py 가 WATCHDOG_TOKEN 환경변수로
# 서버의 /api/v1/tamper-report 엔드포인트에 인증하는 별도 JWT.
# scripts/generate_jwt.py --role watchdog 로 생성.
resource "aws_ssm_parameter" "watchdog_token" {
  name        = "/${local.name_prefix}/watchdog-token"
  description = "AgentWatchdog 전용 JWT 토큰 (v3.0 Tamper Detection)"
  type        = "SecureString"
  value       = var.watchdog_token
  tags        = { Name = "${local.name_prefix}-watchdog-token" }
}

