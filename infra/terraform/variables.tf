# ============================================================
# InfraRed — 입력 변수 (프리티어 최적화)
# ============================================================

# ── 기본 ────────────────────────────────────────────────────
variable "project" {
  description = "프로젝트 이름 (리소스 이름 접두사)"
  type        = string
  default     = "infrared"
}

variable "env" {
  description = "배포 환경"
  type        = string
  default     = "dev"
}

variable "region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

# ── 네트워크 ─────────────────────────────────────────────────
variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "퍼블릭 서브넷 CIDR (RDS는 2개 AZ 필요)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  type    = list(string)
  default = ["ap-northeast-2a", "ap-northeast-2b"]
}

# ── EC2 (프리티어: t2.micro) ──────────────────────────────────
variable "ec2_instance_type" {
  description = "EC2 인스턴스 타입 — t2.micro 프리티어"
  type        = string
  default     = "t2.micro"
}

variable "ec2_key_name" {
  description = "EC2 SSH 키페어 이름 (AWS 콘솔에서 미리 생성)"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "SSH 허용 IP (본인 IP/32 권장, 0.0.0.0/0은 보안 위험)"
  type        = string
  default     = "0.0.0.0/0"
}

# ── RDS (프리티어: db.t3.micro, 20GB) ────────────────────────
variable "db_instance_class" {
  description = "RDS 인스턴스 타입 — db.t3.micro 프리티어"
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  type    = string
  default = "infrared"
}

variable "db_username" {
  type    = string
  default = "infrared"
}

variable "db_password" {
  description = "PostgreSQL 마스터 비밀번호 (최소 8자)"
  type        = string
  sensitive   = true
}

variable "db_allocated_storage" {
  description = "RDS 스토리지 GB — 프리티어 20GB 한도"
  type        = number
  default     = 20
}

# ── JWT / 보안 ────────────────────────────────────────────────
variable "jwt_secret" {
  description = "JWT 서명 비밀키 (최소 32자)"
  type        = string
  sensitive   = true
}

variable "jwt_issuer" {
  type    = string
  default = "infrared"
}

variable "jwt_audience" {
  type    = string
  default = "infrared-ingest"
}

# ── 애플리케이션 ──────────────────────────────────────────────
variable "tenant_id" {
  type    = string
  default = "company-a"
}

variable "agent_id" {
  type    = string
  default = "agent-001"
}

variable "asset_id" {
  type    = string
  default = "asset-001"
}

variable "cors_origins" {
  type    = string
  default = "*"
}

# ── Bedrock (LLM) ────────────────────────────────────────────
variable "bedrock_region" {
  type    = string
  default = "us-east-1"
}

variable "bedrock_model_id" {
  type    = string
  default = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

# ── 알림 (선택) ───────────────────────────────────────────────
variable "discord_webhook_url" {
  description = "Discord Webhook URL (비워두면 비활성)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "abuseipdb_api_key" {
  description = "AbuseIPDB API Key (OTX 없을 때 fallback CTI)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "otx_api_key" {
  description = "AlienVault OTX API Key — v3.0 CTI 연동 (비워두면 AbuseIPDB 또는 mock)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "agent_command_secret" {
  description = "Agent block_ip 명령 HMAC 서명 비밀키 (최소 32자) — v3.0"
  type        = string
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack Webhook URL (비워두면 비활성)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "agent_token" {
  description = "에이전트 JWT 토큰 (scripts/generate_jwt.py --role agent 출력값)"
  type        = string
  sensitive   = true
}

# ── CloudWatch 로그 보존 ──────────────────────────────────────
variable "log_retention_days" {
  description = "CloudWatch 로그 보존 기간 — 프리티어 5GB 한도 고려"
  type        = number
  default     = 7
}

# ── CloudWatch 알람 알림 ──────────────────────────────────────
variable "alarm_email" {
  description = "CloudWatch 알람 수신 이메일 (비워두면 SNS 이메일 구독 비활성)"
  type        = string
  default     = ""
}

# ── step-ca 비밀번호 ──────────────────────────────────────────
variable "step_ca_password" {
  description = "step-ca Root CA 비밀번호 (SSM에 저장, 비워두면 자동 생성)"
  type        = string
  default     = ""
  sensitive   = true
}

# ── Watchdog JWT 토큰 — v3.0 AgentWatchdog ───────────────────
variable "watchdog_token" {
  description = "AgentWatchdog 전용 JWT 토큰 (scripts/generate_jwt.py --role watchdog 로 생성)"
  type        = string
  sensitive   = true
}

# ── Watchdog JWT 토큰 — v3.0 AgentWatchdog ───────────────────
variable "watchdog_token" {
  description = "AgentWatchdog 전용 JWT 토큰 (scripts/generate_jwt.py --role watchdog 로 생성)"
  type        = string
  sensitive   = true
}
