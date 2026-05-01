# ============================================================
# InfraRed — 입력 변수
# ============================================================

# ── 기본 ────────────────────────────────────────────────────
variable "project" {
  description = "프로젝트 이름 (리소스 이름 접두사)"
  type        = string
  default     = "infrared"
}

variable "env" {
  description = "배포 환경 (dev | staging | prod)"
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
  description = "VPC CIDR 블록"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "퍼블릭 서브넷 CIDR (ALB + ECS 퍼블릭 IP)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  description = "사용할 AZ 목록 (ALB는 2개 이상 필요)"
  type        = list(string)
  default     = ["ap-northeast-2a", "ap-northeast-2b"]
}

# ── RDS ─────────────────────────────────────────────────────
variable "db_instance_class" {
  description = "RDS 인스턴스 타입"
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "PostgreSQL 데이터베이스 이름"
  type        = string
  default     = "infrared"
}

variable "db_username" {
  description = "PostgreSQL 마스터 유저명"
  type        = string
  default     = "infrared"
}

variable "db_password" {
  description = "PostgreSQL 마스터 비밀번호"
  type        = string
  sensitive   = true
}

variable "db_allocated_storage" {
  description = "RDS 스토리지 (GB)"
  type        = number
  default     = 20
}

# ── ElastiCache ──────────────────────────────────────────────
variable "redis_node_type" {
  description = "ElastiCache Redis 노드 타입"
  type        = string
  default     = "cache.t3.micro"
}

# ── JWT / 보안 ────────────────────────────────────────────────
variable "jwt_secret" {
  description = "JWT 서명 비밀키 (최소 32자)"
  type        = string
  sensitive   = true
}

variable "jwt_issuer" {
  description = "JWT issuer 클레임"
  type        = string
  default     = "infrared"
}

variable "jwt_audience" {
  description = "JWT audience 클레임"
  type        = string
  default     = "infrared-ingest"
}

# ── 애플리케이션 ──────────────────────────────────────────────
variable "tenant_id" {
  description = "기본 테넌트 ID"
  type        = string
  default     = "company-a"
}

variable "agent_id" {
  description = "기본 에이전트 ID"
  type        = string
  default     = "agent-001"
}

variable "asset_id" {
  description = "기본 자산 ID"
  type        = string
  default     = "asset-001"
}

variable "cors_origins" {
  description = "CORS 허용 오리진 (쉼표 구분)"
  type        = string
  default     = "*"
}

# ── Bedrock (LLM) ────────────────────────────────────────────
variable "bedrock_region" {
  description = "Bedrock 리전 (모델 가용 리전)"
  type        = string
  default     = "us-east-1"
}

variable "bedrock_model_id" {
  description = "Bedrock 모델 ID"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

# ── Slack / Email (선택) ─────────────────────────────────────
variable "slack_webhook_url" {
  description = "Slack Webhook URL (비워두면 비활성)"
  type        = string
  default     = ""
  sensitive   = true
}

# ── ECS 태스크 크기 ───────────────────────────────────────────
variable "ingestion_cpu" {
  description = "Ingestion API CPU 유닛"
  type        = number
  default     = 512
}

variable "ingestion_memory" {
  description = "Ingestion API 메모리 (MB)"
  type        = number
  default     = 1024
}

variable "worker_cpu" {
  description = "Worker CPU 유닛"
  type        = number
  default     = 256
}

variable "worker_memory" {
  description = "Worker 메모리 (MB)"
  type        = number
  default     = 512
}

variable "log_retention_days" {
  description = "CloudWatch 로그 보존 기간 (일)"
  type        = number
  default     = 30
}
