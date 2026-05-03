# ============================================================
# Outputs — terraform apply 후 확인할 정보
# ============================================================

# ── 엔드포인트 ────────────────────────────────────────────────
output "ingestion_api_url" {
  description = "Ingestion API URL (에이전트 BACKEND_URL 설정에 사용)"
  value       = "http://${aws_lb.main.dns_name}"
}

output "heartbeat_url" {
  description = "Heartbeat URL"
  value       = "http://${aws_lb.main.dns_name}/heartbeat"
}

output "dashboard_url" {
  description = "웹 대시보드 URL"
  value       = "http://${aws_lb.main.dns_name}:3000"
}

output "alb_dns_name" {
  description = "ALB DNS 이름 (CNAME 설정용)"
  value       = aws_lb.main.dns_name
}

# ── 데이터베이스 ──────────────────────────────────────────────
output "rds_endpoint" {
  description = "RDS PostgreSQL 엔드포인트"
  value       = aws_db_instance.main.address
}

output "rds_port" {
  description = "RDS 포트"
  value       = aws_db_instance.main.port
}

output "database_url" {
  description = "DATABASE_URL (에이전트/서버 설정용) — 민감 정보"
  value       = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name}"
  sensitive   = true
}

# ── Redis ─────────────────────────────────────────────────────
output "redis_endpoint" {
  description = "ElastiCache Redis 엔드포인트"
  value       = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "redis_url" {
  description = "REDIS_URL"
  value       = local.redis_url
}

# ── ECR ──────────────────────────────────────────────────────
output "ecr_backend_uri" {
  description = "Backend ECR 레포지토리 URI"
  value       = aws_ecr_repository.backend.repository_url
}

output "ecr_frontend_uri" {
  description = "Frontend ECR 레포지토리 URI"
  value       = aws_ecr_repository.frontend.repository_url
}

output "ecr_agent_uri" {
  description = "Agent ECR 레포지토리 URI"
  value       = aws_ecr_repository.agent.repository_url
}

# ── ECS ──────────────────────────────────────────────────────
output "ecs_cluster_name" {
  description = "ECS 클러스터 이름"
  value       = aws_ecs_cluster.main.name
}

# ── 마이그레이션 안내 ─────────────────────────────────────────
output "migration_command" {
  description = "DB 스키마 초기화 명령 (최초 1회 실행)"
  value       = <<-EOT
    # 방법 1: psql이 설치된 경우
    psql postgresql://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name} \
      -f backend/app/db/schema.sql \
      -f infra/postgres/seed.sql

    # 방법 2: Docker를 이용하는 경우
    make aws-migrate RDS_HOST=${aws_db_instance.main.address}

    # 방법 3: Python 스크립트
    DATABASE_URL="postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${var.db_name}" \
    python backend/app/db/migrate.py
  EOT
  sensitive   = true
}

# ── 에이전트 배포 안내 ────────────────────────────────────────
output "agent_deploy_hint" {
  description = "에이전트 Docker 실행 명령 (모니터링 대상 서버에서 실행)"
  value       = <<-EOT
    # 모니터링 대상 서버에서 실행
    docker pull ${aws_ecr_repository.agent.repository_url}:latest

    docker run -d \
      --name infrared-agent \
      --restart unless-stopped \
      -e AGENT_TOKEN="<scripts/generate_jwt.py 출력값>" \
      -e BACKEND_URL="http://${aws_lb.main.dns_name}/ingest" \
      -e HEARTBEAT_URL="http://${aws_lb.main.dns_name}/heartbeat" \
      -e TENANT_ID="${var.tenant_id}" \
      -e AGENT_ID="${var.agent_id}" \
      -e ASSET_ID="${var.asset_id}" \
      -v /var/log:/host/var/log:ro \
      -v infrared-state:/var/lib/infrared \
      ${aws_ecr_repository.agent.repository_url}:latest
  EOT
}
