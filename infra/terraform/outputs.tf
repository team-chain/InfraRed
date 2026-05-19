# ============================================================
# Outputs — terraform apply 후 확인할 정보
# ============================================================

# ── EC2 접속 정보 ─────────────────────────────────────────────
output "ec2_public_ip" {
  description = "EC2 퍼블릭 IP (Elastic IP)"
  value       = aws_eip.main.public_ip
}

output "ssh_command" {
  description = "EC2 SSH 접속 명령"
  value       = "ssh -i ~/.ssh/${var.ec2_key_name}.pem ec2-user@${aws_eip.main.public_ip}"
}

# ── 앱 엔드포인트 ─────────────────────────────────────────────
output "ingestion_api_url" {
  description = "Ingestion API URL (에이전트 BACKEND_URL)"
  value       = "http://${aws_eip.main.public_ip}:8000"
}

output "dashboard_url" {
  description = "웹 대시보드 URL"
  value       = "http://${aws_eip.main.public_ip}:3000"
}

output "healthz_url" {
  description = "헬스체크 URL"
  value       = "http://${aws_eip.main.public_ip}:8000/healthz"
}

# ── RDS ──────────────────────────────────────────────────────
output "rds_endpoint" {
  description = "RDS PostgreSQL 엔드포인트 (EC2 내부에서만 접근 가능)"
  value       = aws_db_instance.main.address
}

output "database_url" {
  description = "DATABASE_URL (민감 정보)"
  value       = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:5432/${var.db_name}"
  sensitive   = true
}

# ── ECR ──────────────────────────────────────────────────────
output "ecr_backend_uri" {
  description = "Backend ECR URI"
  value       = aws_ecr_repository.backend.repository_url
}

output "ecr_frontend_uri" {
  description = "Frontend ECR URI"
  value       = aws_ecr_repository.frontend.repository_url
}

output "ecr_agent_uri" {
  description = "Agent ECR URI"
  value       = aws_ecr_repository.agent.repository_url
}

# ── S3 ───────────────────────────────────────────────────────
output "s3_logs_bucket" {
  description = "로그 보관 S3 버킷"
  value       = aws_s3_bucket.logs.bucket
}

output "s3_reports_bucket" {
  description = "리포트 S3 버킷"
  value       = aws_s3_bucket.reports.bucket
}

# ── 배포 후 체크리스트 ────────────────────────────────────────
output "next_steps" {
  description = "배포 후 수행할 작업"
  value       = <<-EOT

    ✅ Terraform Apply 완료!

    ── 1. 이미지 빌드 & ECR 푸시 ──────────────────────────────
    ./scripts/aws-deploy.sh --push-only

    ── 2. EC2 초기화 완료 확인 (약 3~5분 소요) ────────────────
    ssh -i ~/.ssh/${var.ec2_key_name}.pem ec2-user@${aws_eip.main.public_ip}
    tail -f /var/log/infrared-init.log

    ── 3. 컨테이너 상태 확인 ──────────────────────────────────
    ssh -i ~/.ssh/${var.ec2_key_name}.pem ec2-user@${aws_eip.main.public_ip} \
      "docker compose -f /opt/infrared/docker-compose.yml ps"

    ── 4. 앱 접속 ─────────────────────────────────────────────
    대시보드 : http://${aws_eip.main.public_ip}:3000
    API      : http://${aws_eip.main.public_ip}:8000/healthz

    ── 5. 에이전트 배포 (모니터링 대상 서버에서) ───────────────
    curl -sSL http://${aws_eip.main.public_ip}:8000/install-agent.sh | \
      bash -s -- \
        --token="$(aws ssm get-parameter --name /${local.name_prefix}/agent-token --with-decryption --query Parameter.Value --output text)" \
        --tenant="${var.tenant_id}" \
        --url="http://${aws_eip.main.public_ip}"

    ── 6. CloudWatch 로그 확인 ────────────────────────────────
    aws logs tail /infrared/${var.env}/ingestion --follow --region ${var.region}

  EOT
}

# ── 프리티어 사용량 경고 ──────────────────────────────────────
output "free_tier_warning" {
  description = "프리티어 한도 주의사항"
  value       = <<-EOT

    ⚠️  프리티어 한도 주의사항:
    - EC2 t2.micro : 750시간/월 (단일 인스턴스 = 약 31일 × 24h = 744h → 안전)
    - RDS db.t3.micro : 750시간/월 (동일)
    - S3 : 5GB 무료 → 수명 주기 30일 자동 삭제 설정됨
    - ECR : 500MB/월 → 수명 주기 최근 2개 이미지만 보관 설정됨
    - CloudWatch 로그 : 5GB/월 → 보존 7일 설정됨
    - EIP : EC2에 연결된 상태면 무료 (인스턴스 중지 시 과금 주의!)
    - SSM Parameter Store : 표준 파라미터 무료
    - Bedrock : 프리티어 없음 → 호출 횟수에 따라 과금 (LLM_PROVIDER=static으로 비활성 가능)

  EOT
}
