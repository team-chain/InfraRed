# ============================================================
# 보안 그룹 — Cloudflare proxy 전제
# ============================================================
# 트래픽 흐름:
#   사용자 → Cloudflare → EC2:443 (nginx) → frontend:80 / ingestion:8000 (내부 네트워크)
#
# 외부 직접 노출 (Cloudflare 우회):
#   :22   SSH (본인 IP)
#   :443  HTTPS (Cloudflare IP만 허용)
#   :8000 Ingestion (에이전트 직접 호출 — 향후 도메인 경유로 마이그레이션 시 제거 가능)
#   :9090, :3001 Prometheus/Grafana (본인 IP)
#
# 닫힌 포트:
#   :80   HTTP (Cloudflare는 443으로 origin 접속하므로 불필요)
#   :3000 Frontend 직접 (nginx 경유로만 접근)
# ============================================================

# ── Cloudflare IPv4 대역 (2024 기준, 정기 갱신 필요) ─────────
# 갱신: https://www.cloudflare.com/ips-v4/
locals {
  cloudflare_ipv4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
  ]
}

# ── EC2 Security Group ───────────────────────────────────────
resource "aws_security_group" "ec2" {
  name        = "${local.name_prefix}-ec2-sg"
  # description은 변경 시 SG 교체를 강제하므로 실제 AWS의 기존 값을 유지.
  # 의미 변경(HTTPS Cloudflare 제한 등)은 ingress 룰의 description으로 표현.
  description = "InfraRed EC2 - SSH + App ports"
  vpc_id      = aws_vpc.main.id

  # SSH (본인 IP만)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # HTTPS — Cloudflare IP만 허용 (origin 직접 우회 차단)
  ingress {
    description = "HTTPS (Cloudflare only)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.cloudflare_ipv4
  }

  # Ingestion API — 에이전트 직접 호출용 (TODO: api.infrared.kr 경유로 마이그레이션 후 제거)
  ingress {
    description = "Ingestion API (agent direct)"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Prometheus (선택)
  ingress {
    description = "Prometheus"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Grafana (선택)
  ingress {
    description = "Grafana"
    from_port   = 3001
    to_port     = 3001
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-ec2-sg" }
}

# ── RDS Security Group ───────────────────────────────────────
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "InfraRed RDS - EC2 only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from EC2"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-rds-sg" }
}
