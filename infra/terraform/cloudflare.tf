# ============================================================
# Cloudflare DNS — infrared.kr 도메인 레코드 (선택)
# ============================================================
# cloudflare_zone_id 가 비어("") 있으면 Cloudflare 리소스 전체를 건너뛴다.
# → 데모는 EC2 공인 IP만으로 충분하므로 기본 비활성.
# 도메인을 쓰려면 terraform.tfvars 에:
#   cloudflare_api_token = "<token>"
#   cloudflare_zone_id   = "<zone-id>"
# ============================================================

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

locals {
  cloudflare_enabled = var.cloudflare_zone_id != "" ? 1 : 0
}

resource "cloudflare_record" "root" {
  count   = 0  # 레코드는 Cloudflare 대시보드에서 직접 관리(수동 edit) → 중복 생성 방지
  zone_id = var.cloudflare_zone_id
  name    = "infrared.kr"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1
  proxied = true
  comment = "Managed by Terraform — points to EC2 EIP via Cloudflare proxy"
}

resource "cloudflare_record" "app" {
  count   = 0  # 레코드는 Cloudflare 대시보드에서 직접 관리(수동 edit) → 중복 생성 방지
  zone_id = var.cloudflare_zone_id
  name    = "app"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1
  proxied = true
  comment = "Managed by Terraform — Frontend dashboard"
}

resource "cloudflare_record" "api" {
  count   = 0  # 레코드는 Cloudflare 대시보드에서 직접 관리(수동 edit) → 중복 생성 방지
  zone_id = var.cloudflare_zone_id
  name    = "api"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1
  proxied = true
  comment = "Managed by Terraform — Ingestion API"
}

resource "cloudflare_zone_settings_override" "infrared" {
  count   = local.cloudflare_enabled
  zone_id = var.cloudflare_zone_id

  settings {
    ssl                      = "full"  # origin은 자체서명 인증서(ec2-deploy.sh가 자동 생성) → strict 아님
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    brotli                   = "on"
    http3                    = "on"
    websockets               = "on"
    security_level           = "medium"
  }
}
