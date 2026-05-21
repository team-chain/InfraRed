# ============================================================
# Cloudflare DNS — infrared.kr 도메인 레코드
# ============================================================
# 사전 준비:
#   1) Cloudflare 대시보드에서 API Token 생성
#      Permission: Zone : DNS : Edit + Zone : Zone : Read
#      Zone Resources: Include - Specific zone - infrared.kr
#   2) Zone ID 확인: 대시보드 우측 사이드바 "API" 섹션
#   3) terraform.tfvars 에 아래 추가:
#        cloudflare_api_token = "<token>"
#        cloudflare_zone_id   = "<zone-id>"
# ============================================================

# Cloudflare provider는 main.tf의 required_providers 블록에 추가 필요 (수동)
# terraform {
#   required_providers {
#     cloudflare = {
#       source  = "cloudflare/cloudflare"
#       version = "~> 4.0"
#     }
#   }
# }

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ── A 레코드 ────────────────────────────────────────────────
# Cloudflare proxied=true → CF가 SSL 처리 + DDoS 방어 + 캐싱
# 직접 EC2로 가지 않고 Cloudflare → EC2 nginx 경유

resource "cloudflare_record" "root" {
  zone_id = var.cloudflare_zone_id
  name    = "infrared.kr"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1     # 1 = Auto (proxied=true일 때만 유효)
  proxied = true

  comment = "Managed by Terraform — points to EC2 EIP via Cloudflare proxy"
}

resource "cloudflare_record" "app" {
  zone_id = var.cloudflare_zone_id
  name    = "app"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1
  proxied = true

  comment = "Managed by Terraform — Frontend dashboard"
}

resource "cloudflare_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = "api"
  content = aws_eip.main.public_ip
  type    = "A"
  ttl     = 1
  proxied = true

  comment = "Managed by Terraform — Ingestion API"
}

# ── SSL 설정 ────────────────────────────────────────────────
# Full (strict): origin 인증서 검증 활성화
# origin 인증서는 EC2 nginx가 보유 (Cloudflare Origin CA 발급)
resource "cloudflare_zone_settings_override" "infrared" {
  zone_id = var.cloudflare_zone_id

  settings {
    ssl                      = "strict"        # Full (strict)
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
