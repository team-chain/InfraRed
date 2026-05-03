# ============================================================
# CloudWatch Log Groups — 서비스별 로그 분리
# ============================================================

locals {
  services = [
    "ingestion",
    "frontend",
    "detection-worker",
    "enrichment-worker",
    "correlation-worker",
    "llm-worker",
    "agent",
  ]
}

resource "aws_cloudwatch_log_group" "services" {
  for_each = toset(local.services)

  name              = "/infrared/${var.env}/${each.key}"
  retention_in_days = var.log_retention_days

  tags = { Service = each.key }
}
