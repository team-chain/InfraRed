# ============================================================
# Amazon S3 — 로그 보관 + 리포트 저장 (프리티어)
# ============================================================
# 프리티어: 5GB 스토리지, 20,000 GET, 2,000 PUT 요청/월 (1년)
# 주의: 5GB 초과 시 과금 → 수명 주기 정책으로 자동 삭제
# ============================================================

# ── 로그 보관 버킷 ────────────────────────────────────────────
resource "aws_s3_bucket" "logs" {
  bucket = "${local.name_prefix}-logs-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "${local.name_prefix}-logs", Purpose = "log-archive" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 프리티어 5GB 한도 보호: 30일 후 자동 삭제
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "auto-delete-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}

# ── 리포트 버킷 ───────────────────────────────────────────────
resource "aws_s3_bucket" "reports" {
  bucket = "${local.name_prefix}-reports-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "${local.name_prefix}-reports", Purpose = "pdf-reports" }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 리포트 30일 후 삭제
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "auto-delete-old-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}
