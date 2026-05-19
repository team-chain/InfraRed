# ============================================================
# CloudWatch — Log Groups + 알람 10개 (설계서 4.1절)
# ============================================================
# 프리티어: 5GB 로그 수집/월 무료 | 10개 커스텀 메트릭 무료
# 보존 기간 7일로 최소화 → 프리티어 한도 보호
# 알람 10개: 무료 한도 내 (11번째부터 $0.10/알람/월)
# ============================================================

locals {
  services = [
    "ingestion",
    "frontend",
    "detection-worker",
    "enrichment-worker",
    "incident-worker",
    "campaign-worker",
    "cleanup-worker",
    "step-ca",        # llm-worker → Lambda 이관, step-ca 추가
    "agent",
    "ec2-init",
  ]

  # SNS 알람 수신 이메일 (SSM에서 관리 가능)
  alarm_email = var.alarm_email
}

resource "aws_cloudwatch_log_group" "services" {
  for_each = toset(local.services)

  name              = "/infrared/${var.env}/${each.key}"
  retention_in_days = var.log_retention_days  # 기본 7일 (프리티어 보호)

  tags = { Service = each.key }
}

# ── SNS 알람 토픽 ─────────────────────────────────────────────
resource "aws_sns_topic" "alarms" {
  name = "${local.name_prefix}-alarms"
  tags = { Name = "${local.name_prefix}-alarms" }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ── 알람 1: EC2 CPU 사용률 > 80% ─────────────────────────────
resource "aws_cloudwatch_metric_alarm" "ec2_cpu" {
  alarm_name          = "${local.name_prefix}-ec2-cpu-high"
  alarm_description   = "EC2 CPU 사용률 80% 초과 (t2.micro 한도 근접)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { InstanceId = aws_instance.main.id }
  tags       = { Alarm = "ec2-cpu" }
}

# ── 알람 2: RDS 연결 수 > 80 ─────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${local.name_prefix}-rds-connections-high"
  alarm_description   = "RDS 연결 수 80 초과 (db.t3.micro 한계 근접)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { DBInstanceIdentifier = aws_db_instance.main.id }
  tags       = { Alarm = "rds-connections" }
}

# ── 알람 3: RDS 여유 스토리지 < 2GB ──────────────────────────
resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${local.name_prefix}-rds-storage-low"
  alarm_description   = "RDS 여유 스토리지 2GB 미만 (프리티어 20GB 중)"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 2147483648  # 2GB (bytes)
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { DBInstanceIdentifier = aws_db_instance.main.id }
  tags       = { Alarm = "rds-storage" }
}

# ── 알람 4: SQS 주 이벤트 큐 깊이 > 1,000 ───────────────────
resource "aws_cloudwatch_metric_alarm" "sqs_depth" {
  alarm_name          = "${local.name_prefix}-sqs-depth-high"
  alarm_description   = "SQS 이벤트 큐 적체 1,000 초과 (파이프라인 지연)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1000
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { QueueName = aws_sqs_queue.events.name }
  tags       = { Alarm = "sqs-depth" }
}

# ── 알람 5: SQS DLQ 메시지 > 0 ──────────────────────────────
resource "aws_cloudwatch_metric_alarm" "sqs_dlq" {
  alarm_name          = "${local.name_prefix}-sqs-dlq-messages"
  alarm_description   = "SQS DLQ에 실패 메시지 존재 (처리 오류 발생)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { QueueName = aws_sqs_queue.events_dlq.name }
  tags       = { Alarm = "sqs-dlq" }
}

# ── 알람 6: Lambda AI Worker 오류율 > 10% ────────────────────
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors-high"
  alarm_description   = "Lambda AI Worker 오류 발생 (Static Playbook Fallback 확인 필요)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { FunctionName = aws_lambda_function.ai_worker.function_name }
  treat_missing_data = "notBreaching"
  tags               = { Alarm = "lambda-errors" }
}

# ── 알람 7: S3 로그 버킷 크기 > 4GB (프리티어 5GB 임박) ──────
resource "aws_cloudwatch_metric_alarm" "s3_bucket_size" {
  alarm_name          = "${local.name_prefix}-s3-size-high"
  alarm_description   = "S3 로그 버킷 4GB 초과 (프리티어 5GB 한도 임박)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400  # 일 1회 (S3 메트릭 기본 주기)
  statistic           = "Maximum"
  threshold           = 4294967296  # 4GB (bytes)
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = {
    BucketName  = aws_s3_bucket.logs.bucket
    StorageType = "StandardStorage"
  }
  treat_missing_data = "notBreaching"
  tags               = { Alarm = "s3-size" }
}

# ── 알람 8: EC2 StatusCheckFailed ────────────────────────────
resource "aws_cloudwatch_metric_alarm" "ec2_status" {
  alarm_name          = "${local.name_prefix}-ec2-status-failed"
  alarm_description   = "EC2 상태 체크 실패 (인스턴스 재시작 필요 가능성)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions         = { InstanceId = aws_instance.main.id }
  treat_missing_data = "notBreaching"
  tags               = { Alarm = "ec2-status" }
}

# ── 알람 9: RDS CPU > 80% ─────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name_prefix}-rds-cpu-high"
  alarm_description   = "RDS CPU 80% 초과 (db.t3.micro 처리 한계)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions = { DBInstanceIdentifier = aws_db_instance.main.id }
  tags       = { Alarm = "rds-cpu" }
}

# ── 알람 10: Lambda 동시 실행 수 > 50 (계정 한도 보호) ───────
resource "aws_cloudwatch_metric_alarm" "lambda_concurrency" {
  alarm_name          = "${local.name_prefix}-lambda-concurrency-high"
  alarm_description   = "Lambda 동시 실행 50 초과 (프리티어 한도 주의)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ConcurrentExecutions"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Maximum"
  threshold           = 50
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  dimensions         = { FunctionName = aws_lambda_function.ai_worker.function_name }
  treat_missing_data = "notBreaching"
  tags               = { Alarm = "lambda-concurrency" }
}

# ── Outputs ──────────────────────────────────────────────────
output "sns_alarm_topic_arn" {
  description = "CloudWatch 알람 SNS 토픽 ARN"
  value       = aws_sns_topic.alarms.arn
}
