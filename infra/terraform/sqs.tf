# ============================================================
# SQS 이벤트 버스 — Redis Streams 대체 (설계서 2.5절)
# ============================================================
# 프리티어: SQS 1M 요청/월 항상 무료 (FIFO는 표준의 1/10 = 100K)
# FIFO 큐 = MessageDeduplicationId 기반 Idempotency + 순서 보장
#
# 큐 구성:
#   infrared-events.fifo       — 주 이벤트 버스 (탐지 파이프라인)
#   infrared-events-dlq.fifo   — DLQ (3회 실패 이벤트 격리)
#   infrared-ai-tasks.fifo     — Lambda AI Worker 트리거 전용
#   infrared-spillover.fifo    — EPS 초과 이벤트 임시 보관
# ============================================================

# ── DLQ (Dead Letter Queue) ──────────────────────────────────
resource "aws_sqs_queue" "events_dlq" {
  name                        = "${local.name_prefix}-events-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  message_retention_seconds   = 1209600 # 14일 (최대)

  tags = { Name = "${local.name_prefix}-events-dlq" }
}

# ── 주 이벤트 버스 ───────────────────────────────────────────
resource "aws_sqs_queue" "events" {
  name                        = "${local.name_prefix}-events.fifo"
  fifo_queue                  = true
  content_based_deduplication = true

  # 3회 실패 → DLQ 이동
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.events_dlq.arn
    maxReceiveCount     = 3
  })

  # Long Polling 설정 (불필요한 API 호출 방지, 프리티어 절약)
  receive_wait_time_seconds  = 20
  message_retention_seconds  = 86400  # 1일
  visibility_timeout_seconds = 60     # 워커 처리 타임아웃

  tags = { Name = "${local.name_prefix}-events" }
}

# ── AI Tasks 큐 (Lambda 트리거 전용) ─────────────────────────
resource "aws_sqs_queue" "ai_tasks_dlq" {
  name                        = "${local.name_prefix}-ai-tasks-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  message_retention_seconds   = 1209600

  tags = { Name = "${local.name_prefix}-ai-tasks-dlq" }
}

resource "aws_sqs_queue" "ai_tasks" {
  name                        = "${local.name_prefix}-ai-tasks.fifo"
  fifo_queue                  = true
  content_based_deduplication = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ai_tasks_dlq.arn
    maxReceiveCount     = 3
  })

  receive_wait_time_seconds  = 20
  message_retention_seconds  = 3600   # 1시간 (AI 분석은 신선도 중요)
  visibility_timeout_seconds = 90     # Bedrock 호출 타임아웃 여유

  tags = { Name = "${local.name_prefix}-ai-tasks" }
}

# ── Spill-over 큐 (EPS 초과 이벤트 임시 보관) ───────────────
resource "aws_sqs_queue" "spillover" {
  name                        = "${local.name_prefix}-spillover.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  message_retention_seconds   = 3600  # 1시간 후 자동 삭제

  tags = { Name = "${local.name_prefix}-spillover" }
}

# ── IAM: EC2 → SQS 접근 정책 ────────────────────────────────
resource "aws_iam_role_policy" "ec2_sqs" {
  name = "${local.name_prefix}-ec2-sqs"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ChangeMessageVisibility",
        ]
        Resource = [
          aws_sqs_queue.events.arn,
          aws_sqs_queue.events_dlq.arn,
          aws_sqs_queue.ai_tasks.arn,
          aws_sqs_queue.ai_tasks_dlq.arn,
          aws_sqs_queue.spillover.arn,
        ]
      }
    ]
  })
}

# ── SSM에 큐 URL 저장 (EC2 user_data에서 참조) ───────────────
resource "aws_ssm_parameter" "sqs_events_url" {
  name  = "/${local.name_prefix}/sqs-events-url"
  type  = "String"
  value = aws_sqs_queue.events.url

  tags = { Name = "${local.name_prefix}-sqs-events-url" }
}

resource "aws_ssm_parameter" "sqs_ai_tasks_url" {
  name  = "/${local.name_prefix}/sqs-ai-tasks-url"
  type  = "String"
  value = aws_sqs_queue.ai_tasks.url

  tags = { Name = "${local.name_prefix}-sqs-ai-tasks-url" }
}

# ── Outputs ──────────────────────────────────────────────────
output "sqs_events_url" {
  description = "주 이벤트 버스 SQS FIFO URL"
  value       = aws_sqs_queue.events.url
}

output "sqs_ai_tasks_url" {
  description = "AI Worker Lambda 트리거 SQS URL"
  value       = aws_sqs_queue.ai_tasks.url
}

output "sqs_events_dlq_url" {
  description = "이벤트 DLQ URL (실패 이벤트 모니터링)"
  value       = aws_sqs_queue.events_dlq.url
}
