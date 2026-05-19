# ============================================================
# Lambda AI Worker — Bedrock Claude 분석 (설계서 2.6절)
# ============================================================
# 프리티어: Lambda 1M 요청/월, 400K GB-s/월 항상 무료
# 비용 발생: Bedrock 호출만 (인시던트 건수 비례)
#
# EC2 메모리 절약: llm-worker를 Lambda로 분리 → EC2 ~100MB 확보
# 트리거: SQS infrared-ai-tasks.fifo
# Fallback: Bedrock 장애 시 Static Playbook 자동 전환
# ============================================================

# ── Lambda 패키지 빌드 ───────────────────────────────────────
# Lambda 배포 전 수동 빌드 필요:
#   cd lambda/ai_worker
#   pip install -r requirements.txt -t package/
#   cp handler.py package/
#   cd package && zip -r ../ai_worker.zip .
data "archive_file" "ai_worker" {
  type        = "zip"
  source_dir  = "${path.root}/../../lambda/ai_worker"
  output_path = "${path.root}/../../lambda/ai_worker.zip"

  # requirements.txt 제외 (패키지는 별도 빌드)
  excludes = ["requirements.txt", "__pycache__", "*.pyc"]
}

# ── Lambda 실행 역할 ─────────────────────────────────────────
resource "aws_iam_role" "lambda_ai_worker" {
  name = "${local.name_prefix}-lambda-ai-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${local.name_prefix}-lambda-ai-worker" }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_ai_worker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC 내 ENI 생성 권한 (CreateNetworkInterface 포함)
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_ai_worker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "lambda_ai_worker" {
  name = "${local.name_prefix}-lambda-ai-worker-policy"
  role = aws_iam_role.lambda_ai_worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # SQS 접근 (트리거 + DLQ)
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility",
        ]
        Resource = [
          aws_sqs_queue.ai_tasks.arn,
          aws_sqs_queue.ai_tasks_dlq.arn,
        ]
      },
      # Bedrock 호출 (Claude Haiku + Sonnet)
      {
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]
        Resource = [
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-haiku-4-5-20251001",
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-sonnet-4-6",
        ]
      },
      # SSM Parameter Store (DB 비밀번호 조회)
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParametersByPath"]
        Resource = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.name_prefix}/*"
      },
      # CloudWatch 로그
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
    ]
  })
}

# ── Lambda 함수 ──────────────────────────────────────────────
resource "aws_lambda_function" "ai_worker" {
  filename         = data.archive_file.ai_worker.output_path
  source_code_hash = data.archive_file.ai_worker.output_base64sha256
  function_name    = "${local.name_prefix}-ai-worker"
  role             = aws_iam_role.lambda_ai_worker.arn
  handler          = "handler.handler"
  runtime          = "python3.12"

  # 설계서 2.6절: 512MB, 60초 타임아웃
  memory_size = 512
  timeout     = 60

  environment {
    variables = {
      ENV           = var.env
      BEDROCK_REGION = var.region   # AWS_REGION은 Lambda 예약어 — 자동 주입됨
      POSTGRES_HOST  = aws_db_instance.main.address
      POSTGRES_PORT  = "5432"
      POSTGRES_DB    = var.db_name
      POSTGRES_USER  = var.db_username
      # DB 비밀번호는 SSM에서 런타임 조회 (보안)
      SSM_PREFIX     = "/${local.name_prefix}"
    }
  }

  # VPC 내부에서 RDS 접근 (EC2와 같은 VPC)
  vpc_config {
    subnet_ids         = aws_subnet.public[*].id
    security_group_ids = [aws_security_group.ec2.id]
  }

  # Bedrock 리전 (ap-northeast-2에서 지원 모델 확인 필요)
  # Claude Haiku / Sonnet은 us-east-1에서 호출 후 결과 저장도 가능

  tags = { Name = "${local.name_prefix}-ai-worker" }
}

# ── SQS → Lambda 트리거 ──────────────────────────────────────
resource "aws_lambda_event_source_mapping" "ai_worker_sqs" {
  event_source_arn                   = aws_sqs_queue.ai_tasks.arn
  function_name                      = aws_lambda_function.ai_worker.arn
  batch_size                         = 5     # 한 번에 최대 5개 인시던트 처리
  function_response_types            = ["ReportBatchItemFailures"]

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_ai_worker,
  ]
}

# ── CloudWatch Log Group (Lambda) ────────────────────────────
resource "aws_cloudwatch_log_group" "lambda_ai_worker" {
  name              = "/aws/lambda/${aws_lambda_function.ai_worker.function_name}"
  retention_in_days = 7  # 프리티어 보호

  tags = { Service = "lambda-ai-worker" }
}

# ── Outputs ──────────────────────────────────────────────────
output "lambda_ai_worker_arn" {
  description = "AI Worker Lambda ARN"
  value       = aws_lambda_function.ai_worker.arn
}

output "lambda_ai_worker_name" {
  description = "AI Worker Lambda 함수명"
  value       = aws_lambda_function.ai_worker.function_name
}
