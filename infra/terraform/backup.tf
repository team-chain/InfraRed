# ============================================================
# 백업 자동화 (설계서 §4.2) — 프리티어 한도 내 구현
# ============================================================
# 프리티어 범위:
#   ✅ step-ca S3 백업  : Lambda 무료 + S3 소용량(수 MB) → 무료 5GB 내
#   ✅ RDS 자동 백업    : backup_retention_period=7 (rds.tf) → 20GB 한도 내 무료
#
# 프리티어 초과로 미구현:
#   ❌ EBS 스냅샷 Lambda: EBS 스냅샷 $0.05/GB/월 (20GB → $1/월)
#   ❌ RDS 수동 스냅샷   : 자동 백업 7일 보존으로 대체 (추가 수동 스냅샷은 비용 발생)
# ============================================================

# ── 공통: 백업 Lambda 실행 역할 ──────────────────────────────
resource "aws_iam_role" "backup_lambda" {
  name = "${local.name_prefix}-backup-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${local.name_prefix}-backup-lambda-role" }
}

resource "aws_iam_role_policy_attachment" "backup_lambda_basic" {
  role       = aws_iam_role.backup_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "backup_lambda_policy" {
  name = "backup-lambda-policy"
  role = aws_iam_role.backup_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3: step-ca 볼륨 백업 업로드 (logs 버킷 내 backups/ 폴더)
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/backups/*",
        ]
      },
      # SSM: EC2에서 step-ca 볼륨 tar 압축 명령 실행
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation",
        ]
        Resource = "*"
      },
    ]
  })
}

# ── step-ca S3 백업 Lambda (주 1회, 프리티어 무료) ───────────
# step-ca Docker 볼륨을 SSM으로 tar 압축 후 S3 업로드
# 볼륨 크기: 수 MB (인증서 파일만) → S3 5GB 무료 한도에 영향 없음
data "archive_file" "step_ca_backup" {
  type                    = "zip"
  output_path             = "${path.module}/../../lambda/step_ca_backup.zip"
  source_content_filename = "handler.py"
  source_content          = <<-PYTHON
import boto3
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    step-ca Docker 볼륨을 EC2 SSM으로 tar 압축 후 S3에 업로드.
    설계서 §4.2: 주 1회 암호화 백업.
    Lambda + S3 소용량 → 프리티어 완전 무료.
    """
    ssm         = boto3.client("ssm")
    instance_id = os.environ["EC2_INSTANCE_ID"]
    s3_bucket   = os.environ["S3_BUCKET"]
    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    s3_key      = f"backups/step-ca/{timestamp}.tar.gz"
    tmp_path    = f"/tmp/step-ca-backup-{timestamp}.tar.gz"

    # SSM으로 EC2에서 step-ca 볼륨을 tar 압축 후 S3 직접 업로드
    cmd = " && ".join([
        f"docker run --rm -v step-ca-data:/mnt/step-ca:ro -v /tmp:/tmp alpine tar czf {tmp_path} -C /mnt/step-ca .",
        f"aws s3 cp {tmp_path} s3://{s3_bucket}/{s3_key}",
        f"rm -f {tmp_path}",
    ])

    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [cmd]},
    )
    command_id = response["Command"]["CommandId"]
    logger.info(f"step-ca backup sent: command_id={command_id}, s3_key={s3_key}")
    return {"status": "ok", "command_id": command_id, "s3_key": s3_key}
PYTHON
}

resource "aws_lambda_function" "step_ca_backup" {
  filename         = data.archive_file.step_ca_backup.output_path
  source_code_hash = data.archive_file.step_ca_backup.output_base64sha256
  function_name    = "${local.name_prefix}-step-ca-backup"
  role             = aws_iam_role.backup_lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  memory_size      = 128
  timeout          = 120

  environment {
    variables = {
      EC2_INSTANCE_ID = aws_instance.main.id
      S3_BUCKET       = aws_s3_bucket.logs.bucket
    }
  }

  tags = { Name = "${local.name_prefix}-step-ca-backup" }
}

resource "aws_cloudwatch_log_group" "step_ca_backup" {
  name              = "/aws/lambda/${aws_lambda_function.step_ca_backup.function_name}"
  retention_in_days = 7
}

# EventBridge: 매주 일요일 18:00 UTC (한국 월요일 03:00 KST)
resource "aws_cloudwatch_event_rule" "step_ca_backup" {
  name                = "${local.name_prefix}-step-ca-backup-weekly"
  description         = "step-ca 볼륨 주 1회 S3 백업 (설계서 §4.2)"
  schedule_expression = "cron(0 18 ? * SUN *)"
  tags                = { Name = "${local.name_prefix}-step-ca-backup" }
}

resource "aws_cloudwatch_event_target" "step_ca_backup" {
  rule      = aws_cloudwatch_event_rule.step_ca_backup.name
  target_id = "StepCaBackupLambda"
  arn       = aws_lambda_function.step_ca_backup.arn
}

resource "aws_lambda_permission" "step_ca_backup" {
  statement_id  = "AllowEventBridgeInvokeStepCaBackup"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.step_ca_backup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.step_ca_backup.arn
}
