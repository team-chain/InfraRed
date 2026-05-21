# ============================================================
# IAM — EC2 인스턴스 역할
# ============================================================
# EC2가 필요한 권한:
#   ECR       : Docker 이미지 pull
#   SSM       : 파라미터 스토어에서 시크릿 읽기
#   S3        : 로그 업로드 / 리포트 저장
#   Bedrock   : LLM 호출
#   CloudWatch: 로그 전송
# ============================================================

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  name               = "${local.name_prefix}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  description        = "InfraRed EC2 role (ECR + SSM + S3 + Bedrock + CloudWatch)"
}

# ── ECR: 이미지 pull ─────────────────────────────────────────
resource "aws_iam_role_policy" "ec2_ecr" {
  name = "ecr-pull"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage",
          "ecr:DescribeRepositories",
          "ecr:ListImages"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── SSM Parameter Store: 시크릿 읽기 ─────────────────────────
resource "aws_iam_role_policy" "ec2_ssm" {
  name = "ssm-read"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.name_prefix}/*"
      }
    ]
  })
}

# ── S3: 로그 업로드 + 리포트 저장 ────────────────────────────
resource "aws_iam_role_policy" "ec2_s3" {
  name = "s3-access"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*",
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*"
        ]
      }
    ]
  })
}

# ── Bedrock: LLM 호출 ────────────────────────────────────────
resource "aws_iam_role_policy" "ec2_bedrock" {
  name = "bedrock-invoke"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = "arn:aws:bedrock:*::foundation-model/*"
      }
    ]
  })
}

# ── CloudWatch: 로그 전송 ─────────────────────────────────────
resource "aws_iam_role_policy" "ec2_cloudwatch" {
  name = "cloudwatch-logs"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/infrared/*"
      }
    ]
  })
}

# ── SQS: 이벤트 발행 + 수신 ──────────────────────────────────
# (sqs.tf에서 분리하여 여기서도 관리 일관성 유지)
# sqs.tf의 ec2_sqs와 중복 방지를 위해 sqs.tf 참조

# ── v8.0 Honey Access Key 관리 권한 (설계서 §6) ─────────────
# AWSHoneyKeyManager가 boto3로 직접 IAM User / Access Key를 생성하므로
# EC2 Role에 해당 권한이 있어야 함.
# 탐지: DECEPTION-003 (CloudTrail 폴링으로 Honey Key 외부 사용 감지)
resource "aws_iam_role_policy" "ec2_honey_key" {
  name = "honey-key-management"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # IAM Honey User 생성/삭제 + Access Key 발급/회수
      {
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:ListUserPolicies",
          "iam:GetUser",
          "iam:ListAccessKeys",
          "iam:TagUser",
        ]
        # honey IAM User 이름 접두사로 범위 제한 (최소 권한 원칙)
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/infrared-honey-*"
        ]
      },
      # CloudTrail LookupEvents — Honey Key 외부 사용 탐지
      # (기본 이벤트 히스토리 90일 조회, 별도 Trail 불필요)
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${local.name_prefix}-ec2-profile"
  role = aws_iam_role.ec2.name
}
