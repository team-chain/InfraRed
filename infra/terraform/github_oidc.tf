# ============================================================
# GitHub Actions OIDC — keyless authentication for CI/CD
# ============================================================
# 목적:
#   GitHub Actions가 long-lived IAM access key 대신 OIDC 기반 임시 자격증명으로
#   AWS 리소스에 접근하도록 함. 키 유출/회전 부담 제거, 감사 추적 향상.
#
# 적용 순서:
#   1) terraform apply  → OIDC provider + IAM role 생성
#   2) .github/workflows/*.yml 의 `aws-actions/configure-aws-credentials` 단계를
#      role-to-assume = output github_actions_role_arn 으로 교체
#   3) workflow 한 번 트리거해서 OIDC 인증 정상 작동 확인
#   4) GitHub Secrets 에서 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY 삭제
# ============================================================

# ── 리포지터리 식별자 (trust policy 제한용) ──────────────────
locals {
  github_org  = "team-chain"
  github_repo = "InfraRed"
}

# ── OIDC identity provider ───────────────────────────────────
# token.actions.githubusercontent.com 에서 발급한 JWT를 AWS STS가 신뢰하도록 등록.
# thumbprint는 GitHub OIDC 인증서의 SHA-1 fingerprint (공식 알려진 값).
# AWS에서 STS 측이 자동 검증하기 시작한 이후로는 thumbprint 정확성 중요도가
# 낮아졌지만, 여전히 필수 인자라서 공식 값을 명시.
resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]

  tags = {
    Name = "${local.name_prefix}-github-actions-oidc"
  }
}

# ── Trust policy: 특정 repo + branch만 assume 허용 ───────────
# subject 패턴: "repo:<org>/<repo>:ref:refs/heads/<branch>"
# main 과 develop 만 허용하여 fork/PR 에서의 unauthorized assume 차단.
data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid     = "GitHubActionsOIDC"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    # audience 검증 — configure-aws-credentials@v4 가 사용하는 기본값
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # subject 제한 — 우리 repo의 main/develop 브랜치 또는 environment 한정
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${local.github_org}/${local.github_repo}:ref:refs/heads/main",
        "repo:${local.github_org}/${local.github_repo}:ref:refs/heads/develop",
        "repo:${local.github_org}/${local.github_repo}:environment:*",
      ]
    }
  }
}

# ── IAM role: GitHub Actions가 assume할 역할 ─────────────────
resource "aws_iam_role" "github_actions_deploy" {
  name               = "${local.name_prefix}-github-actions-deploy"
  description        = "Deploy role assumed by GitHub Actions via OIDC (no long-lived keys)"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json

  # 1 시간 (build + push + deploy 충분)
  max_session_duration = 3600

  tags = {
    Name = "${local.name_prefix}-github-actions-deploy"
  }
}

# ── 권한: ECR push + (필요 시 SSM read) ──────────────────────
# deploy.yml 이 호출하는 AWS API:
#   1) aws-actions/amazon-ecr-login@v2 → ecr:GetAuthorizationToken (wildcard 필수)
#   2) docker/build-push-action → ecr:PutImage 등 push 권한
# EC2 pull은 SSH 안에서 EC2 IAM role 권한으로 수행되므로 GH Actions 권한 불필요.
data "aws_iam_policy_document" "github_actions_permissions" {
  # ECR Authorization Token — wildcard resource 필수 (AWS 제약)
  statement {
    sid     = "ECRAuth"
    effect  = "Allow"
    actions = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # ECR push/pull — 우리 3개 repo로 한정 (least privilege)
  statement {
    sid    = "ECRPushPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [
      aws_ecr_repository.backend.arn,
      aws_ecr_repository.frontend.arn,
      aws_ecr_repository.agent.arn,
    ]
  }
}

resource "aws_iam_role_policy" "github_actions_permissions" {
  name   = "deploy-permissions"
  role   = aws_iam_role.github_actions_deploy.id
  policy = data.aws_iam_policy_document.github_actions_permissions.json
}

# ── Output: workflow에서 쓸 role ARN ─────────────────────────
output "github_actions_role_arn" {
  description = "ARN to use as `role-to-assume` in GitHub Actions workflow (replaces AWS_ACCESS_KEY_ID/SECRET)"
  value       = aws_iam_role.github_actions_deploy.arn
}
