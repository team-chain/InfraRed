# ============================================================
# InfraRed 프리티어 배포 스크립트 (PowerShell)
# EC2 + Docker Compose 환경용
# ============================================================
# 사용법:
#   .\scripts\deploy.ps1              # 전체 (빌드 + 푸시 + EC2 재시작)
#   .\scripts\deploy.ps1 -PushOnly   # 이미지 빌드 & ECR 푸시만
#   .\scripts\deploy.ps1 -RestartOnly # EC2 docker compose 재시작만
# ============================================================

param(
    [switch]$PushOnly,
    [switch]$RestartOnly
)

$ErrorActionPreference = "Stop"

# ── 설정 ─────────────────────────────────────────────────────
$ROOT = Split-Path $PSScriptRoot -Parent
$TF_DIR = "$ROOT\infra\terraform"

# Terraform 출력에서 값 읽기
Push-Location $TF_DIR
$AWS_REGION     = "ap-northeast-2"
$ACCOUNT_ID     = (aws sts get-caller-identity --query Account --output text)
$ECR_BASE       = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
$ECR_BACKEND    = (terraform output -raw ecr_backend_uri)
$ECR_FRONTEND   = (terraform output -raw ecr_frontend_uri)
$ECR_AGENT      = (terraform output -raw ecr_agent_uri)
$EC2_IP         = (terraform output -raw ec2_public_ip)
$API_URL        = "http://${EC2_IP}:8000"
Pop-Location

Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  InfraRed 프리티어 배포" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  EC2 IP   : $EC2_IP"
Write-Host "  ECR Base : $ECR_BASE"
Write-Host ""

# ── ECR 빌드 & 푸시 ──────────────────────────────────────────
if (-not $RestartOnly) {
    Write-Host "[1/4] ECR 로그인 중..." -ForegroundColor Yellow
    $ECR_TOKEN = aws ecr get-login-password --region $AWS_REGION
    $ECR_TOKEN | docker login --username AWS --password-stdin $ECR_BASE
    Write-Host "      ECR 로그인 완료" -ForegroundColor Green

    # Git 커밋 해시 (태그용)
    $GIT_SHA = git -C $ROOT rev-parse --short HEAD 2>$null
    if (-not $GIT_SHA) { $GIT_SHA = "latest" }

    # ── Backend ─────────────────────────────────────────────
    Write-Host "[2/4] Backend 이미지 빌드 중..." -ForegroundColor Yellow
    docker build `
        -f "$ROOT\infra\docker\backend.Dockerfile" `
        -t "${ECR_BACKEND}:latest" `
        -t "${ECR_BACKEND}:${GIT_SHA}" `
        "$ROOT\backend"
    docker push "${ECR_BACKEND}:latest"
    docker push "${ECR_BACKEND}:${GIT_SHA}"
    Write-Host "      Backend 푸시 완료" -ForegroundColor Green

    # ── Frontend ────────────────────────────────────────────
    Write-Host "[3/4] Frontend 이미지 빌드 중..." -ForegroundColor Yellow
    docker build `
        -f "$ROOT\infra\docker\frontend.Dockerfile" `
        --build-arg "VITE_API_BASE_URL=$API_URL" `
        -t "${ECR_FRONTEND}:latest" `
        -t "${ECR_FRONTEND}:${GIT_SHA}" `
        "$ROOT\frontend"
    docker push "${ECR_FRONTEND}:latest"
    docker push "${ECR_FRONTEND}:${GIT_SHA}"
    Write-Host "      Frontend 푸시 완료" -ForegroundColor Green

    # ── Agent ────────────────────────────────────────────────
    Write-Host "[4/4] Agent 이미지 빌드 중..." -ForegroundColor Yellow
    docker build `
        -f "$ROOT\infra\docker\agent.Dockerfile" `
        -t "${ECR_AGENT}:latest" `
        -t "${ECR_AGENT}:${GIT_SHA}" `
        "$ROOT\agent"
    docker push "${ECR_AGENT}:latest"
    docker push "${ECR_AGENT}:${GIT_SHA}"
    Write-Host "      Agent 푸시 완료" -ForegroundColor Green
}

if ($PushOnly) {
    Write-Host ""
    Write-Host "이미지 푸시 완료. EC2 재시작은 수동으로 진행하세요:" -ForegroundColor Cyan
    Write-Host "  ssh -i infrared-key.pem ec2-user@$EC2_IP"
    Write-Host "  docker compose -f /opt/infrared/docker-compose.yml pull"
    Write-Host "  docker compose -f /opt/infrared/docker-compose.yml up -d"
    exit 0
}

# ── EC2 SSH로 docker compose 재시작 ──────────────────────────
Write-Host ""
Write-Host "[재시작] EC2 docker compose 업데이트 중..." -ForegroundColor Yellow

$KEY = "$ROOT\infrared-key.pem"
if (-not (Test-Path $KEY)) {
    Write-Host "      키 파일 없음: $KEY" -ForegroundColor Red
    Write-Host "      아래 명령으로 수동 재시작하세요:" -ForegroundColor Yellow
    Write-Host "      ssh -i <키파일경로> ec2-user@$EC2_IP 'cd /opt/infrared && docker compose pull && docker compose up -d'"
    exit 0
}

$SSH_CMD = "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_BASE && cd /opt/infrared && docker compose pull && docker compose up -d && docker compose ps"

ssh -i $KEY -o StrictHostKeyChecking=no "ec2-user@$EC2_IP" $SSH_CMD

Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host "  배포 완료!" -ForegroundColor Green
Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host "  대시보드 : http://$EC2_IP:3000"
Write-Host "  API      : http://$EC2_IP:8000/healthz"
Write-Host ""
Write-Host "로그 확인:"
Write-Host "  ssh -i $KEY ec2-user@$EC2_IP 'docker compose -f /opt/infrared/docker-compose.yml logs -f'"
