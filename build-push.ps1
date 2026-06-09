# =============================================================================
#  InfraRed — 이미지 빌드 & ECR 푸시 (Windows / PowerShell)
# -----------------------------------------------------------------------------
#  실행:  C:\InfraRed> .\build-push.ps1
#  전제:  Docker Desktop 실행 중,  aws CLI 로그인됨(infrared-admin 자격증명)
#  하는 일: backend/frontend/agent 3개 이미지를 linux/amd64로 빌드 → ECR push
#  이후:  EC2에서  bash ec2-deploy.sh  실행하면 끝
# =============================================================================
$ErrorActionPreference = "Stop"

$ACCOUNT = "431538665162"
$REGION  = "ap-northeast-2"
$ECR     = "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
$ROOT    = $PSScriptRoot
Set-Location $ROOT

Write-Host "== [0/4] ECR 로그인 ==" -ForegroundColor Cyan
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR
if ($LASTEXITCODE -ne 0) { throw "ECR 로그인 실패 — aws 자격증명 확인" }

Write-Host "== [1/4] backend 빌드/푸시 ==" -ForegroundColor Cyan
docker build --platform linux/amd64 -f infra/docker/backend.Dockerfile -t "$ECR/infrared-dev-backend:latest" backend
if ($LASTEXITCODE -ne 0) { throw "backend 빌드 실패" }
docker push "$ECR/infrared-dev-backend:latest"

Write-Host "== [2/4] frontend 빌드/푸시 (VITE_API_BASE_URL='') ==" -ForegroundColor Cyan
docker build --platform linux/amd64 -f infra/docker/frontend.Dockerfile --build-arg VITE_API_BASE_URL= -t "$ECR/infrared-dev-frontend:latest" frontend
if ($LASTEXITCODE -ne 0) { throw "frontend 빌드 실패" }
docker push "$ECR/infrared-dev-frontend:latest"

Write-Host "== [3/4] agent 빌드/푸시 ==" -ForegroundColor Cyan
docker build --platform linux/amd64 -f infra/docker/agent.Dockerfile -t "$ECR/infrared-dev-agent:latest" agent
if ($LASTEXITCODE -ne 0) { throw "agent 빌드 실패" }
docker push "$ECR/infrared-dev-agent:latest"

Write-Host ""
Write-Host "[OK] 3개 이미지 push 완료" -ForegroundColor Green
Write-Host "   다음: EC2(Xshell)에서  ->  bash ec2-deploy.sh" -ForegroundColor Yellow
