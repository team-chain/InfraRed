#!/usr/bin/env bash
# =============================================================================
#  InfraRed — 인프라 띄우기 (standup)
# -----------------------------------------------------------------------------
#  실행 위치 : infra/terraform/
#  하는 일   : 자격증명 확인 → (계정 바뀌었으면 경고) → init → plan → apply
#  사용법    : ./standup.sh            # plan 보여주고 확인 후 apply
#              ./standup.sh -y         # 확인 없이 바로 apply (-auto-approve)
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_0="\033[0m"
say(){ echo -e "${C_G}[+]${C_0} $*"; }; warn(){ echo -e "${C_Y}[!]${C_0} $*"; }; err(){ echo -e "${C_R}[x]${C_0} $*" >&2; }

AUTO=""; [ "${1:-}" = "-y" ] && AUTO="-auto-approve"

# 0) 도구·자격증명 확인
command -v terraform >/dev/null || { err "terraform 미설치"; exit 1; }
command -v aws >/dev/null        || { err "aws CLI 미설치"; exit 1; }

say "현재 AWS 자격증명 확인..."
CALLER=$(aws sts get-caller-identity --output text --query 'Account' 2>/dev/null) || {
  err "AWS 자격증명이 유효하지 않습니다. 'aws configure'로 새 계정 키를 등록하세요."; exit 1; }
say "현재 계정: ${CALLER}"

# 1) state가 다른 계정 것이면 경고 (계정 전환 직후 1회)
if [ -f terraform.tfstate ]; then
  STATE_ACCT=$(grep -oE '[0-9]{12}' terraform.tfstate | head -1 || true)
  if [ -n "${STATE_ACCT:-}" ] && [ "$STATE_ACCT" != "$CALLER" ]; then
    err "기존 state는 다른 계정(${STATE_ACCT}) 것입니다. 현재 계정(${CALLER})과 불일치."
    warn "계정을 새로 바꾼 경우, 빈 state로 시작해야 합니다:"
    warn "  mv terraform.tfstate terraform.tfstate.OLD-${STATE_ACCT}"
    warn "  mv terraform.tfstate.backup terraform.tfstate.backup.OLD 2>/dev/null || true"
    warn "그 후 이 스크립트를 다시 실행하세요."
    exit 1
  fi
fi

# 2) tfvars 존재 확인
[ -f terraform.tfvars ] || { err "terraform.tfvars 없음. terraform.tfvars.example을 복사해 채우세요."; exit 1; }

# 3) init → plan → apply
say "terraform init..."
terraform init -input=false >/dev/null

say "terraform plan..."
terraform plan -input=false -out=tfplan

if [ -z "$AUTO" ]; then
  echo; read -rp "$(echo -e "${C_Y}위 plan대로 인프라를 생성할까요? (yes/no): ${C_0}")" ans
  [ "$ans" = "yes" ] || { warn "취소됨."; rm -f tfplan; exit 0; }
fi

say "terraform apply..."
terraform apply -input=false tfplan
rm -f tfplan

echo
say "배포 완료. 주요 출력:"
terraform output 2>/dev/null || true
warn "데모/작업이 끝나면 비용 방지를 위해  ./teardown.sh  로 전부 내리세요."
