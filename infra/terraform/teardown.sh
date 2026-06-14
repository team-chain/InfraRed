#!/usr/bin/env bash
# =============================================================================
#  InfraRed — 인프라 전부 삭제 (teardown)
# -----------------------------------------------------------------------------
#  실행 위치 : infra/terraform/
#  하는 일   : terraform destroy → 잔여 리소스가 0인지 검증 (크레딧 새는 것 방지)
#  사용법    : ./teardown.sh           # 확인 후 destroy
#              ./teardown.sh -y        # 확인 없이 바로 destroy
#
#  ※ s3.tf force_destroy / ecr.tf force_delete 덕분에 버킷·이미지가 있어도
#    destroy가 중간에 멈추지 않고 한 번에 깨끗이 삭제됩니다.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_0="\033[0m"
say(){ echo -e "${C_G}[+]${C_0} $*"; }; warn(){ echo -e "${C_Y}[!]${C_0} $*"; }; err(){ echo -e "${C_R}[x]${C_0} $*" >&2; }

AUTO=""; [ "${1:-}" = "-y" ] && AUTO="-auto-approve"

command -v terraform >/dev/null || { err "terraform 미설치"; exit 1; }
command -v aws >/dev/null        || { err "aws CLI 미설치"; exit 1; }

CALLER=$(aws sts get-caller-identity --output text --query 'Account' 2>/dev/null) || {
  err "AWS 자격증명이 유효하지 않습니다."; exit 1; }
say "현재 계정: ${CALLER}"

# 현재 추적 중인 리소스 수
COUNT=$(terraform state list 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" = "0" ]; then
  say "삭제할 리소스가 없습니다 (state 비어 있음). 이미 깨끗합니다."
  exit 0
fi
say "현재 ${COUNT}개 리소스가 추적 중입니다."

if [ -z "$AUTO" ]; then
  echo; read -rp "$(echo -e "${C_R}정말 전부 삭제할까요? (yes/no): ${C_0}")" ans
  [ "$ans" = "yes" ] || { warn "취소됨."; exit 0; }
fi

say "terraform destroy..."
terraform destroy -input=false ${AUTO:--auto-approve}

# 검증: 잔여 리소스 0 확인
echo
REMAIN=$(terraform state list 2>/dev/null | wc -l | tr -d ' ')
if [ "$REMAIN" = "0" ]; then
  say "✅ 잔여 리소스 0 — 전부 삭제되었습니다. 과금 없음."
else
  err "⚠️  ${REMAIN}개 리소스가 state에 남아 있습니다:"
  terraform state list
  warn "위 항목을 'terraform destroy -target=...' 또는 콘솔에서 수동 확인하세요."
  exit 1
fi
