#!/usr/bin/env bash
# =============================================================================
#  InfraRed 라이브 데모 — 타깃(피해자) VM 셋업 스크립트
# -----------------------------------------------------------------------------
#  실행 위치 : 타깃 VM (Ubuntu 22.04 권장)  ※ 격리된 내부망의 본인 소유 VM에서만
#  목적      : 공격자 VM이 실제로 공격할 수 있도록 "취약하지만 통제된" 피해자 환경 구성
#              + InfraRed 백엔드/대시보드/에이전트 기동 + 미끼(허니토큰)·폐기 데이터 배치
#  재실행    : sudo ./target_setup.sh reset   → 데모 후 상태 초기화(스냅샷 대용)
#
#  ⚠️  안전 범위: 본인 소유의 격리(host-only/internal) 네트워크 VM 전용.
#      실서버·공용망·타인 자산에 절대 사용 금지. 모든 변경은 reset으로 되돌릴 수 있음.
# =============================================================================
set -euo pipefail

# ── 설정값 (환경에 맞게 수정) ────────────────────────────────────────────────
VICTIM_USER="deploy"                 # 희생자 계정
VICTIM_PASS="Summer2024"             # 일부러 약한 비밀번호 (워드리스트에 심을 값)
ROOT_PASS="Passw0rd!"                # root 비밀번호 (지속성 단계용)
LOOT_DIR="/home/${VICTIM_USER}/important_docs"   # 랜섬웨어 시연용 폐기 데이터
HONEY_DIR="/home/${VICTIM_USER}/.aws"            # 미끼 자격증명 위치
INFRARED_DIR="${INFRARED_DIR:-/opt/infrared}"    # docker compose 프로젝트 경로
RUN_STACK="${RUN_STACK:-1}"          # 1이면 docker compose & 네이티브 에이전트 기동 시도

C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_0="\033[0m"
say()  { echo -e "${C_G}[+]${C_0} $*"; }
warn() { echo -e "${C_Y}[!]${C_0} $*"; }
err()  { echo -e "${C_R}[x]${C_0} $*" >&2; }

require_root() { [ "$(id -u)" -eq 0 ] || { err "sudo로 실행하세요: sudo $0 $*"; exit 1; }; }

# ── reset: 데모 후 초기화 ────────────────────────────────────────────────────
do_reset() {
  require_root reset
  say "데모 상태 초기화 중..."
  # 공격자가 심은 흔적 제거
  rm -f /root/.ssh/authorized_keys.attacker 2>/dev/null || true
  if [ -f /root/.ssh/authorized_keys ]; then
    grep -v "INFRARED-DEMO-ATTACKER" /root/.ssh/authorized_keys > /root/.ssh/.ak.tmp 2>/dev/null || true
    mv /root/.ssh/.ak.tmp /root/.ssh/authorized_keys 2>/dev/null || true
  fi
  rm -f /etc/cron.d/infrared-demo-backdoor 2>/dev/null || true
  rm -f /tmp/update_helper 2>/dev/null || true
  # 랜섬웨어 시연 폴더 복원 (.locked → 원복, 랜섬노트 삭제)
  if [ -d "$LOOT_DIR" ]; then
    find "$LOOT_DIR" -name '*.locked' | while read -r f; do mv "$f" "${f%.locked}"; done
    rm -f "$LOOT_DIR"/README_DECRYPT.txt 2>/dev/null || true
  fi
  # iptables 차단 룰 제거 (에이전트가 남긴 DROP)
  iptables -F INPUT 2>/dev/null || true
  say "초기화 완료. 다시 데모 가능합니다."
  exit 0
}

[ "${1:-setup}" = "reset" ] && do_reset
require_root

# ── 1. 패키지 ────────────────────────────────────────────────────────────────
say "필수 패키지 설치..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server rsyslog cron iptables sudo >/dev/null

# ── 2. 희생자 계정 + 약한 비밀번호 ───────────────────────────────────────────
say "희생자 계정(${VICTIM_USER}) 구성..."
id "$VICTIM_USER" &>/dev/null || useradd -m -s /bin/bash "$VICTIM_USER"
echo "${VICTIM_USER}:${VICTIM_PASS}" | chpasswd
echo "root:${ROOT_PASS}" | chpasswd
usermod -aG sudo "$VICTIM_USER"

# ── 3. sshd: 데모를 위해 패스워드/루트 로그인 허용 (격리망 전용!) ─────────────
say "sshd 설정 (데모용: 패스워드·root 로그인 허용)..."
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/'        /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 30/'               /etc/ssh/sshd_config  # 브루트포스 허용
systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh

# auth.log 보장 (에이전트가 tail하는 경로)
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog
touch /var/log/auth.log

# ── 4. 미끼 허니토큰 (가짜 AWS 자격증명) ─────────────────────────────────────
say "미끼 자격증명(허니토큰) 배치: ${HONEY_DIR}/credentials"
install -d -m 700 -o "$VICTIM_USER" -g "$VICTIM_USER" "$HONEY_DIR"
# 허니토큰 값은 실행 시점에 무작위 생성한다 (레포에 실제 키 문자열을 남기지 않기 위함 +
# 배포마다 유니크한 미끼). 탐지는 이 파일에 대한 '접근'을 보는 것이라 값은 무관하다.
_HONEY_AK="AKIA$(tr -dc 'A-Z0-9' </dev/urandom | head -c 16)"
_HONEY_SK="$(tr -dc 'A-Za-z0-9+/' </dev/urandom | head -c 40)"
cat > "${HONEY_DIR}/credentials" <<EOF
[default]
# Production deploy key — DO NOT SHARE
aws_access_key_id = ${_HONEY_AK}
aws_secret_access_key = ${_HONEY_SK}
region = ap-northeast-2
EOF
chown "$VICTIM_USER:$VICTIM_USER" "${HONEY_DIR}/credentials"
chmod 600 "${HONEY_DIR}/credentials"

# ── 5. 랜섬웨어 시연용 폐기 데이터 ───────────────────────────────────────────
say "폐기 데이터 폴더 생성: ${LOOT_DIR} (더미 문서 150개)"
install -d -m 755 -o "$VICTIM_USER" -g "$VICTIM_USER" "$LOOT_DIR"
for i in $(seq 1 150); do
  printf 'Quarterly report %03d — confidential dummy content.\n' "$i" \
    > "${LOOT_DIR}/report_${i}.docx"
done
chown -R "$VICTIM_USER:$VICTIM_USER" "$LOOT_DIR"

# ── 6. InfraRed 스택 + 에이전트 기동 (선택) ──────────────────────────────────
if [ "$RUN_STACK" = "1" ]; then
  if [ -f "${INFRARED_DIR}/docker-compose.yml" ]; then
    say "InfraRed 스택 기동 (docker compose up -d)..."
    ( cd "$INFRARED_DIR" && docker compose up -d --build ) \
      || warn "docker compose 기동 실패 — 수동으로 백엔드를 띄우세요."
    warn "에이전트(native)가 /var/log/auth.log + FIM 경로를 감시하도록 기동했는지 확인하세요."
    warn "에이전트 감시 핵심 경로: /root/.ssh/authorized_keys, /etc/cron.d, /etc/passwd, /tmp 실행, /home·/var/www 대량변조"
  else
    warn "INFRARED_DIR(${INFRARED_DIR})에 docker-compose.yml이 없습니다."
    warn "InfraRed 저장소를 그 경로에 두거나 INFRARED_DIR 환경변수로 지정하세요."
  fi
else
  warn "RUN_STACK=0 — 스택/에이전트는 수동 기동하세요."
fi

# ── 요약 ─────────────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo
say "타깃 셋업 완료!"
cat <<EOF

  ┌─────────────────────────────────────────────────────────┐
  │  타깃 IP        : ${IP}
  │  희생자 계정     : ${VICTIM_USER} / ${VICTIM_PASS}
  │  root           : root / ${ROOT_PASS}
  │  미끼 자격증명   : ${HONEY_DIR}/credentials
  │  폐기 데이터     : ${LOOT_DIR} (report_*.docx 150개)
  │  대시보드        : http://${IP}:3000  (admin@infrared.local / infrared123)
  └─────────────────────────────────────────────────────────┘

  다음: 공격자 VM에서  ./attack.sh ${IP}  실행
  데모 후 초기화:       sudo ./target_setup.sh reset
EOF
