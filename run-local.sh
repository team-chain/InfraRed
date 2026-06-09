#!/usr/bin/env bash
# =============================================================================
#  InfraRed — 로컬 데모 한 방 실행 (AWS 불필요)
# -----------------------------------------------------------------------------
#  하는 일: .env 생성/보정 → JWT 토큰 발급 → 빌드 → 기동 → 헬스체크
#  실행:    ./run-local.sh           # 기동
#           ./run-local.sh down      # 종료(볼륨 유지)
#           ./run-local.sh reset     # 종료 + 볼륨 삭제(완전 초기화)
#  요구:    docker, docker compose, python3
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_0="\033[0m"
say(){ echo -e "${C_G}[+]${C_0} $*"; }; warn(){ echo -e "${C_Y}[!]${C_0} $*"; }; err(){ echo -e "${C_R}[x]${C_0} $*" >&2; }

COMPOSE="docker compose -f docker-compose.dev.yml"

case "${1:-up}" in
  down)  $COMPOSE down; say "종료 완료(볼륨 유지)."; exit 0;;
  reset) $COMPOSE down -v; rm -f .env; say "완전 초기화 완료(볼륨·.env 삭제)."; exit 0;;
esac

command -v docker  >/dev/null || { err "docker 미설치"; exit 1; }
command -v python3 >/dev/null || { err "python3 미설치"; exit 1; }

# ── 1. .env 생성 (없으면 example에서 복사) ───────────────────────────────────
if [ ! -f .env ]; then
  say ".env 생성 (.env.example 기반)"
  cp .env.example .env
fi

# ── 2. 로컬 데모용 값 보정 (멱등) ────────────────────────────────────────────
set_kv() { # set_kv KEY VALUE  — .env에서 해당 키 라인을 교체(없으면 추가)
  local k="$1" v="$2"
  if grep -qE "^${k}=" .env; then
    # 구분자로 | 사용 (값에 / 포함 가능)
    sed -i "s|^${k}=.*|${k}=${v}|" .env
  else
    echo "${k}=${v}" >> .env
  fi
}

say "로컬 데모용 .env 값 보정..."
set_kv ENV local
set_kv JWT_SECRET "infrared-local-dev-secret-please-change-0123456789"
set_kv AGENT_COMMAND_SECRET "infrared-local-dev-cmd-secret-please-change-32c"
set_kv REDIS_URL "redis://:infrared-redis-pw@redis:6379/0"
set_kv DATABASE_URL "postgresql+asyncpg://infrared:infrared-dev-pw@postgres:5432/infrared"
set_kv LLM_PROVIDER "auto"     # 자격증명 없으면 정적 플레이북으로 자동 대체
set_kv CTI_PROVIDER "mock"

# ── 3. JWT 토큰 발급 (.env의 JWT_SECRET 사용) ───────────────────────────────
say "에이전트/워치독 토큰 발급..."
AGENT_TOKEN=$(python3 scripts/generate_jwt.py --role agent 2>/dev/null | tail -1)
WATCHDOG_TOKEN=$(python3 scripts/generate_jwt.py --role watchdog 2>/dev/null | tail -1)
if [ -n "${AGENT_TOKEN}" ]; then set_kv AGENT_TOKEN "${AGENT_TOKEN}"; else warn "AGENT_TOKEN 발급 실패 — scripts/generate_jwt.py 확인 필요"; fi
if [ -n "${WATCHDOG_TOKEN}" ]; then set_kv WATCHDOG_TOKEN "${WATCHDOG_TOKEN}"; fi

# ── 4. 빌드 + 기동 ───────────────────────────────────────────────────────────
say "이미지 빌드 & 컨테이너 기동 (최초 빌드는 수 분 소요)..."
$COMPOSE up --build -d

# ── 5. 헬스체크 대기 ─────────────────────────────────────────────────────────
say "백엔드 헬스체크 대기..."
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8000/healthz >/dev/null 2>&1; then
    say "백엔드 정상!"
    break
  fi
  sleep 3
  [ "$i" = "60" ] && warn "헬스체크 타임아웃 — '$COMPOSE logs ingestion' 로 확인하세요."
done

cat <<EOF

  ┌──────────────────────────────────────────────────────┐
  │  대시보드   : http://localhost:3000
  │  API        : http://localhost:8000   (healthz, debug/replay-events)
  │  로그인     : admin@infrared.local / infrared123
  └──────────────────────────────────────────────────────┘

  로그 보기 :  $COMPOSE logs -f
  종료      :  ./run-local.sh down
  초기화    :  ./run-local.sh reset
EOF
