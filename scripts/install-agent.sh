#!/usr/bin/env bash
# InfraRed Agent 설치 스크립트 (one-liner installer)
#
# 사용법:
#   curl -fsSL https://infrared.kr/install.sh | sudo bash -s -- \
#     --token "<AGENT_TOKEN>" \
#     --tenant "<TENANT_ID>" \
#     --server "https://api.infrared.kr"
#
# 환경변수로 동일 인자 전달 가능:
#   INFRARED_TOKEN, INFRARED_TENANT_ID, INFRARED_SERVER_URL,
#   INFRARED_AGENT_IMAGE, INFRARED_INSTALL_MODE (auto|docker|native),
#   INFRARED_AGENT_REPO (native 모드용 git URL)
#
# 두 가지 설치 모드:
#   docker  → 컨테이너로 실행 (권장, 기본)
#   native  → git clone + venv (Docker 없을 때 폴백)
#
# 멱등(idempotent): 재실행 시 환경/서비스가 안전하게 업데이트됨.
set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────
# Defaults
# ────────────────────────────────────────────────────────────────────────────
AGENT_TOKEN="${INFRARED_TOKEN:-}"
TENANT_ID="${INFRARED_TENANT_ID:-}"
SERVER_URL="${INFRARED_SERVER_URL:-https://api.infrared.kr}"
AGENT_IMAGE="${INFRARED_AGENT_IMAGE:-ghcr.io/infrared-kr/agent:latest}"
INSTALL_MODE="${INFRARED_INSTALL_MODE:-auto}"
AGENT_REPO="${INFRARED_AGENT_REPO:-https://github.com/infrared-kr/infrared.git}"

INSTALL_DIR="/opt/infrared-agent"
SERVICE_NAME="infrared-agent"
ENV_FILE="$INSTALL_DIR/.env"

# ────────────────────────────────────────────────────────────────────────────
# 인자 파싱 (CLI > env var)
# ────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token|-t)        AGENT_TOKEN="$2";  shift 2 ;;
    --token=*)         AGENT_TOKEN="${1#*=}"; shift ;;
    --tenant)          TENANT_ID="$2";    shift 2 ;;
    --tenant=*)        TENANT_ID="${1#*=}";   shift ;;
    --server|--url)    SERVER_URL="$2";   shift 2 ;;
    --server=*|--url=*) SERVER_URL="${1#*=}";  shift ;;
    --image)           AGENT_IMAGE="$2";  shift 2 ;;
    --image=*)         AGENT_IMAGE="${1#*=}"; shift ;;
    --mode)            INSTALL_MODE="$2"; shift 2 ;;
    --mode=*)          INSTALL_MODE="${1#*=}"; shift ;;
    --repo)            AGENT_REPO="$2";   shift 2 ;;
    --repo=*)          AGENT_REPO="${1#*=}";  shift ;;
    -h|--help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "[InfraRed] 알 수 없는 인자: $1" >&2
      exit 1
      ;;
  esac
done

# ────────────────────────────────────────────────────────────────────────────
# 사전 검증
# ────────────────────────────────────────────────────────────────────────────
if [[ -z "$AGENT_TOKEN" ]] || [[ -z "$TENANT_ID" ]]; then
  cat >&2 <<EOF
[InfraRed] 오류: --token 과 --tenant 가 필요합니다.

사용 예:
  curl -fsSL https://infrared.kr/install.sh | sudo bash -s -- \\
    --token "<AGENT_TOKEN>" --tenant "<TENANT_ID>"
EOF
  exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "[InfraRed] 오류: root 권한이 필요합니다. 'sudo' 를 붙여 다시 실행하세요." >&2
  exit 3
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "[InfraRed] 오류: systemd가 필요합니다 (이 스크립트는 systemd 기반 배포판만 지원)." >&2
  exit 4
fi

HOSTNAME_VAL="$(hostname)"

# ────────────────────────────────────────────────────────────────────────────
# OS 감지
# ────────────────────────────────────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}
OS="$(detect_os)"
echo "[InfraRed] OS 감지: $OS"

pkg_install() {
  case "$OS" in
    ubuntu|debian)         apt-get update -qq && apt-get install -y -qq "$@" ;;
    centos|rhel|fedora|amzn|rocky|almalinux)
                            yum install -y -q "$@" ;;
    *)  echo "[InfraRed] 경고: 자동 패키지 설치 미지원 — 수동으로 $* 설치 필요" >&2 ;;
  esac
}

# ────────────────────────────────────────────────────────────────────────────
# 모드 결정
# ────────────────────────────────────────────────────────────────────────────
have_docker() { command -v docker >/dev/null 2>&1; }

if [[ "$INSTALL_MODE" == "auto" ]]; then
  if have_docker; then
    INSTALL_MODE="docker"
  else
    INSTALL_MODE="native"
  fi
fi
echo "[InfraRed] 설치 모드: $INSTALL_MODE"

# ────────────────────────────────────────────────────────────────────────────
# 공통: 환경 파일 작성
# ────────────────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cat > "$ENV_FILE" <<EOF
# Managed by install-agent.sh — do not edit AGENT_TOKEN by hand.
TENANT_ID=$TENANT_ID
AGENT_ID=${HOSTNAME_VAL}-agent
ASSET_ID=$HOSTNAME_VAL
AGENT_TOKEN=$AGENT_TOKEN
BACKEND_URL=$SERVER_URL/ingest
HEARTBEAT_URL=$SERVER_URL/heartbeat
HEARTBEAT_INTERVAL_SEC=30
POLL_INTERVAL_SEC=2
AGENT_OFFSET_DB=/var/lib/infrared/offset.sqlite
AGENT_AUTH_LOG_PATH=/host/var/log/auth.log
EOF
chmod 600 "$ENV_FILE"
mkdir -p /var/lib/infrared
echo "[InfraRed] 환경 파일 작성됨: $ENV_FILE"

# ────────────────────────────────────────────────────────────────────────────
# Docker 모드
# ────────────────────────────────────────────────────────────────────────────
install_docker_mode() {
  if ! have_docker; then
    echo "[InfraRed] Docker 미설치 — 설치 중..."
    pkg_install ca-certificates curl gnupg
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
  fi

  echo "[InfraRed] Agent 이미지 pull: $AGENT_IMAGE"
  docker pull "$AGENT_IMAGE"

  # 기존 컨테이너 정리
  docker rm -f infrared-agent >/dev/null 2>&1 || true

  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=InfraRed Security Agent (Docker)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStartPre=-/usr/bin/docker rm -f infrared-agent
ExecStart=/usr/bin/docker run --rm --name infrared-agent \\
  --env-file $ENV_FILE \\
  -v /var/log:/host/var/log:ro \\
  -v /var/lib/infrared:/var/lib/infrared \\
  --network host \\
  $AGENT_IMAGE
ExecStop=/usr/bin/docker stop infrared-agent

[Install]
WantedBy=multi-user.target
EOF
}

# ────────────────────────────────────────────────────────────────────────────
# Native 모드 (Python venv + git clone)
# ────────────────────────────────────────────────────────────────────────────
install_native_mode() {
  echo "[InfraRed] 의존성 설치 (python3, pip, git, curl)..."
  pkg_install python3 python3-pip python3-venv git curl iptables

  if [[ ! -d "$INSTALL_DIR/src/.git" ]]; then
    echo "[InfraRed] Agent 소스 clone..."
    rm -rf "$INSTALL_DIR/src"
    git clone --depth 1 "$AGENT_REPO" "$INSTALL_DIR/src"
  else
    echo "[InfraRed] Agent 소스 업데이트 (git pull)..."
    git -C "$INSTALL_DIR/src" pull --ff-only || true
  fi

  if [[ ! -x "$INSTALL_DIR/venv/bin/python" ]]; then
    python3 -m venv "$INSTALL_DIR/venv"
  fi
  "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install --quiet \
    httpx pydantic pydantic-settings aiosqlite asyncio-throttle PyJWT

  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=InfraRed Security Agent (Native)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/src/agent
EnvironmentFile=$ENV_FILE
Environment=PYTHONPATH=$INSTALL_DIR/src/agent
ExecStart=$INSTALL_DIR/venv/bin/python -m infrared_agent.main
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  # Native 모드는 /var/log 직접 접근 가능 — host prefix 제거
  sed -i 's|^AGENT_AUTH_LOG_PATH=.*|AGENT_AUTH_LOG_PATH=/var/log/auth.log|' "$ENV_FILE"
}

case "$INSTALL_MODE" in
  docker) install_docker_mode ;;
  native) install_native_mode ;;
  *)
    echo "[InfraRed] 오류: 알 수 없는 INSTALL_MODE: $INSTALL_MODE" >&2
    exit 5
    ;;
esac

# ────────────────────────────────────────────────────────────────────────────
# 서비스 등록 + 시작
# ────────────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 4
if systemctl is-active --quiet "$SERVICE_NAME"; then
  cat <<EOF

✅ InfraRed Agent 설치 완료
   모드      : $INSTALL_MODE
   테넌트    : $TENANT_ID
   서버      : $HOSTNAME_VAL
   백엔드    : $SERVER_URL
   상태      : 실행 중

대시보드에서 이 호스트가 '온라인'으로 표시될 때까지 약 30초 기다려 주세요.
로그 확인:  journalctl -u $SERVICE_NAME -f
EOF
else
  cat >&2 <<EOF
❌ Agent 시작 실패
   로그 확인:  journalctl -u $SERVICE_NAME -n 80 --no-pager
EOF
  exit 6
fi
