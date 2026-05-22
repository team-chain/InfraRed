#!/usr/bin/env bash
# InfraRed Agent 설치 스크립트 (one-liner installer)
#
# 사용법:
#   curl -fsSL https://api.infrared.kr/install-agent.sh | sudo bash -s -- \
#     --token "<AGENT_TOKEN>" \
#     --tenant "<TENANT_ID>" \
#     --server "https://api.infrared.kr"
#
# 환경변수로 동일 인자 전달 가능:
#   INFRARED_TOKEN, INFRARED_TENANT_ID, INFRARED_SERVER_URL,
#   INFRARED_AGENT_IMAGE, INFRARED_INSTALL_MODE (auto|docker|native)
#
# 두 가지 설치 모드:
#   docker  → 컨테이너로 실행 (이미지 publish 후 활성화 예정)
#   native  → 백엔드에서 agent tarball 다운로드 + Python venv 실행
#
# Agent 소스: ${SERVER_URL}/agent-source.tar.gz 에서 다운로드.
# GitHub 의존성 없음 — 우리 백엔드 도메인 하나만 접근 가능하면 됨.
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
# Docker image가 아직 public publish 전 — auto 모드는 우선 native로 폴백.
INSTALL_MODE="${INFRARED_INSTALL_MODE:-native}"
# Agent 소스 tarball URL (백엔드가 직접 서빙). 환경 변수로 override 가능 — 폐쇄망 미러 등.
AGENT_TARBALL_URL="${INFRARED_AGENT_TARBALL_URL:-${SERVER_URL}/agent-source.tar.gz}"

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
    --tarball)         AGENT_TARBALL_URL="$2"; shift 2 ;;
    --tarball=*)       AGENT_TARBALL_URL="${1#*=}"; shift ;;
    --repo|--repo=*)
      # 구버전 호환 — git 모드는 더 이상 지원하지 않음 (silent ignore)
      [[ "$1" == --repo ]] && shift 2 || shift ;;
    -h|--help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
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
  # Docker 이미지가 public publish 되면 docker 우선 — 현재는 native로 폴백.
  if [[ "${INFRARED_ALLOW_DOCKER_AUTO:-0}" == "1" ]] && have_docker; then
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
  echo "[InfraRed] 의존성 설치 (python3, pip, curl, tar)..."
  pkg_install python3 python3-pip python3-venv curl tar iptables

  echo "[InfraRed] Agent 소스 다운로드: $AGENT_TARBALL_URL"
  rm -rf "$INSTALL_DIR/src"
  mkdir -p "$INSTALL_DIR/src"

  # 스트리밍 다운로드 + 압축 해제. tarball 안에 agent/ 디렉토리가 있다고 가정.
  if ! curl -fsSL "$AGENT_TARBALL_URL" | tar -xz -C "$INSTALL_DIR/src"; then
    echo "[InfraRed] 오류: agent tarball 다운로드/해제 실패" >&2
    echo "         URL: $AGENT_TARBALL_URL" >&2
    echo "         백엔드가 도달 가능한지 확인:  curl -I $AGENT_TARBALL_URL" >&2
    exit 7
  fi

  if [[ ! -d "$INSTALL_DIR/src/agent" ]]; then
    echo "[InfraRed] 오류: tarball에 agent/ 디렉토리가 없습니다." >&2
    exit 8
  fi

  if [[ ! -x "$INSTALL_DIR/venv/bin/python" ]]; then
    python3 -m venv "$INSTALL_DIR/venv"
  fi
  "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip

  # requirements.txt가 있으면 우선 사용, 없으면 최소 의존성만 설치.
  if [[ -f "$INSTALL_DIR/src/agent/requirements.txt" ]]; then
    "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/src/agent/requirements.txt"
  else
    "$INSTALL_DIR/venv/bin/pip" install --quiet \
      httpx pydantic pydantic-settings aiosqlite asyncio-throttle PyJWT
  fi

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

c