#!/usr/bin/env bash
# InfraRed Agent 설치 스크립트
# 사용법: curl -sSL https://install.infrared.io/agent | bash -s -- --token=TOKEN --tenant=TENANT_ID
set -euo pipefail

AGENT_VERSION="latest"
BACKEND_URL="${INFRARED_BACKEND_URL:-https://api.infrared.io}"
INSTALL_DIR="/opt/infrared-agent"
SERVICE_NAME="infrared-agent"

# ── 인자 파싱 ──────────────────────────────────────────────────────────────── #
AGENT_TOKEN=""
TENANT_ID=""

for arg in "$@"; do
  case $arg in
    --token=*)  AGENT_TOKEN="${arg#*=}" ;;
    --tenant=*) TENANT_ID="${arg#*=}" ;;
    --url=*)    BACKEND_URL="${arg#*=}" ;;
  esac
done

if [[ -z "$AGENT_TOKEN" || -z "$TENANT_ID" ]]; then
  echo "오류: --token 과 --tenant 가 필요합니다."
  echo "사용법: curl -sSL https://install.infrared.io/agent | bash -s -- --token=TOKEN --tenant=TENANT_ID"
  exit 1
fi

# ── OS 감지 ───────────────────────────────────────────────────────────────── #
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "$ID"
  elif [ -f /etc/debian_version ]; then
    echo "debian"
  elif [ -f /etc/redhat-release ]; then
    echo "rhel"
  else
    echo "unknown"
  fi
}

OS=$(detect_os)
echo "[InfraRed] OS 감지: $OS"

# ── 의존성 설치 ───────────────────────────────────────────────────────────── #
install_deps() {
  case "$OS" in
    ubuntu|debian)
      apt-get update -qq
      apt-get install -y -qq python3 python3-pip python3-venv curl iptables
      ;;
    centos|rhel|fedora|amzn)
      yum install -y -q python3 python3-pip curl iptables
      ;;
    *)
      echo "[InfraRed] 경고: 지원하지 않는 OS입니다. 의존성을 수동으로 설치하세요."
      ;;
  esac
}

echo "[InfraRed] 의존성 설치 중..."
install_deps

# ── Agent 설치 ────────────────────────────────────────────────────────────── #
echo "[InfraRed] Agent 설치 중... ($INSTALL_DIR)"
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet infrared-agent=="$AGENT_VERSION" 2>/dev/null || \
  "$INSTALL_DIR/venv/bin/pip" install --quiet \
    httpx pydantic pydantic-settings aiosqlite 2>/dev/null

# ── 환경 설정 파일 ─────────────────────────────────────────────────────────── #
cat > "$INSTALL_DIR/.env" <<EOF
AGENT_TOKEN=$AGENT_TOKEN
TENANT_ID=$TENANT_ID
BACKEND_URL=$BACKEND_URL
AGENT_ID=$(hostname)-agent
ASSET_ID=$(hostname)
EOF
chmod 600 "$INSTALL_DIR/.env"

# ── systemd 서비스 등록 ───────────────────────────────────────────────────── #
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=InfraRed Security Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/python -m infrared_agent.main
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# ── 설치 확인 ─────────────────────────────────────────────────────────────── #
sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
  echo ""
  echo "✅ InfraRed Agent 설치 완료"
  echo "   테넌트: $TENANT_ID"
  echo "   서버:   $(hostname)"
  echo "   상태:   실행 중"
  echo ""
  echo "대시보드에서 이 서버가 '온라인'으로 표시될 때까지 약 30초 기다려 주세요."
else
  echo "❌ Agent 시작 실패. 로그 확인: journalctl -u $SERVICE_NAME -n 50"
  exit 1
fi
