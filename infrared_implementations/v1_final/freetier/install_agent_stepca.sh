#!/usr/bin/env bash
# ============================================================
# InfraRed Agent 설치 스크립트 — step-ca PKI 환경
# 프리티어 설계서 v1.0 §4.3 에이전트 배포
# ============================================================
# 원본 설계와의 차이:
#   - AWS ACM (유료) 대신 step-ca (오픈소스)로 Root CA 대체
#   - Root CA 인증서 번들만 변경 (infrared-ca.crt 경로 교체)
#   - STEP_CA_URL, STEP_CA_FINGERPRINT 환경변수 추가
# ============================================================
set -euo pipefail

SCRIPT_VERSION="1.0.0-freetier"
INFRARED_VERSION="${INFRARED_VERSION:-latest}"
AGENT_INSTALL_DIR="/opt/infrared-agent"
CERT_DIR="/etc/infrared/certs"
SYSTEMD_SERVICE="infrared-agent"

# step-ca 연결 정보 (환경변수 또는 인자로 전달)
STEP_CA_URL="${STEP_CA_URL:-}"                   # 예: https://ca.your-domain.internal:8443
STEP_CA_FINGERPRINT="${STEP_CA_FINGERPRINT:-}"   # step certificate fingerprint <root-ca.crt>
INFRARED_SERVER_URL="${INFRARED_SERVER_URL:-}"    # 예: https://infrared.your-domain.com
AGENT_TOKEN="${AGENT_TOKEN:-}"                   # 백엔드에서 발급한 등록 토큰
TENANT_ID="${TENANT_ID:-}"

# 색상
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── 사전 검증 ──────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "이 스크립트는 root 권한으로 실행해야 합니다."
        echo "  sudo bash $0"
        exit 1
    fi
}

check_requirements() {
    local missing=()
    for cmd in curl jq python3 systemctl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "필수 도구 누락: ${missing[*]}"
        echo "  apt-get install -y ${missing[*]}"
        exit 1
    fi

    if [[ -z "$STEP_CA_URL" || -z "$STEP_CA_FINGERPRINT" ]]; then
        log_error "step-ca 연결 정보가 필요합니다."
        echo ""
        echo "환경변수 설정 방법:"
        echo "  export STEP_CA_URL=https://ca.your-domain.internal:8443"
        echo "  export STEP_CA_FINGERPRINT=\$(step certificate fingerprint /path/to/root-ca.crt)"
        echo "  export INFRARED_SERVER_URL=https://infrared.your-domain.com"
        echo "  export AGENT_TOKEN=<백엔드에서 발급된 토큰>"
        echo "  export TENANT_ID=<테넌트 UUID>"
        exit 1
    fi
}

# ── step CLI 설치 ──────────────────────────────────────────
install_step_cli() {
    if command -v step &>/dev/null; then
        log_info "step CLI 이미 설치됨: $(step version 2>&1 | head -1)"
        return 0
    fi

    log_info "step CLI 설치 중..."
    local OS_ARCH
    OS_ARCH=$(uname -m)
    local STEP_VERSION="0.25.2"

    if [[ "$OS_ARCH" == "x86_64" ]]; then
        local DEB_URL="https://dl.smallstep.com/gh-release/cli/gh-release-header/v${STEP_VERSION}/step-cli_${STEP_VERSION}_amd64.deb"
    elif [[ "$OS_ARCH" == "aarch64" ]]; then
        local DEB_URL="https://dl.smallstep.com/gh-release/cli/gh-release-header/v${STEP_VERSION}/step-cli_${STEP_VERSION}_arm64.deb"
    else
        log_error "지원하지 않는 아키텍처: $OS_ARCH"
        exit 1
    fi

    local TMP_DEB="/tmp/step-cli.deb"
    curl -fsSL "$DEB_URL" -o "$TMP_DEB"
    dpkg -i "$TMP_DEB" || apt-get install -f -y
    rm -f "$TMP_DEB"
    log_info "step CLI 설치 완료: $(step version 2>&1 | head -1)"
}

# ── Root CA 인증서 번들 가져오기 ───────────────────────────
fetch_root_ca() {
    log_info "step-ca Root CA 인증서 다운로드 중..."
    mkdir -p "$CERT_DIR"

    # step-ca에서 Root CA 인증서 다운로드 (--fingerprint 검증)
    step ca root \
        --ca-url "$STEP_CA_URL" \
        --fingerprint "$STEP_CA_FINGERPRINT" \
        "$CERT_DIR/infrared-ca.crt"

    # 시스템 CA 번들에 추가
    if [[ -d /usr/local/share/ca-certificates ]]; then
        cp "$CERT_DIR/infrared-ca.crt" "/usr/local/share/ca-certificates/infrared-ca.crt"
        update-ca-certificates
        log_info "Root CA 인증서를 시스템 번들에 추가했습니다"
    fi
}

# ── 에이전트 인증서 발급 ────────────────────────────────────
issue_agent_cert() {
    local HOSTNAME
    HOSTNAME=$(hostname -f)
    local AGENT_ID
    AGENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

    log_info "에이전트 인증서 발급 중 (step-ca JWK provisioner)..."

    # 1. 백엔드 API에서 OTP 획득 (에이전트 등록 토큰 → 인증서 OTP)
    local OTP_RESPONSE
    OTP_RESPONSE=$(curl -fsSL \
        -X POST "${INFRARED_SERVER_URL}/api/v1/agents/certificate-otp" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -d "{\"hostname\": \"$HOSTNAME\", \"tenant_id\": \"$TENANT_ID\"}"
    )
    local OTP
    OTP=$(echo "$OTP_RESPONSE" | jq -r '.otp // empty')
    AGENT_ID=$(echo "$OTP_RESPONSE" | jq -r '.agent_id // empty')

    if [[ -z "$OTP" ]]; then
        log_error "OTP 발급 실패: $OTP_RESPONSE"
        exit 1
    fi

    # 2. step-ca에서 클라이언트 인증서 발급 (OTP provisioner 사용)
    step ca certificate \
        "infrared-agent-${AGENT_ID}" \
        "$CERT_DIR/agent.crt" \
        "$CERT_DIR/agent.key" \
        --ca-url "$STEP_CA_URL" \
        --root "$CERT_DIR/infrared-ca.crt" \
        --token "$OTP" \
        --not-after 2160h \
        --san "$HOSTNAME" \
        --san "infrared-agent.local"

    chmod 600 "$CERT_DIR/agent.key"
    chmod 644 "$CERT_DIR/agent.crt"

    echo "$AGENT_ID" > "$CERT_DIR/agent_id"
    log_info "에이전트 인증서 발급 완료 (Agent ID: $AGENT_ID)"
}

# ── 에이전트 설치 ──────────────────────────────────────────
install_agent() {
    log_info "InfraRed 에이전트 설치 중..."
    mkdir -p "$AGENT_INSTALL_DIR"

    # Python 가상환경 생성
    python3 -m venv "$AGENT_INSTALL_DIR/venv"
    "$AGENT_INSTALL_DIR/venv/bin/pip" install --upgrade pip -q

    # 에이전트 패키지 설치 (PyPI 또는 로컬)
    if [[ -f "/tmp/infrared-agent.tar.gz" ]]; then
        "$AGENT_INSTALL_DIR/venv/bin/pip" install "/tmp/infrared-agent.tar.gz" -q
    else
        "$AGENT_INSTALL_DIR/venv/bin/pip" install "infrared-agent==${INFRARED_VERSION}" -q 2>/dev/null || {
            log_warn "PyPI 설치 실패 — 소스 복사 방식으로 진행"
            # 소스가 있으면 직접 복사
            if [[ -d "/tmp/infrared_agent_src" ]]; then
                cp -r /tmp/infrared_agent_src/* "$AGENT_INSTALL_DIR/"
                "$AGENT_INSTALL_DIR/venv/bin/pip" install -r "$AGENT_INSTALL_DIR/requirements.txt" -q
            fi
        }
    fi
}

# ── 설정 파일 생성 ─────────────────────────────────────────
write_config() {
    local AGENT_ID
    AGENT_ID=$(cat "$CERT_DIR/agent_id" 2>/dev/null || echo "unknown")

    cat > "$AGENT_INSTALL_DIR/config.yaml" << CONFIG
# InfraRed Agent 설정 — step-ca PKI 환경
server_url: "${INFRARED_SERVER_URL}"
tenant_id: "${TENANT_ID}"
agent_id: "${AGENT_ID}"

# TLS 인증 (step-ca 발급 인증서)
tls:
  ca_cert: "${CERT_DIR}/infrared-ca.crt"
  client_cert: "${CERT_DIR}/agent.crt"
  client_key: "${CERT_DIR}/agent.key"

# 인증서 자동 갱신 (만료 24시간 전)
cert_renewal:
  enabled: true
  step_ca_url: "${STEP_CA_URL}"
  step_ca_fingerprint: "${STEP_CA_FINGERPRINT}"
  renewal_threshold_hours: 24

# 수집 설정
collection:
  log_tail_paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log
  buffer_db: "${AGENT_INSTALL_DIR}/buffer.db"
  batch_size: 100
  send_interval_sec: 5

# 민감정보 마스킹
masking:
  enabled: true
  patterns:
    - "password"
    - "secret"
    - "token"
    - "api_key"
CONFIG
    log_info "설정 파일 생성 완료: $AGENT_INSTALL_DIR/config.yaml"
}

# ── systemd 서비스 등록 ────────────────────────────────────
install_systemd_service() {
    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}.service" << SERVICE
[Unit]
Description=InfraRed Security Agent (step-ca PKI)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=infrared
Group=infrared
WorkingDirectory=${AGENT_INSTALL_DIR}
ExecStart=${AGENT_INSTALL_DIR}/venv/bin/python -m infrared_agent.main \\
    --config ${AGENT_INSTALL_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=infrared-agent

# 보안 강화
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${AGENT_INSTALL_DIR} /run/infrared
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
SERVICE

    # 전용 시스템 사용자 생성
    if ! id -u infrared &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin infrared
    fi

    # 디렉토리 권한 설정
    chown -R infrared:infrared "$AGENT_INSTALL_DIR" "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    chmod 750 "$AGENT_INSTALL_DIR"

    # 로그 디렉토리 접근 (auth.log 읽기)
    usermod -aG adm infrared 2>/dev/null || true
    usermod -aG systemd-journal infrared 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable "$SYSTEMD_SERVICE"
    systemctl start "$SYSTEMD_SERVICE"
    log_info "systemd 서비스 등록 및 시작 완료"
}

# ── 인증서 갱신 크론 설정 ─────────────────────────────────
setup_cert_renewal() {
    cat > "/etc/cron.d/infrared-cert-renewal" << CRON
# InfraRed 에이전트 인증서 자동 갱신 (매일 새벽 2시)
0 2 * * * root ${AGENT_INSTALL_DIR}/venv/bin/python -m infrared_agent.cert_renewal \
    --config ${AGENT_INSTALL_DIR}/config.yaml >> /var/log/infrared-cert-renewal.log 2>&1
CRON
    log_info "인증서 자동 갱신 크론 등록 완료"
}

# ── 설치 검증 ─────────────────────────────────────────────
verify_installation() {
    log_info "설치 검증 중..."
    local AGENT_ID
    AGENT_ID=$(cat "$CERT_DIR/agent_id" 2>/dev/null || echo "unknown")

    sleep 3  # 서비스 시작 대기

    # 서비스 상태 확인
    if systemctl is-active "$SYSTEMD_SERVICE" &>/dev/null; then
        log_info "✅ 서비스 실행 중"
    else
        log_warn "⚠️  서비스 시작 실패 — journalctl -u ${SYSTEMD_SERVICE} 확인"
    fi

    # 백엔드 연결 테스트
    local HEALTH_RESP
    HEALTH_RESP=$(curl -fsSL \
        --cacert "$CERT_DIR/infrared-ca.crt" \
        --cert "$CERT_DIR/agent.crt" \
        --key "$CERT_DIR/agent.key" \
        "${INFRARED_SERVER_URL}/health" 2>/dev/null || echo "connection_failed")

    if echo "$HEALTH_RESP" | grep -q "ok\|healthy"; then
        log_info "✅ 백엔드 연결 성공"
    else
        log_warn "⚠️  백엔드 연결 실패 (서버 URL/방화벽 확인)"
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  InfraRed Agent 설치 완료"
    echo "  버전: $SCRIPT_VERSION"
    echo "  에이전트 ID: $AGENT_ID"
    echo "  인증 방식: step-ca mTLS"
    echo "  CA URL: $STEP_CA_URL"
    echo ""
    echo "  로그 확인:"
    echo "    journalctl -u $SYSTEMD_SERVICE -f"
    echo ""
    echo "  인증서 만료 확인:"
    echo "    step certificate inspect $CERT_DIR/agent.crt"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── 제거 ──────────────────────────────────────────────────
uninstall() {
    log_warn "InfraRed 에이전트를 제거합니다..."
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null || true
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}.service"
    rm -f "/etc/cron.d/infrared-cert-renewal"
    rm -rf "$AGENT_INSTALL_DIR" "$CERT_DIR"
    systemctl daemon-reload
    log_info "제거 완료"
}

# ── 메인 ──────────────────────────────────────────────────
main() {
    if [[ "${1:-}" == "uninstall" ]]; then
        uninstall
        exit 0
    fi

    echo "InfraRed Agent Installer v${SCRIPT_VERSION} (step-ca PKI 환경)"
    echo ""

    check_root
    check_requirements
    install_step_cli
    fetch_root_ca
    issue_agent_cert
    install_agent
    write_config
    install_systemd_service
    setup_cert_renewal
    verify_installation
}

main "$@"
