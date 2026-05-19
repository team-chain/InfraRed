#!/usr/bin/env bash
# InfraRed mTLS 인증서 생성 스크립트 — v7.0 설계서
#
# 생성 구조:
#   ca.key / ca.crt          — 내부 CA (루트 인증서)
#   server.key / server.crt  — 백엔드 서버 인증서
#   agent-<id>.key / .crt    — 에이전트별 클라이언트 인증서
#
# 사용법:
#   ./generate_mtls_certs.sh [--agent-id agent-001] [--out-dir /etc/infrared/certs]
#
# 요구사항: openssl
#
set -euo pipefail

# ── 파라미터 파싱 ─────────────────────────────────────────────────────────────
AGENT_ID="agent-001"
OUT_DIR="/etc/infrared/certs"
DAYS_CA=3650     # CA 유효기간 10년
DAYS_CERT=730    # 서버/클라이언트 인증서 유효기간 2년
BACKEND_HOSTNAME="ingestion"  # 백엔드 서버 hostname (SAN에 추가)

while [[ $# -gt 0 ]]; do
  case $1 in
    --agent-id)   AGENT_ID="$2";  shift 2 ;;
    --out-dir)    OUT_DIR="$2";   shift 2 ;;
    --hostname)   BACKEND_HOSTNAME="$2"; shift 2 ;;
    --days-ca)    DAYS_CA="$2";   shift 2 ;;
    --days-cert)  DAYS_CERT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "=== InfraRed mTLS 인증서 생성 ==="
echo "  Agent ID  : $AGENT_ID"
echo "  Output Dir: $OUT_DIR"
echo "  Backend   : $BACKEND_HOSTNAME"

# ── 1. CA 키 + 인증서 ─────────────────────────────────────────────────────────
if [[ ! -f ca.key ]]; then
  echo "[1/4] CA 키 + 인증서 생성..."
  openssl genrsa -out ca.key 4096
  openssl req -new -x509 \
    -key ca.key \
    -out ca.crt \
    -days "$DAYS_CA" \
    -subj "/CN=InfraRed Internal CA/O=InfraRed/C=KR" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "  ✓ ca.key + ca.crt 생성 완료"
else
  echo "[1/4] CA 키 + 인증서 이미 존재 — 건너뜀"
fi

# ── 2. 백엔드 서버 인증서 ─────────────────────────────────────────────────────
if [[ ! -f server.key ]]; then
  echo "[2/4] 서버 인증서 생성 (CN=$BACKEND_HOSTNAME)..."
  openssl genrsa -out server.key 2048
  openssl req -new \
    -key server.key \
    -out server.csr \
    -subj "/CN=$BACKEND_HOSTNAME/O=InfraRed/C=KR"

  # SAN (Subject Alternative Name) 설정
  cat > server_ext.cnf << EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $BACKEND_HOSTNAME
DNS.2 = ingestion
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

  openssl x509 -req \
    -in server.csr \
    -CA ca.crt -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days "$DAYS_CERT" \
    -extfile server_ext.cnf \
    -extensions v3_req

  rm -f server.csr server_ext.cnf
  echo "  ✓ server.key + server.crt 생성 완료"
else
  echo "[2/4] 서버 인증서 이미 존재 — 건너뜀"
fi

# ── 3. 에이전트 클라이언트 인증서 ─────────────────────────────────────────────
AGENT_KEY="agent-${AGENT_ID}.key"
AGENT_CRT="agent-${AGENT_ID}.crt"

if [[ ! -f "$AGENT_KEY" ]]; then
  echo "[3/4] 에이전트 클라이언트 인증서 생성 (CN=$AGENT_ID)..."
  openssl genrsa -out "$AGENT_KEY" 2048
  openssl req -new \
    -key "$AGENT_KEY" \
    -out agent.csr \
    -subj "/CN=$AGENT_ID/O=InfraRed Agent/C=KR"

  cat > agent_ext.cnf << EOF
[req]
req_extensions = v3_req
[v3_req]
extendedKeyUsage = clientAuth
EOF

  openssl x509 -req \
    -in agent.csr \
    -CA ca.crt -CAkey ca.key \
    -CAcreateserial \
    -out "$AGENT_CRT" \
    -days "$DAYS_CERT" \
    -extfile agent_ext.cnf \
    -extensions v3_req

  rm -f agent.csr agent_ext.cnf
  echo "  ✓ $AGENT_KEY + $AGENT_CRT 생성 완료"
else
  echo "[3/4] 에이전트 인증서 이미 존재 — 건너뜀"
fi

# ── 4. 편의 심볼릭 링크 (에이전트 기본 경로 참조용) ─────────────────────────
if [[ ! -L agent.key ]]; then
  ln -sf "$AGENT_KEY" agent.key
  ln -sf "$AGENT_CRT" agent.crt
fi

# ── 5. 권한 설정 ─────────────────────────────────────────────────────────────
chmod 600 ./*.key
chmod 644 ./*.crt ca.crt
echo "[4/4] 파일 권한 설정 완료"

# ── 요약 출력 ─────────────────────────────────────────────────────────────────
echo ""
echo "=== 생성된 파일 ==="
ls -la "$OUT_DIR"/*.{key,crt} 2>/dev/null || true
echo ""
echo "=== 에이전트 환경변수 (agent.env에 추가) ==="
echo "MTLS_ENABLED=true"
echo "MTLS_CERT_PATH=$OUT_DIR/$AGENT_CRT"
echo "MTLS_KEY_PATH=$OUT_DIR/$AGENT_KEY"
echo "MTLS_CA_PATH=$OUT_DIR/ca.crt"
echo ""
echo "=== 백엔드 환경변수 (backend.env에 추가) ==="
echo "MTLS_ENABLED=true"
echo "TLS_CERTFILE=$OUT_DIR/server.crt"
echo "TLS_KEYFILE=$OUT_DIR/server.key"
echo "TLS_CA_CERTS=$OUT_DIR/ca.crt"
echo ""
echo "=== Nginx mTLS 설정 참고 ==="
cat << 'NGINX_CONF'
# /etc/nginx/conf.d/infrared-mtls.conf
server {
    listen 443 ssl;
    ssl_certificate     /etc/infrared/certs/server.crt;
    ssl_certificate_key /etc/infrared/certs/server.key;
    ssl_client_certificate /etc/infrared/certs/ca.crt;
    ssl_verify_client on;

    location /ingest {
        proxy_pass http://ingestion:8000;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Client-DN     $ssl_client_s_dn;
    }
}
NGINX_CONF
