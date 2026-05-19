#!/bin/bash
# InfraRed EC2 User Data — 초기 프로비저닝 스크립트
# 설계서_최종.docx 구현 순서 #3

set -euo pipefail
exec > >(tee /var/log/infrared-init.log | logger -t user-data -s 2>/dev/console) 2>&1

ENVIRONMENT="${environment}"
AWS_REGION="${aws_region}"
DOMAIN_NAME="${domain_name}"
S3_LOG_BUCKET="${s3_log_bucket}"
DISCORD_WEBHOOK="${discord_webhook}"

echo "=== InfraRed 초기화 시작: $(date) ==="

# ──────────────────────────────────────────────────────────────
# 1. 시스템 업데이트 및 기본 패키지 설치
# ──────────────────────────────────────────────────────────────
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl wget git unzip jq \
    ca-certificates gnupg lsb-release \
    fail2ban ufw \
    awscli \
    python3-pip python3-venv \
    logrotate

# ──────────────────────────────────────────────────────────────
# 2. Docker 설치
# ──────────────────────────────────────────────────────────────
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable docker
systemctl start docker

# ──────────────────────────────────────────────────────────────
# 3. 방화벽 설정
# ──────────────────────────────────────────────────────────────
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "HTTP"
ufw allow 443/tcp  comment "HTTPS"
ufw allow 8443/tcp comment "Agent TLS"
ufw --force enable

# ──────────────────────────────────────────────────────────────
# 4. fail2ban 설정
# ──────────────────────────────────────────────────────────────
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl enable fail2ban
systemctl start fail2ban

# ──────────────────────────────────────────────────────────────
# 5. SSM Parameter Store에서 시크릿 로드
# ──────────────────────────────────────────────────────────────
mkdir -p /opt/infrared
DB_PASSWORD=$(aws ssm get-parameter \
    --name "/infrared/$ENVIRONMENT/db_password" \
    --with-decryption \
    --region "$AWS_REGION" \
    --query Parameter.Value \
    --output text)

JWT_SECRET=$(aws ssm get-parameter \
    --name "/infrared/$ENVIRONMENT/jwt_secret" \
    --with-decryption \
    --region "$AWS_REGION" \
    --query Parameter.Value \
    --output text)

REDIS_PASSWORD=$(aws ssm get-parameter \
    --name "/infrared/$ENVIRONMENT/redis_password" \
    --with-decryption \
    --region "$AWS_REGION" \
    --query Parameter.Value \
    --output text)

# ──────────────────────────────────────────────────────────────
# 6. .env 파일 생성
# ──────────────────────────────────────────────────────────────
cat > /opt/infrared/.env <<EOF
ENVIRONMENT=$ENVIRONMENT
AWS_REGION=$AWS_REGION
DOMAIN_NAME=$DOMAIN_NAME
S3_LOG_BUCKET=$S3_LOG_BUCKET
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET
REDIS_PASSWORD=$REDIS_PASSWORD
DISCORD_WEBHOOK_URL=$DISCORD_WEBHOOK
DRY_RUN=false
LOG_LEVEL=INFO
IMAGE_TAG=latest
EOF
chmod 600 /opt/infrared/.env

# ──────────────────────────────────────────────────────────────
# 7. InfraRed 소스코드 클론 및 배포
# ──────────────────────────────────────────────────────────────
cd /opt/infrared
if [ ! -d "infrared" ]; then
    git clone https://github.com/your-org/infrared.git infrared
fi
cd infrared

# .env 심볼릭 링크
ln -sf /opt/infrared/.env .env

# Docker 이미지 빌드
docker compose -f deploy/docker-compose.prod.yml build --no-cache

# DB 마이그레이션
docker compose -f deploy/docker-compose.prod.yml run --rm api \
    python -m alembic upgrade head

# 서비스 시작
docker compose -f deploy/docker-compose.prod.yml up -d

# ──────────────────────────────────────────────────────────────
# 8. Certbot SSL 인증서 발급
# ──────────────────────────────────────────────────────────────
docker compose -f deploy/docker-compose.prod.yml exec certbot \
    certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email admin@"$DOMAIN_NAME" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN_NAME" || echo "SSL 발급 실패 — 나중에 수동 실행 필요"

# ──────────────────────────────────────────────────────────────
# 9. CloudWatch 에이전트 설정
# ──────────────────────────────────────────────────────────────
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
    "metrics": {
        "namespace": "InfraRed",
        "metrics_collected": {
            "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 60},
            "disk": {"measurement": ["disk_used_percent"], "resources": ["/"], "metrics_collection_interval": 60},
            "cpu": {"measurement": ["cpu_usage_active"], "metrics_collection_interval": 60}
        }
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {"file_path": "/var/log/infrared-init.log", "log_group_name": "/infrared/init"},
                    {"file_path": "/var/log/nginx/access.log",  "log_group_name": "/infrared/nginx/access"},
                    {"file_path": "/var/log/nginx/error.log",   "log_group_name": "/infrared/nginx/error"}
                ]
            }
        }
    }
}
EOF
systemctl start amazon-cloudwatch-agent
systemctl enable amazon-cloudwatch-agent

# ──────────────────────────────────────────────────────────────
# 10. 로그 로테이션 설정
# ──────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/infrared <<EOF
/var/log/infrared/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF

# ──────────────────────────────────────────────────────────────
# 11. 자동 재시작 크론 (데모 안정성)
# ──────────────────────────────────────────────────────────────
cat > /etc/cron.d/infrared-watchdog <<EOF
*/5 * * * * root cd /opt/infrared/infrared && docker compose -f deploy/docker-compose.prod.yml ps | grep -q "unhealthy" && docker compose -f deploy/docker-compose.prod.yml restart >> /var/log/infrared/watchdog.log 2>&1
EOF

echo "=== InfraRed 초기화 완료: $(date) ==="
