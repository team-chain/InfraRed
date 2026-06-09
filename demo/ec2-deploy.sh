#!/usr/bin/env bash
# =============================================================================
#  InfraRed — EC2 데모 복구 스크립트 (terraform apply + 이미지 push 후 실행)
# -----------------------------------------------------------------------------
#  실행 위치 : EC2(Amazon Linux) 안에서  →  bash ec2-deploy.sh
#  전제      : (1) terraform apply 완료  (2) ECR에 backend/frontend/agent push 완료
#              (3) /opt/infrared/.env 존재 (EC2 init이 SSM에서 생성)
#  하는 일   : 자체서명 TLS 생성 → compose/nginx 작성 → 컨테이너 기동
#              → 룰 카탈로그 35개 주입 → admin 계정(chain) 생성 → 프록시 재시작
#  접속      : 직접  http://<EIP>:8000     /  Cloudflare 경유  https://infrared.kr
# =============================================================================
set -euo pipefail

# ── 설정 ─────────────────────────────────────────────────────────────────────
ACCOUNT_ID=431538665162
REGION=ap-northeast-2
ECR="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
TENANT=chain
ADMIN_EMAIL=dkdevelop511@gmail.com
ADMIN_PW=infrared511
BEDROCK_MODEL=us.anthropic.claude-sonnet-4-6
DOMAIN="infrared.kr app.infrared.kr api.infrared.kr"
DIR=/opt/infrared

echo "── [1/9] .env 패치 (테넌트=${TENANT}, Bedrock=${BEDROCK_MODEL}) ──"
sudo sed -i "s/^TENANT_ID=.*/TENANT_ID=${TENANT}/"            ${DIR}/.env
sudo sed -i "s/^LLM_PROVIDER=.*/LLM_PROVIDER=bedrock/"        ${DIR}/.env
sudo sed -i "s|^BEDROCK_MODEL_ID=.*|BEDROCK_MODEL_ID=${BEDROCK_MODEL}|" ${DIR}/.env

echo "── [2/9] 자체서명 TLS 인증서 (Cloudflare Full 모드용, 없을 때만) ──"
sudo mkdir -p ${DIR}/ssl
if [ ! -f ${DIR}/ssl/origin.crt ]; then
  sudo openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout ${DIR}/ssl/origin.key -out ${DIR}/ssl/origin.crt \
    -subj "/CN=infrared.kr" >/dev/null 2>&1
  echo "  생성됨: ${DIR}/ssl/origin.{crt,key}"
else
  echo "  기존 인증서 재사용"
fi

echo "── [3/9] nginx.conf 작성 (8000=http 직접, 443=https Cloudflare) ──"
sudo tee ${DIR}/nginx.conf >/dev/null <<'NGINX'
server {
    listen 8000;
    listen 443 ssl;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/origin.crt;
    ssl_certificate_key /etc/nginx/ssl/origin.key;

    location = / { proxy_pass http://frontend:80; }
    location = /index.html { proxy_pass http://frontend:80; }
    location /assets/ { proxy_pass http://frontend:80; }
    location ~* \.(js|css|map|woff2?|ttf|eot|png|jpe?g|gif|svg|ico)$ { proxy_pass http://frontend:80; }
    location / {
        proxy_pass http://ingestion:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
NGINX

echo "── [4/9] docker-compose.yml 작성 ──"
sudo tee ${DIR}/docker-compose.yml >/dev/null <<YAML
services:
  redis:
    image: redis:7-alpine
    container_name: infrared-redis
    command: redis-server --requirepass infrared-redis-pw --maxmemory 200mb --maxmemory-policy allkeys-lru
    restart: unless-stopped
  ingestion:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-ingestion
    command: ["sh","-c","python -m app.db.migrate && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
    env_file: ${DIR}/.env
    depends_on: [redis]
    restart: unless-stopped
  detection-worker:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-detection
    command: ["python","-m","app.workers.detection.worker"]
    env_file: ${DIR}/.env
    depends_on: [redis, ingestion]
    restart: unless-stopped
  enrichment-worker:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-enrichment
    command: ["python","-m","app.workers.enrichment.worker"]
    env_file: ${DIR}/.env
    depends_on: [redis]
    restart: unless-stopped
  incident-worker:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-incident
    command: ["python","-m","app.workers.correlation.worker"]
    env_file: ${DIR}/.env
    depends_on: [redis]
    restart: unless-stopped
  campaign-worker:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-campaign
    command: ["python","-m","app.workers.campaign.worker"]
    env_file: ${DIR}/.env
    depends_on: [redis]
    restart: unless-stopped
  cleanup-worker:
    image: ${ECR}/infrared-dev-backend:latest
    container_name: infrared-cleanup
    command: ["python","-m","app.workers.cleanup.worker"]
    env_file: ${DIR}/.env
    depends_on: [redis]
    restart: unless-stopped
  frontend:
    image: ${ECR}/infrared-dev-frontend:latest
    container_name: infrared-frontend
    restart: unless-stopped
  proxy:
    image: nginx:1.27-alpine
    container_name: infrared-proxy
    ports:
      - "8000:8000"
      - "443:443"
    volumes:
      - ${DIR}/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ${DIR}/ssl:/etc/nginx/ssl:ro
    depends_on: [frontend, ingestion]
    restart: unless-stopped
  agent:
    image: ${ECR}/infrared-dev-agent:latest
    container_name: infrared-agent
    env_file: ${DIR}/.env
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - /var/log:/host/var/log:ro
      - agent-state:/var/lib/infrared
    depends_on: [ingestion]
    restart: on-failure
volumes:
  agent-state:
YAML

echo "── [5/9] ECR 로그인 ──"
aws ecr get-login-password --region ${REGION} | sudo docker login --username AWS --password-stdin ${ECR}

echo "── [6/9] 컨테이너 기동 (이미지 pull + up) ──"
sudo docker compose -f ${DIR}/docker-compose.yml up -d

echo "── [7/9] ingestion 헬스 대기 (최대 120초) ──"
for i in $(seq 1 40); do
  if curl -fsS http://localhost:8000/healthz >/dev/null 2>&1; then echo "  ingestion OK"; break; fi
  sleep 3
  [ "$i" = "40" ] && echo "  ⚠️ 헬스 타임아웃 — 'sudo docker logs infrared-ingestion' 확인"
done

echo "── [8/9] 탐지 룰 카탈로그 35개 주입 ──"
sudo tee ${DIR}/rules.sql >/dev/null <<'SQL'
INSERT INTO detection_rules (rule_id, name, source, mitre_tactic, mitre_technique, enabled) VALUES
 ('AUTH-001','SSH Brute Force','auth.log','Credential Access','T1110.001',TRUE),
 ('AUTH-002','Root Login Attempt','auth.log','Initial Access','T1078',TRUE),
 ('AUTH-003','Invalid User Enumeration','auth.log','Reconnaissance','T1592',TRUE),
 ('AUTH-004','Failed Then Success','auth.log','Initial Access','T1110.001 -> T1078',TRUE),
 ('AUTH-005','Suspicious Login','auth.log','Initial Access','T1078',TRUE),
 ('AUTH-006','Off Hours Login','auth.log','Initial Access','T1078',TRUE),
 ('AUTH-007','Foreign IP Login','auth.log','Initial Access','T1078',TRUE),
 ('AUTH-006A','Credential Stuffing','auth.log','Credential Access','T1110.004',TRUE),
 ('AUTH-006B','Password Spraying','auth.log','Credential Access','T1110.003',TRUE),
 ('WEB-001','Web Shell Access','nginx','Initial Access','T1505.003',TRUE),
 ('WEB-002','Admin Path Scan','nginx','Reconnaissance','T1595',TRUE),
 ('WEB-003','Automation Tool Access','nginx','Initial Access','T1190',TRUE),
 ('WEB-004','404 Burst','nginx','Reconnaissance','T1595',TRUE),
 ('WEB-005','SQL Injection','nginx','Initial Access','T1190',TRUE),
 ('WEB-006','Path Traversal','nginx','Initial Access','T1190',TRUE),
 ('WEB-007','CVE Probe','nginx','Initial Access','T1190',TRUE),
 ('WEB-HNY-001','Honeypot Access','nginx','Reconnaissance','T1595',TRUE),
 ('NET-001','HTTP Flood','nginx','Impact','T1498',TRUE),
 ('DECEPTION-001','Honeytoken File Access','agent.fim','Discovery','T1083',TRUE),
 ('DECEPTION-002','Honeytoken Account Use','auth.log','Credential Access','T1110',TRUE),
 ('EXEC-001','Tmp Process Execution','agent.exec','Execution','T1059',TRUE),
 ('EXEC-002','Webshell Child Process','agent.exec','Initial Access','T1505.003',TRUE),
 ('EXEC-003','Bulk File Modification','agent.exec','Impact','T1486',TRUE),
 ('FIM-001','Authorized Keys Tamper','agent.fim','Persistence','T1098.004',TRUE),
 ('FIM-002','SSHD Config Tamper','agent.fim','Defense Evasion','T1562.004',TRUE),
 ('FIM-003','Crontab Tamper','agent.fim','Persistence','T1053.003',TRUE),
 ('FIM-004','Passwd Tamper','agent.fim','Persistence','T1136.001',TRUE),
 ('FIM-005','Sudoers Tamper','agent.fim','Privilege Escalation','T1548.003',TRUE),
 ('FIM-005-SVC','Systemd Service Tamper','agent.fim','Persistence','T1543.002',TRUE),
 ('PERSIST-001','Authorized Keys Monitor','agent.fim','Persistence','T1098.004',TRUE),
 ('PERSIST-002','Cron Monitor','agent.fim','Persistence','T1053.003',TRUE),
 ('PERSIST-003','Systemd Service Monitor','agent.fim','Persistence','T1543.002',TRUE),
 ('ESCALATE-001','Sensitive File Monitor','agent.fim','Privilege Escalation','T1548',TRUE),
 ('TAMPER-001','Agent Watchdog','agent','Defense Evasion','T1562.001',TRUE),
 ('TAMPER-002','Log Integrity','agent','Defense Evasion','T1070.002',TRUE)
ON CONFLICT (rule_id) DO NOTHING;
SQL
sudo docker exec -i infrared-ingestion python -c "
import asyncio, asyncpg, os, sys
sql=sys.stdin.read()
async def m():
    c=await asyncpg.connect(os.environ['DATABASE_URL'].replace('+asyncpg',''))
    await c.execute(sql)
    print('  detection_rules:', await c.fetchval('SELECT count(*) FROM detection_rules'))
    await c.close()
asyncio.run(m())
" < ${DIR}/rules.sql

echo "── [9/9] admin 계정 생성(${ADMIN_EMAIL} / tenant=${TENANT}) + 프록시 재시작 ──"
sudo docker exec \
  -e INITIAL_ADMIN_EMAIL=${ADMIN_EMAIL} \
  -e INITIAL_ADMIN_PASSWORD=${ADMIN_PW} \
  -e INITIAL_ADMIN_TENANT_ID=${TENANT} \
  -e INITIAL_ADMIN_TENANT_NAME=Chain \
  infrared-ingestion python -m app.db.migrate 2>&1 | grep -i bootstrap_admin || true
sudo docker restart infrared-proxy >/dev/null

EIP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "<EIP>")
echo ""
echo "✅ 복구 완료!"
echo "   직접 접속    : http://${EIP}:8000"
echo "   Cloudflare   : https://infrared.kr  (DNS 전파 + zone_id 적용 후)"
echo "   로그인       : 조직=${TENANT} / ${ADMIN_EMAIL} / ${ADMIN_PW}"
