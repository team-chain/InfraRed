# ============================================================
# EC2 t2.micro — 모든 컨테이너를 단일 인스턴스에서 실행
# ============================================================
# 프리티어: t2.micro 750시간/월 (1년)
#
# 인스턴스에서 실행되는 것 (v3.0):
#   Docker Compose
#   ├── ingestion        (FastAPI :8000)
#   ├── detection-worker (침투 후 행위 탐지 룰 7종 포함)
#   ├── enrichment-worker
#   ├── incident-worker  (공격 체인 시나리오 매처 5종)
#   ├── campaign-worker  (캠페인 단위 알림 집계 — v3 신규)
#   ├── llm-worker
#   ├── cleanup-worker
#   ├── frontend         (:3000)
#   └── redis            (:6379, 컨테이너)
#
# RDS는 별도 관리형 서비스 (프리티어)
# ============================================================

# ── 최신 Amazon Linux 2023 AMI ───────────────────────────────
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── EC2 User Data: Docker 설치 + 앱 배포 ─────────────────────
locals {
  # SSM에서 읽어올 파라미터 경로
  ssm_prefix = "/${local.name_prefix}"

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    exec > >(tee /var/log/infrared-init.log) 2>&1

    echo "=== InfraRed EC2 초기화 시작 ==="

    # ── 시스템 업데이트 ──────────────────────────────────────
    dnf update -y
    dnf install -y docker git aws-cli jq

    # ── Docker 시작 ──────────────────────────────────────────
    systemctl enable docker
    systemctl start docker
    usermod -aG docker ec2-user

    # ── Docker Compose v2 설치 ───────────────────────────────
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

    # ── ECR 로그인 ───────────────────────────────────────────
    AWS_REGION="${var.region}"
    ACCOUNT_ID="${data.aws_caller_identity.current.account_id}"
    ECR_BASE="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

    aws ecr get-login-password --region "$AWS_REGION" \
      | docker login --username AWS --password-stdin "$ECR_BASE"

    # ── SSM에서 환경변수 읽기 ────────────────────────────────
    SSM_PREFIX="${local.ssm_prefix}"

    get_ssm() {
      aws ssm get-parameter --name "$SSM_PREFIX/$1" \
        --with-decryption --query Parameter.Value --output text --region "$AWS_REGION" 2>/dev/null || echo ""
    }

    JWT_SECRET=$(get_ssm "jwt-secret")
    DB_PASSWORD=$(get_ssm "db-password")
    AGENT_TOKEN=$(get_ssm "agent-token")
    DISCORD_WEBHOOK=$(get_ssm "discord-webhook-url")
    SLACK_WEBHOOK=$(get_ssm "slack-webhook-url")
    ABUSEIPDB_KEY=$(get_ssm "abuseipdb-api-key")
    OTX_API_KEY=$(get_ssm "otx-api-key")
    AGENT_CMD_SECRET=$(get_ssm "agent-command-secret")

    # ── .env 파일 생성 ───────────────────────────────────────
    mkdir -p /opt/infrared
    cat > /opt/infrared/.env <<ENVEOF
    ECR_BASE=$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
    ENV=${var.env}
    LOG_LEVEL=INFO
    TZ=Asia/Seoul
    TENANT_ID=${var.tenant_id}
    AGENT_ID=${var.agent_id}
    ASSET_ID=${var.asset_id}

    # JWT
    JWT_SECRET=$JWT_SECRET
    JWT_ALG=HS256
    JWT_ISSUER=${var.jwt_issuer}
    JWT_AUDIENCE=${var.jwt_audience}
    JWT_AGENT_TTL_SECONDS=86400
    JWT_USER_TTL_SECONDS=3600

    # Agent
    AGENT_TOKEN=$AGENT_TOKEN
    BACKEND_URL=http://ingestion:8000/ingest
    HEARTBEAT_URL=http://ingestion:8000/heartbeat
    HEARTBEAT_INTERVAL_SEC=30
    AGENT_OFFSET_DB=/var/lib/infrared/offset.sqlite
    AGENT_AUTH_LOG_PATH=/host/var/log/auth.log
    POLL_INTERVAL_SEC=2

    # Ingestion
    INGEST_HOST=0.0.0.0
    INGEST_PORT=8000
    CORS_ORIGINS=${var.cors_origins}
    INTERNAL_API_BASE_URL=http://ingestion:8000
    PAYLOAD_MAX_BYTES=65536

    # Redis (컨테이너)
    REDIS_URL=redis://:infrared-redis-pw@redis:6379/0
    REDIS_STREAM_MAXLEN=100000
    DEDUP_TTL_SECONDS=3600

    # PostgreSQL (RDS)
    POSTGRES_HOST=${aws_db_instance.main.address}
    POSTGRES_PORT=5432
    POSTGRES_DB=${var.db_name}
    POSTGRES_USER=${var.db_username}
    POSTGRES_PASSWORD=$DB_PASSWORD
    DATABASE_URL=postgresql+asyncpg://${var.db_username}:$DB_PASSWORD@${aws_db_instance.main.address}:5432/${var.db_name}

    # LLM
    LLM_PROVIDER=auto
    BEDROCK_REGION=${var.bedrock_region}
    BEDROCK_MODEL_ID=${var.bedrock_model_id}
    LLM_CACHE_TTL_SECONDS=3600

    # 알림
    DISCORD_WEBHOOK_URL=$DISCORD_WEBHOOK
    SLACK_WEBHOOK_URL=$SLACK_WEBHOOK

    # CTI (v3: OTX 우선, AbuseIPDB fallback, 없으면 mock)
    OTX_API_KEY=$OTX_API_KEY
    ABUSEIPDB_API_KEY=$ABUSEIPDB_KEY
    CTI_PROVIDER=${var.otx_api_key != "" ? "otx" : (var.abuseipdb_api_key != "" ? "abuseipdb" : "mock")}
    CTI_CACHE_TTL_SECONDS=3600

    # v3.0 Response System — TTL 기반 실제 차단
    AGENT_COMMAND_SECRET=$AGENT_CMD_SECRET
    BLOCK_TTL_SECONDS=1800
    BLOCK_EXTEND_TTL_SECONDS=86400
    CONFIDENCE_AUTO_BLOCK_THRESHOLD=0.85
    CONFIDENCE_APPROVAL_THRESHOLD=0.70

    # v3.0 Campaign Aggregation
    CAMPAIGN_WINDOW_SECONDS=600
    CAMPAIGN_MIN_SIGNALS=5
    CAMPAIGN_MIN_TARGETS=2

    # v3.0 Attack Chain Correlation
    SCENARIO_SSH_COMPROMISE_WINDOW=600
    SCENARIO_WEBSHELL_WINDOW=1200
    SCENARIO_PRIV_ESC_WINDOW=300
    SCENARIO_RANSOMWARE_WINDOW=180
    SCENARIO_LATERAL_WINDOW=600

    # S3
    S3_BUCKET=${aws_s3_bucket.logs.bucket}
    S3_REPORTS_BUCKET=${aws_s3_bucket.reports.bucket}
    AWS_REGION=${var.region}

    # Frontend
    VITE_API_BASE_URL=http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000

    # Detection thresholds
    AUTH_BRUTE_FORCE_THRESHOLD=3
    AUTH_BRUTE_FORCE_WINDOW_SECONDS=300
    AUTH_INVALID_USER_THRESHOLD=2
    AUTH_INVALID_USER_WINDOW_SECONDS=300
    AUTH_FAIL_THEN_SUCCESS_WINDOW_SECONDS=600
    AUTH_FAIL_THEN_SUCCESS_THRESHOLD=3
    WEB_ADMIN_SCAN_THRESHOLD=30
    WEB_ADMIN_SCAN_WINDOW_SECONDS=300
    WEB_404_THRESHOLD=50
    WEB_404_WINDOW_SECONDS=300

    # Incident
    INCIDENT_MERGE_WINDOW_MINUTES=120
    INCIDENT_DEDUP_TTL_SECONDS=600
    DLQ_MAX_RETRIES=3
    DLQ_IDLE_SECONDS=60
    LATE_EVENT_THRESHOLD_SECONDS=300
    LATE_EVENT_MAX_SECONDS=86400

    # Fluent Bit
    FLUENTBIT_API_KEY=ir_demo_key_company_a_000000000000
    FLUENTBIT_TENANT_ID=${var.tenant_id}

    # SQS 이벤트 버스 (설계서 2.5절)
    SQS_QUEUE_URL=https://sqs.${var.region}.amazonaws.com/${data.aws_caller_identity.current.account_id}/infrared-events.fifo
    SQS_AI_TASKS_URL=https://sqs.${var.region}.amazonaws.com/${data.aws_caller_identity.current.account_id}/infrared-ai-tasks.fifo
    SQS_DLQ_URL=https://sqs.${var.region}.amazonaws.com/${data.aws_caller_identity.current.account_id}/infrared-events-dlq.fifo

    # step-ca PKI (설계서 2.4절)
    STEP_CA_URL=https://step-ca:9000
    STEP_CA_ROOT=/home/step/certs/root_ca.crt
    ENVEOF

    chmod 600 /opt/infrared/.env

    # ── step-ca 초기화 (최초 1회) ──────────────────────────────
    STEP_CA_VOL="step-ca-data"
    docker volume create $STEP_CA_VOL 2>/dev/null || true

    # Root CA 비밀번호 파일 생성
    STEP_CA_PASS=$(aws ssm get-parameter --name "$SSM_PREFIX/step-ca-password" \
      --with-decryption --query Parameter.Value --output text --region "$AWS_REGION" 2>/dev/null \
      || openssl rand -hex 32)

    # step-ca 초기화 (볼륨이 비어있을 때만 실행)
    docker run --rm \
      -v "$STEP_CA_VOL:/home/step" \
      -e DOCKER_STEPCA_INIT_NAME="InfraRed CA" \
      -e DOCKER_STEPCA_INIT_DNS_NAMES="step-ca,localhost" \
      -e DOCKER_STEPCA_INIT_PROVISIONER_NAME="infrared-provisioner" \
      -e DOCKER_STEPCA_INIT_PASSWORD="$STEP_CA_PASS" \
      -e DOCKER_STEPCA_INIT_ADDRESS=":9000" \
      smallstep/step-ca:latest 2>/dev/null || true

    # ── docker-compose.yml 생성 (프리티어 최적화, 메모리 한도 명시) ─
    # 설계서 2.3절 메모리 배분 기준 (t2.micro 1GB 한도):
    #   redis: 100MB | ingestion: 160MB | detection: 130MB
    #   incident: 110MB | enrichment: 60MB | campaign: 55MB
    #   cleanup: 45MB | frontend: 130MB | step-ca: 80MB | agent: 80MB
    #   합계: ~950MB  (OS + Docker 데몬 ~50MB 포함 ~1000MB)
    # llm-worker: Lambda로 분리 (EC2에서 제외, 메모리 절약)
    cat > /opt/infrared/docker-compose.yml <<'COMPOSEEOF'
    services:
      redis:
        image: redis:7-alpine
        container_name: infrared-redis
        command: >
          redis-server
          --requirepass infrared-redis-pw
          --maxmemory 100mb
          --maxmemory-policy allkeys-lru
          --save 60 1
        mem_limit: 100m
        volumes:
          - redis-data:/data
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "redis-cli", "-a", "infrared-redis-pw", "ping"]
          interval: 10s
          timeout: 3s
          retries: 5

      step-ca:
        image: smallstep/step-ca:latest
        container_name: infrared-step-ca
        mem_limit: 80m
        volumes:
          - step-ca-data:/home/step
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "step", "ca", "health", "--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt"]
          interval: 30s
          timeout: 10s
          retries: 5
          start_period: 10s

      ingestion:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-ingestion
        command: ["sh", "-c", "python -m app.db.migrate && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
        env_file: /opt/infrared/.env
        mem_limit: 160m
        ports:
          - "8000:8000"
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
          interval: 30s
          timeout: 5s
          retries: 3

      detection-worker:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-detection
        command: ["python", "-m", "app.workers.detection.worker"]
        env_file: /opt/infrared/.env
        mem_limit: 130m
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped

      enrichment-worker:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-enrichment
        command: ["python", "-m", "app.workers.enrichment.worker"]
        env_file: /opt/infrared/.env
        mem_limit: 60m
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped

      incident-worker:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-incident
        command: ["python", "-m", "app.workers.correlation.worker"]
        env_file: /opt/infrared/.env
        mem_limit: 110m
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped

      campaign-worker:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-campaign
        command: ["python", "-m", "app.workers.campaign.worker"]
        env_file: /opt/infrared/.env
        mem_limit: 55m
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped

      cleanup-worker:
        image: $${ECR_BASE}/infrared-dev-backend:latest
        container_name: infrared-cleanup
        command: ["python", "-m", "app.workers.cleanup.worker"]
        env_file: /opt/infrared/.env
        mem_limit: 45m
        depends_on:
          redis:
            condition: service_healthy
        restart: unless-stopped

      frontend:
        image: $${ECR_BASE}/infrared-dev-frontend:latest
        container_name: infrared-frontend
        env_file: /opt/infrared/.env
        mem_limit: 130m
        ports:
          - "3000:3000"
        depends_on:
          - ingestion
        restart: unless-stopped

      agent:
        image: $${ECR_BASE}/infrared-dev-agent:latest
        container_name: infrared-agent
        env_file: /opt/infrared/.env
        mem_limit: 80m
        volumes:
          - /var/log:/host/var/log:ro
          - agent-state:/var/lib/infrared
        deploy:
          resources:
            limits:
              cpus: "0.05"
        depends_on:
          - ingestion
        restart: on-failure

    volumes:
      redis-data:
      step-ca-data:
        external: true
        name: step-ca-data
      agent-state:
    COMPOSEEOF

    # ── 이미지 pull & 실행 ───────────────────────────────────
    cd /opt/infrared
    docker compose pull
    docker compose up -d

    # ── systemd 서비스 등록 (재부팅 후 자동 시작) ────────────
    cat > /etc/systemd/system/infrared.service <<'SVCEOF'
    [Unit]
    Description=InfraRed Docker Compose Stack
    After=docker.service network-online.target
    Requires=docker.service

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    WorkingDirectory=/opt/infrared
    ExecStart=/usr/local/lib/docker/cli-plugins/docker-compose up -d
    ExecStop=/usr/local/lib/docker/cli-plugins/docker-compose down
    TimeoutStartSec=300

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    systemctl daemon-reload
    systemctl enable infrared

    echo "=== InfraRed EC2 초기화 완료 ==="
  EOF
}

# ── EC2 인스턴스 ─────────────────────────────────────────────
resource "aws_instance" "main" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.ec2_instance_type
  key_name               = var.ec2_key_name
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
  }

  user_data                   = local.user_data
  user_data_replace_on_change = false

  tags = { Name = "${local.name_prefix}-server" }
}

# ── Elastic IP ───────────────────────────────────────────────
# 프리티어: 연결된 EIP 무료, 미연결 EIP 유료 (인스턴스 중지 시 과금 주의)
resource "aws_eip" "main" {
  instance   = aws_instance.main.id
  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]

  tags = { Name = "${local.name_prefix}-eip" }
}
