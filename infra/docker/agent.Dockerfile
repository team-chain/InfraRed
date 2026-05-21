# ============================================================
# InfraRed Agent Dockerfile  [역할 A]
# ============================================================
# - python:3.11-slim 기반
# - 비루트 유저(infrared)로 실행 → 최소 권한 원칙
# - /var/lib/infrared : offset SQLite 볼륨 마운트 경로
# - /host/var/log     : 호스트 로그 읽기 전용 마운트 경로
# ============================================================
FROM python:3.11-slim

LABEL maintainer="infrared-team" \
      component="agent" \
      role="A"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# ── 시스템 패키지 (sqlite3 런타임 + iptables/docker for responder actions) ──
# iptables           : block_ip / isolate_server 명령 실행
# iproute2           : 네트워크 진단
# docker.io-cli      : container_isolate (docker network disconnect / pause / stop)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libsqlite3-0 \
        curl \
        procps \
        iptables \
        iproute2 \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── 의존성 설치 ───────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# ── 소스 복사 ────────────────────────────────────────────────
COPY . .

# ── 데이터/로그 디렉토리 준비 ───────────────────────────────
# /var/log/infrared : 자동 대응 액션 append-only 로그 (iptables_actions.jsonl 등)
RUN mkdir -p /var/lib/infrared /host/var/log /var/log/infrared

# NOTE: agent는 root로 실행 — iptables / docker / 시스템 파일 제어를 위해 필요.
# Compose에서 cap_add: [NET_ADMIN] + /var/run/docker.sock 마운트도 필요.
# 비루트 격리는 watchdog/responder 별도 분리 후 재도입 검토 (v8.x 이후).

# ── 헬스체크: offset DB 파일 또는 프로세스 존재 여부 ──────────
# (에이전트는 HTTP 포트가 없으므로 프로세스 기반 체크)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f "infrared_agent.main" > /dev/null || exit 1

CMD ["python", "-m", "infrared_agent.main"]
