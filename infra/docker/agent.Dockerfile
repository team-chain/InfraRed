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

# ── 시스템 패키지 (sqlite3 런타임 포함) ──────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libsqlite3-0 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── 비루트 유저 생성 ─────────────────────────────────────────
# UID/GID 1500 : 호스트 auth.log 권한과 충돌하지 않도록 임의 지정
RUN groupadd --gid 1500 infrared \
    && useradd --uid 1500 --gid infrared --no-create-home --shell /sbin/nologin infrared

WORKDIR /app

# ── 의존성 설치 (root 권한 필요) ──────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# ── 소스 복사 ────────────────────────────────────────────────
COPY . .

# ── 데이터 디렉토리 준비 + 소유권 이전 ───────────────────────
RUN mkdir -p /var/lib/infrared /host/var/log \
    && chown -R infrared:infrared /var/lib/infrared /app

# ── 비루트로 전환 ────────────────────────────────────────────
USER infrared

# ── 헬스체크: offset DB 파일 또는 프로세스 존재 여부 ──────────
# (에이전트는 HTTP 포트가 없으므로 프로세스 기반 체크)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f "infrared_agent.main" > /dev/null || exit 1

CMD ["python", "-m", "infrared_agent.main"]
