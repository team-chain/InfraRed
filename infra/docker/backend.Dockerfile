FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# ── 시스템 패키지 ──────────────────────────────────────────────────────────────
# WeasyPrint: Cairo, Pango (PDF 렌더링 — 설계서 §4-D)
# GeoIP2: libmaxminddb
# ldap3 requires openssl, libsasl2
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
        libmaxminddb0 \
        libssl-dev \
        libsasl2-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python 패키지 ─────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

# Non-root user for security (설계서 §2 보안 기반)
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --no-create-home appuser && \
    chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
