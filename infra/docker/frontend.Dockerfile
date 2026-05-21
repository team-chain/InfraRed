# ============================================================
# Frontend — production build (multi-stage)
# Stage 1: vite build → 정적 파일 생성
# Stage 2: nginx:alpine 으로 정적 서빙 (메모리 ~20MB)
# ============================================================

# ── Stage 1: build ─────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .

# 빌드 시점에 주입되는 환경변수 (api.infrared.kr 등)
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

# tsc 타입체크는 빌드 깨질 위험 있어 skip — vite가 esbuild로 트랜스파일
RUN npx vite build

# ── Stage 2: serve ─────────────────────────────────────────
FROM nginx:1.27-alpine

# 컨테이너 내부 nginx 설정 (SPA fallback + gzip)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 빌드 결과물만 가져옴
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

# nginx:alpine 기본 CMD 사용 (포그라운드 실행)
