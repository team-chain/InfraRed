# InfraRed — 구현 진행상황 인수인계 문서

> **대상 독자**: 이 프로젝트를 이어받는 AI / 팀원  
> **기준 문서**: `InfraRed_설계서_최종.docx` (v1.0, AI ROOKIE 2026)  
> **최종 업데이트**: 2026-05-12

---

## 프로젝트 개요

**InfraRed** — 중소기업용 AI 보안 자동화 플랫폼.  
서버에 에이전트를 설치하면 공격 징후를 실시간 탐지하고, AI(AWS Bedrock Claude)가 사건을 분석한 뒤, 관리자가 설정한 정책 범위 안에서 알림·Watchlist 등록·차단까지 자동 수행.

### 핵심 파이프라인

```
Agent (auth.log + nginx.log)
  → POST /ingest (FastAPI)
  → Redis Streams (events:raw)
  → Detection Worker (AUTH/WEB/NET 룰 평가)
  → Redis Streams (signals:matched)
  → Enrichment Worker (GeoIP/CTI)
  → Redis Streams (signals:enriched)
  → Incident Worker (Correlation, Incident 생성)
      ↓ Discord 1차 즉시 알림 (Static Playbook)
      ↓ SSE Push → Dashboard / Tray App
  → Redis Streams (incidents:new)
  → LLM Worker (Bedrock Claude 분석)
      ↓ Discord 2차 알림 (AI 완료 후)
      ↓ Policy Engine (Watchlist/Denylist)
  → Web Dashboard + PyQt6 Tray App
```

---

## ✅ 완료된 구현 항목

### ① Redis Denylist 실제 차단 + 403 미들웨어
**파일**: `backend/app/autoresponse/engine.py`, `backend/app/main.py`

- `engine.py` 기본 정책 변경: `critical.block_ip = True` (기존 `False`)
- `_denylist_add()` 구현: `block_ip=True` 시 Redis SADD로 실제 차단 (기존 dry_run 로그만)
- `_denylist_remove()` 구현: 롤백용
- `rollback_denylist()` 공개 함수 추가
- `main.py`에 `denylist_middleware` 추가:
  - 모든 HTTP 요청마다 `X-Forwarded-For` / `client.host`를 Redis Denylist와 대조
  - 차단된 IP 요청 → 즉시 `403 {"detail": "blocked"}` 반환
  - `/healthz`, `/metrics`, `/auth/`, `/sdk.js`는 차단 제외
- 중복 차단 idempotent 처리 (`block_ip_already_blocked` 상태 구분)
- `auto_response_logs.dry_run = False` (실제 차단으로 변경)

**발표 데모 효과**: 모바일 QR 접속 → /.env 탐지 → Critical Policy → Redis Denylist 등록 → 모바일 재접속 시 403 차단 페이지

---

### ② Discord 1차 즉시 알림 분리
**파일**: `backend/app/dispatcher/discord.py`, `backend/app/workers/correlation/worker.py`

- `discord.py`에 `send_discord_first_alert()` 함수 추가:
  - 탐지 룰 ID, 출발지 IP, Static Playbook 요약 포함
  - "AI 분석 중, 2차 알림 예정" 안내 포함
- `correlation/worker.py`에서 Incident 신규 생성(`created=True`) 시 즉시 1차 알림 발송
- 기존 LLM Worker의 2차 알림(AI 완료 후)은 유지
- Medium/High/Critical만 1차 알림 발송 (Info 제외)

**설계서 4.3 구현**: 1차 즉시 → AI 분석 중 → 2차 AI 완료

---

### ③ Static Playbook WEB/NET 룰 대응
**파일**: `backend/app/workers/llm/playbook.py`

전면 재작성. rule_id 기반 분기로 탐지 컨텍스트에 맞는 한국어 요약 생성.

**지원 룰**:
- `AUTH-001` ~ `AUTH-004`: SSH 브루트포스, root 로그인, 계정 열거, 계정 탈취
- `AUTH-006A/B`: Credential Stuffing / Password Spraying
- `WEB-HNY-001`: Honeypot 경로 접근 (발표 데모 핵심)
- `WEB-001`: 웹셸 접근 의심
- `WEB-007`: CVE 탐침 경로
- `NET-001`: HTTP Flood

추가 함수:
- `get_first_alert_summary()`: Discord 1차 알림용 한 줄 요약 반환
- `_render()`: `{source_ip}`, `{username}` 템플릿 치환

---

### ④ 에이전트 nginx.log 수집
**파일**: `agent/infrared_agent/nginx_tailer.py` (신규), `agent/infrared_agent/main.py`, `agent/infrared_agent/config.py`

- `nginx_tailer.py` 신규 생성:
  - nginx Combined Log Format 정규식 파싱
  - `WEB_REQUEST` EventType의 RawEventEnvelope 생성
  - `source_ip`, `http_method`, `request_path`, `status_code`, `user_agent` 필드 포함
  - 파일 없으면 조용히 스킵 (nginx 없는 환경 호환)
- `config.py`에 설정 추가:
  - `agent_nginx_log_path`: `/host/var/log/nginx/access.log`
  - `agent_nginx_enabled`: `True`
- `main.py` 전면 개선:
  - `AuthLogTailer` + `NginxLogTailer` 병렬 실행
  - `_send_log_events()` 공통 함수로 리팩터링
  - S3 업로드 nginx 로그도 포함

---

### ⑤ PyQt6 Tray App
**파일**: `tray_app/main.py` (신규), `tray_app/requirements.txt` (신규)

설계서 6장 전체 구현:
- SSE 연결 (`SseWorker` QThread) — 백그라운드 Redis Pub/Sub 수신
- High/Critical 발생 시 `QSystemTrayIcon.showMessage()` OS 알림 팝업
- 최근 Incident 3개 트레이 메뉴 표시
- 클릭 시 웹 대시보드 URL 열기 (`webbrowser.open`)
- 연결 상태 아이콘: 초록(Connected) / 회색(Disconnected) / 빨강(Alert)
- 설정 다이얼로그: API URL, Token, 대시보드 URL 저장
- 자동 재연결 (Exponential backoff, 최대 60초)

**실행**:
```bash
cd tray_app
pip install -r requirements.txt
INFRARED_TOKEN=<your_token> python main.py
```

---

### ⑥ NET-001 HTTP Flood 탐지 룰
**파일**: `backend/app/common/constants.py`, `backend/app/workers/detection/web_rules.py`, `backend/app/workers/detection/rule_settings.py`, `backend/app/workers/detection/worker.py`

- `constants.py`: `NET_HTTP_FLOOD = "NET-001"` RuleId 추가
- `rule_settings.py`: `net_http_flood_enabled`, `net_http_flood_threshold`(300req), `net_http_flood_window_seconds`(300s) 추가
- `web_rules.py`: `evaluate_net_rules()` 구현
  - Sliding Window (Redis Sorted Set) 방식
  - 5분 내 동일 IP 300+ 요청 → NET-001 Signal 생성
  - MITRE T1595 매핑, Impact KillChain 단계
- `worker.py`: WEB_REQUEST 이벤트에서 `evaluate_net_rules()` 추가 호출

---

### ⑦ 정책 UI per-severity 체크박스
**파일**: `backend/app/ingestion/policy_routes.py`, `frontend/src/pages/SettingsPage.tsx`, `frontend/src/lib/api.ts`

- `policy_routes.py`에 추가:
  - `GET /api/policy/autoresponse`: 현재 severity별 정책 조회
  - `PATCH /api/policy/autoresponse`: 정책 수정 → Redis 즉시 반영
  - 입력 검증 (유효한 severity/action 값만 허용)
- `api.ts`에 추가:
  - `fetchAutoresponsePolicy()`, `patchAutoresponsePolicy()` 함수
  - `AutoresponsePolicy`, `AutoresponseActions` 타입
  - `unblockIp()` 함수
- `SettingsPage.tsx`에 추가:
  - `AutoresponsePolicyTable` 컴포넌트: severity × action 체크박스 테이블
  - Toggle 변경 즉시 API 호출 → 성공 시 toast 알림
  - 실패 시 낙관적 업데이트 롤백

---

### ⑧ SSE 실시간 Push 엔드포인트
**파일**: `backend/app/ingestion/sse_routes.py` (신규), `backend/app/main.py`, `backend/app/workers/correlation/worker.py`, `frontend/src/pages/Dashboard.tsx`

- `sse_routes.py` 신규 생성:
  - `GET /events/stream`: JWT 인증 → Redis Pub/Sub 구독 → `text/event-stream` 응답
  - 20초마다 keepalive ping 발송
  - `publish_incident_event()`: 다른 Worker에서 SSE 이벤트 발행용 헬퍼
- `main.py`: SSE 라우터 등록
- `correlation/worker.py`: Incident 생성/업데이트 시 SSE 발행
- `Dashboard.tsx`: `EventSource` 연결 추가
  - `incident_created` 이벤트 → 목록 즉시 갱신
  - `incident_updated` 이벤트 → 목록 갱신
  - `llm_completed` 이벤트 → 선택된 Incident 상세 갱신
  - 자동 재연결 (EventSource 기본 동작)

---

### ⑨ IP 차단 롤백 API
**파일**: `backend/app/main.py`

- `DELETE /policy/denylist/{ip}`: Redis Denylist에서 IP 제거
  - `auto_response_logs.reversed = true` DB 업데이트
  - `reversed_at`, `reversed_by` 기록
  - `audit_logs`에 `policy.denylist.remove` 기록
- `GET /policy/denylist`: 현재 차단된 IP 목록 조회
- `engine.py`에 `rollback_denylist()` 공개 함수 추가

---

### ⑩ 룰 ID 명명 통일
**파일**: `backend/app/common/constants.py`, `backend/app/workers/detection/rules.py`

| 이전 | 이후 | 설계서 |
|------|------|--------|
| `AUTH-CS-A` | `AUTH-006A` | Credential Stuffing |
| `AUTH-CS-B` | `AUTH-006B` | Password Spraying |

- `playbook.py`에 이전 명칭 호환 별칭 유지 (`_PLAYBOOK["AUTH-CS-A"] = _PLAYBOOK["AUTH-006A"]`)
- `rules.py` 주석 통일

---

### ⑪ Worker 컨테이너 명칭 정리
**파일**: `docker-compose.yml`

| 이전 | 이후 |
|------|------|
| 서비스명: `correlation-worker` | `incident-worker` |
| `container_name: infrared-correlation` | `infrared-incident` |

---

## 📁 신규 생성 파일 목록

| 파일 | 역할 |
|------|------|
| `tray_app/main.py` | PyQt6 Tray App 전체 |
| `tray_app/requirements.txt` | Tray App 의존성 |
| `agent/infrared_agent/nginx_tailer.py` | nginx access.log 수집 |
| `backend/app/ingestion/sse_routes.py` | SSE 실시간 Push 엔드포인트 |

---

## 🔧 수정된 파일 목록

| 파일 | 주요 변경 |
|------|-----------|
| `backend/app/autoresponse/engine.py` | Denylist 실제 차단, 기본 정책 수정 |
| `backend/app/main.py` | Denylist 미들웨어, SSE 라우터, 롤백 API |
| `backend/app/dispatcher/discord.py` | 1차 즉시 알림 함수 추가 |
| `backend/app/workers/correlation/worker.py` | 1차 Discord + SSE 발행 |
| `backend/app/workers/llm/playbook.py` | 전면 재작성 (rule_id 분기) |
| `backend/app/workers/detection/web_rules.py` | NET-001 룰 추가 |
| `backend/app/workers/detection/worker.py` | NET-001 호출 추가 |
| `backend/app/workers/detection/rule_settings.py` | NET-001 임계값 추가 |
| `backend/app/workers/detection/rules.py` | AUTH-006A/B 주석 통일 |
| `backend/app/common/constants.py` | NET-001 RuleId, AUTH-006A/B |
| `backend/app/ingestion/policy_routes.py` | Autoresponse 정책 API 추가 |
| `agent/infrared_agent/main.py` | NginxTailer 병렬 실행 |
| `agent/infrared_agent/config.py` | nginx 설정 추가 |
| `frontend/src/lib/api.ts` | Autoresponse, unblockIp 함수 |
| `frontend/src/pages/SettingsPage.tsx` | per-severity 체크박스 UI |
| `frontend/src/pages/Dashboard.tsx` | SSE EventSource 연결 |
| `docker-compose.yml` | incident-worker 명칭 변경 |

---

## ⚠️ 잔여 작업 / 주의사항

### 발표 데모 전 필수 확인
1. **EC2 배포**: `docker compose up --build` 후 EC2 공인 IP로 접속 가능한지 확인
2. **Bedrock 권한**: AWS Bedrock Claude 모델 접근 권한 활성화 필요 (`docs/AWS_BEDROCK_SETUP.md` 참조)
3. **nginx.log 마운트**: `docker-compose.yml`의 agent 볼륨에 `/var/log/nginx` 마운트 추가 필요
4. **Demo 경로 설정**: `/demo` QR 접속 URL을 발표 환경 도메인으로 변경
5. **발표 정책 사전 설정**: Critical → block_ip=True 정책 UI에서 확인

### 미구현 (데모 제외 확장 기능)
- auditd 로그 수집 (설계서 3.2 확장 탐지)
- S3 장기 보관 실제 연동 (설정만 있고 미검증)
- AWS WAF / Cloudflare 연동 (Level 3~4)
- Kubernetes 배포 (운영 확장)

### 알려진 이슈
- `correlation/worker.py`에서 `_get_tenant_dispatch_config` import 시 순환 참조 가능성 → 실행 시 확인 필요
- `SettingsPage.tsx`의 기존 severity 버튼 UI와 per-severity 테이블이 공존 — 기존 버튼 UI는 `approval/auto` 모드에서만 보임

---

## 🚀 빠른 시작

```powershell
# 환경 설정
Copy-Item .env.example .env
# AGENT_TOKEN, DISCORD_WEBHOOK_URL, AWS 키 설정 후:

# 실행
docker compose up --build

# 테스트 이벤트 발송
python scripts/send_test_event.py

# Tray App 실행 (별도 터미널)
cd tray_app
pip install -r requirements.txt
python main.py
```

서비스 포트:
- API: `http://localhost:8000`
- Dashboard: `http://localhost:3000`
- SSE Stream: `http://localhost:8000/events/stream`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`
