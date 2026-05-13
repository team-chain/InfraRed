# InfraRed — 구현 진행상황 인수인계 문서

> **대상 독자**: 이 프로젝트를 이어받는 AI / 팀원  
> **기준 문서**: `InfraRed_고도화_설계서_v2.0.docx`  
> **최종 업데이트**: 2026-05-13

---

## 프로젝트 개요

**InfraRed** — 중소기업용 AI 보안 자동화 플랫폼.  
서버에 에이전트를 설치하면 공격 징후를 실시간 탐지하고, AI(AWS Bedrock Claude)가 사건을 분석한 뒤, 관리자가 설정한 정책 범위 안에서 알림·Watchlist 등록·차단까지 자동 수행.

---

## ✅ v2.0 고도화 완료 항목

### Phase 0 — 보안 기반
| 항목 | 파일 | 설명 |
|------|------|------|
| DB 마이그레이션 | `backend/app/db/migrate_v2.sql` | Phase 1~5 전체 스키마 추가 (365줄) |
| Row-Level Security | migrate_v2.sql | 테넌트 격리 RLS 정책 |
| LLM 인젝션 방어 | `backend/app/workers/llm/sanitizer.py` | 프롬프트 인젝션 패턴 필터 |
| LLM Provider 추상화 | `backend/app/workers/llm/providers.py` | Bedrock / Anthropic SDK 통합 인터페이스 |

---

### Phase 1 — 인시던트 워크플로우
**파일**: `backend/app/ingestion/incident_routes.py` (624줄)

- `PATCH /incidents/{id}/status` — 상태 전이 (open→ack→in_progress→contained→resolved→closed)
- `PATCH /incidents/{id}/assignee` — 담당자 지정
- `POST/GET /incidents/{id}/comments` — 코멘트 스레드
- `POST/GET /incidents/{id}/links` — 인시던트 연결 (related/duplicate/caused_by)
- `GET /incidents/{id}/history` — 상태 변경 이력
- `GET /incidents/stats/fp` — FP 비율 통계
- `GET /incidents/stats/timeseries` — 시계열 인시던트 집계

**프론트엔드**: `frontend/src/components/IncidentWorkflow.tsx`, `IncidentTable.tsx`, `EvidenceTimeline.tsx`

---

### Phase 1-B — 알림 그룹핑 & 헬스체크
| 항목 | 파일 |
|------|------|
| 알림 그룹핑 | `backend/app/workers/detection/alert_grouping.py` |
| 헬스체크 API | `backend/app/ingestion/health_routes.py` (235줄) |
| RBAC v2 (4역할) | `backend/app/iam/rbac_v2.py` |

- `GET /health/dashboard` — 시스템 전체 상태 (agent_connectivity, detection_stream, llm_queue 등)
- `GET /health/agents` — 에이전트별 온/오프라인 상태 + 버전 비교

---

### Phase 2 — 룰 관리 플랫폼
**파일**: `backend/app/ingestion/rule_mgmt_routes.py` (646줄)

- `GET/POST /rules` — 룰 목록 / 생성(Draft)
- `GET/PATCH /rules/{id}` — 상세 조회 / 수정
- `POST /rules/{id}/dry-run` — 최근 1시간 시그널 대상 사전 검증
- `POST /rules/{id}/activate` — 관리자 승인 후 Active 전환
- `POST /rules/{id}/disable` — 비활성화
- `POST /rules/{id}/rollback` — 이전 버전 롤백
- `GET /rules/{id}/versions` — 버전 이력
- `GET /rules/stats/fp` — FP 통계 (incident_routes 공유)

**프론트엔드**: `frontend/src/pages/RuleManagementPage.tsx`

---

### Phase 2-C — Allowlist / Suppression / Maintenance Window
**파일**: `backend/app/ingestion/suppression_routes.py` (471줄)

- Allowlist: `GET/POST /allowlist`, `DELETE /allowlist/{id}`
- Suppression: `GET/POST /suppressions`, `DELETE /suppressions/{id}`
- Maintenance Window: `GET/POST /maintenance-windows`, `DELETE /maintenance-windows/{id}`

**프론트엔드**: `frontend/src/pages/SuppressionPage.tsx`

---

### Phase 3 — 에이전트 Lifecycle + 멤버 관리
| 파일 | 내용 |
|------|------|
| `backend/app/ingestion/agent_mgmt_routes.py` (386줄) | 에이전트 등록/활성화/비활성화/버전이력 |
| `backend/app/ingestion/user_routes.py` (403줄) | 멤버 CRUD, 역할 변경, 온보딩 API |
| `agent/infrared_agent/fim_watcher.py` | File Integrity Monitoring (inotify 기반) |

**에이전트 Lifecycle API**:
- `GET /agents` — 에이전트 목록
- `POST /agents/{id}/activate` — 활성화
- `POST /agents/{id}/deactivate` — 비활성화

**멤버 관리 API**:
- `GET/POST /users/{tenant_id}/members` — 멤버 목록 / 초대
- `PATCH /users/{tenant_id}/members/{user_id}/role` — 역할 변경
- `DELETE /users/{tenant_id}/members/{user_id}` — 멤버 제거
- `GET/POST /onboarding/status`, `/onboarding/complete/{step}` — 온보딩 흐름
- `POST /onboarding/generate-install-command` — 에이전트 설치 명령 생성

**프론트엔드**: `frontend/src/pages/MembersPage.tsx`, `frontend/src/pages/OnboardingPage.tsx`

---

### Phase 4 — 탐지 확장
| 항목 | 파일 |
|------|------|
| FIM 탐지 | `agent/infrared_agent/fim_watcher.py` |
| RAG 유사 인시던트 | `backend/app/workers/llm/rag.py` |
| 탐지 룰 설정 동기화 | `backend/app/workers/detection/rule_settings.py` |

**RAG** (pgvector 기반):
- Bedrock Titan Embeddings → 유사 인시던트 top-3 조회
- disposition 있는 사례만 포함 (FP 품질 보장)
- hash 기반 fallback (개발 환경)

---

### Phase 4-D — PDF 보고서
**파일**: `backend/app/workers/report/pdf_report.py`

- WeasyPrint HTML→PDF 변환
- 주간/월간 인시던트 통계 자동 생성
- S3 업로드 후 URL 제공
- `GET /reports` — 보고서 목록
- `POST /reports/generate` — 즉시 생성

**프론트엔드**: `frontend/src/pages/ReportsPage.tsx`

---

### Phase 5 — 엔터프라이즈
**파일**: `backend/app/ingestion/enterprise_routes.py` (592줄)

- `POST /search/natural` — 자연어 인시던트 검색 (NL2SQL 안전 파라미터 방식)
- `POST /notify/slack/test` — Slack 알림 테스트
- `POST /notify/teams/test` — MS Teams 알림 테스트
- `GET /config/backup` — 설정 내보내기 (JSON)
- `POST /config/restore` — 설정 가져오기
- `GET /config/backup/history` — 백업 이력

**프론트엔드**: `frontend/src/pages/NaturalSearchPage.tsx`

---

### 프론트엔드 (전체)

| 페이지 | 파일 |
|--------|------|
| 메인 대시보드 | `src/pages/Dashboard.tsx` |
| 자산 관리 | `src/pages/AssetsPage.tsx` |
| 분석/검색 | `src/pages/NaturalSearchPage.tsx` |
| 헬스체크 | `src/pages/HealthDashboardPage.tsx` |
| 룰 관리 | `src/pages/RuleManagementPage.tsx` |
| 억제 관리 | `src/pages/SuppressionPage.tsx` |
| 멤버 관리 | `src/pages/MembersPage.tsx` |
| 보고서 | `src/pages/ReportsPage.tsx` |
| 설정 | `src/pages/SettingsPage.tsx` |
| 온보딩 | `src/pages/OnboardingPage.tsx` |
| API 타입/함수 | `src/lib/api.ts` |

**빌드 상태**: `npm run build` ✅ (dist 생성 완료)

---

## 📊 테스트 결과

```
82 passed, 2 failed (실제 DB/AWS 연결 필요, 샌드박스 정상)
```

실패 2건: `test_llm_worker_policy.py` — RDS/Bedrock 네트워크 접속 불가 (환경 문제, 코드 정상)

---

## 🗂️ 신규 생성 파일 (v2.0)

```
backend/app/db/migrate_v2.sql
backend/app/workers/llm/sanitizer.py
backend/app/workers/llm/providers.py
backend/app/workers/llm/rag.py
backend/app/workers/report/pdf_report.py
backend/app/workers/detection/alert_grouping.py
backend/app/iam/rbac_v2.py
backend/app/ingestion/incident_routes.py
backend/app/ingestion/health_routes.py
backend/app/ingestion/rule_mgmt_routes.py
backend/app/ingestion/suppression_routes.py
backend/app/ingestion/user_routes.py
backend/app/ingestion/agent_mgmt_routes.py
backend/app/ingestion/enterprise_routes.py
agent/infrared_agent/fim_watcher.py
frontend/src/components/IncidentWorkflow.tsx
frontend/src/components/IncidentTable.tsx
frontend/src/components/EvidenceTimeline.tsx
frontend/src/pages/AssetsPage.tsx
frontend/src/pages/HealthDashboardPage.tsx
frontend/src/pages/RuleManagementPage.tsx
frontend/src/pages/SuppressionPage.tsx
frontend/src/pages/MembersPage.tsx
frontend/src/pages/ReportsPage.tsx
frontend/src/pages/NaturalSearchPage.tsx
frontend/src/pages/OnboardingPage.tsx
```

---

## ⚠️ 배포 전 확인 사항

1. **DB 마이그레이션**: `python -m app.db.migrate` 실행 (migrate_v2.sql 자동 적용)
2. **pgvector 확장**: RDS에서 `CREATE EXTENSION IF NOT EXISTS vector;` 필요 (RAG 기능)
3. **WeasyPrint**: PDF 생성용 `pip install weasyprint` + 시스템 패키지(Cairo, Pango) 필요
4. **Bedrock 권한**: Titan Embeddings 모델 (`amazon.titan-embed-text-v1`) 활성화 필요
5. **환경변수 추가**:
   - `ANTHROPIC_API_KEY` (Anthropic SDK 직접 사용 시)
   - `SLACK_WEBHOOK_URL` (Phase 5-B)
   - `TEAMS_WEBHOOK_URL` (Phase 5-B)
   - `SENDGRID_API_KEY` (PDF 보고서 이메일)

---

## 🚀 빠른 시작

```powershell
# 환경 설정
Copy-Item .env.example .env
# AGENT_TOKEN, DISCORD_WEBHOOK_URL, AWS 키 설정 후:

# 실행
docker compose up --build

# DB 마이그레이션 (별도 실행 또는 compose startup hook)
docker compose exec api python -m app.db.migrate

# 테스트 이벤트 발송
python scripts/send_test_event.py
```

서비스 포트:
- API: `http://localhost:8000`
- Dashboard: `http://localhost:3000`
- SSE Stream: `http://localhost:8000/events/stream`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`
