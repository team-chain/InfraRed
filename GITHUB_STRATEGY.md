# InfraRed GitHub Strategy

InfraRed는 A/B/C 역할이 같은 저장소에서 동시에 작업하는 구조입니다. 이 문서는 브랜치, 커밋, PR, 리뷰, 배포 흐름을 맞추기 위한 팀 규칙입니다.

## 기본 원칙

- `main`은 항상 실행 가능한 상태를 유지합니다.
- 직접 `main`에 커밋하지 않고, 역할별 브랜치에서 작업 후 PR로 합칩니다.
- 공용 계약 변경은 반드시 다른 역할 담당자에게 공유합니다.
- `.env`, 토큰, AWS 키, Discord Webhook 같은 비밀값은 절대 커밋하지 않습니다.
- 설계 변경은 코드보다 먼저 `docs/`에 짧게 기록합니다.

## 브랜치 전략

기본 브랜치:

```text
main
```

작업 브랜치 규칙:

```text
feat/a-기능명
feat/b-기능명
feat/c-기능명
fix/a-버그명
fix/b-버그명
fix/c-버그명
docs/문서명
chore/작업명
```

예시:

```text
feat/a-agent-rotation
feat/b-auth-rule-engine
feat/c-incident-dashboard
fix/b-dedup-window
docs/github-strategy
```

## 역할별 소유 영역

### A - 수집/전송

주요 경로:

- `agent/`
- `backend/app/ingestion/`
- `backend/app/redis_kv/`
- `infra/`
- `docker-compose.yml`

주의:

- Redis Stream 이름이나 Envelope 구조를 바꾸면 B/C에게 PR에서 명확히 알립니다.
- Agent에서 raw log를 전송할 때 민감정보 마스킹 정책을 유지합니다.

### B - 탐지/분석

주요 경로:

- `backend/app/workers/detection/`
- `backend/app/workers/enrichment/`
- `backend/app/workers/correlation/`
- `backend/app/db/`
- `backend/app/models/signal.py`
- `backend/app/models/incident.py`

주의:

- `signals`, `incidents`, `incident_evidence`, `normalized_events` 스키마 변경은 C에게 영향이 큽니다.
- Rule ID, MITRE mapping, severity 기준 변경은 PR 설명에 반드시 남깁니다.

### C - AI/알림/프론트엔드

주요 경로:

- `backend/app/workers/llm/`
- `backend/app/dispatcher/`
- `backend/app/iam/`
- `frontend/`
- `infra/prometheus/`
- `infra/grafana/`

주의:

- Dashboard가 소비하는 API 응답 구조를 바꿀 때는 B와 함께 확인합니다.
- Bedrock, Discord, SMTP 설정은 `.env.example`에는 이름만 두고 실제 값은 커밋하지 않습니다.

## 공용 계약 변경 규칙

아래 파일은 3명 모두에게 영향을 주는 계약 파일입니다.

- `backend/app/models/`
- `backend/app/redis_kv/streams.py`
- `backend/app/redis_kv/keys.py`
- `backend/app/db/schema.sql`
- `docs/CONTRACTS.md`
- `docker-compose.yml`
- `.env.example`

이 파일을 수정하는 PR은 다음 중 최소 1명을 리뷰어로 둡니다.

- A 영향: A 담당자
- B 영향: B 담당자
- C 영향: C 담당자
- 전체 영향: A/B/C 전원

## 커밋 메시지 규칙

권장 형식:

```text
type(scope): message
```

type:

- `feat`: 기능 추가
- `fix`: 버그 수정
- `docs`: 문서
- `refactor`: 구조 개선
- `test`: 테스트
- `chore`: 설정/빌드/잡무

scope 예시:

- `agent`
- `ingestion`
- `detection`
- `enrichment`
- `correlation`
- `llm`
- `dispatcher`
- `frontend`
- `infra`
- `docs`

예시:

```text
feat(agent): add inode based log rotation handling
fix(detection): prevent duplicate brute force signals
docs(roles): clarify A/B/C ownership
chore(infra): add grafana provisioning
```

## PR 규칙

PR 제목:

```text
[A] Agent offset 저장 개선
[B] AUTH-001 brute force 룰 추가
[C] Incident dashboard 목록 화면 추가
[Common] Envelope 계약 변경
```

PR 본문에 포함할 내용:

```markdown
## Summary
- 무엇을 바꿨는지

## Scope
- A/B/C 중 어느 영역인지

## Contract Changes
- Envelope, Redis Stream, DB Schema, API 응답 변경 여부

## Test
- 실행한 검증 명령
- 실행하지 못한 검증과 이유

## Risk
- 영향받는 컴포넌트
```

## 리뷰 기준

리뷰어는 우선순위를 이렇게 봅니다.

1. 데이터 유실 가능성
2. 멀티테넌시 격리 문제
3. 보안/비밀값 노출
4. 공용 계약 깨짐
5. 장애 시 재처리 가능성
6. 테스트나 로컬 재현 절차 누락
7. 코드 스타일

## 이슈 관리

이슈 제목 예시:

```text
[A] Agent heartbeat retry policy
[B] AUTH-004 failed-then-success correlation
[C] Discord alert template
[Common] Incident Contract v1 freeze
```

권장 라벨:

- `role:a`
- `role:b`
- `role:c`
- `common`
- `bug`
- `feature`
- `docs`
- `security`
- `infra`
- `priority:high`

## Pull 전 습관

작업 시작 전:

```powershell
git checkout main
git pull
git checkout -b feat/a-example
```

작업 중 원격 변경 반영:

```powershell
git fetch origin
git rebase origin/main
```

충돌이 부담스러우면 merge를 사용해도 됩니다.

```powershell
git pull origin main
```

## Push 전 체크리스트

```powershell
git status
python scripts/check_syntax.py
docker compose config --quiet
```

가능하면 Docker Desktop을 켠 뒤:

```powershell
docker compose up --build
```

확인할 URL:

- API: `http://localhost:8000/healthz`
- Dashboard: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

## 금지 사항

- `.env` 커밋 금지
- JWT, AWS Key, Discord Webhook, SMTP Password 커밋 금지
- `main` 강제 push 금지
- 공용 계약 변경을 말없이 push 금지
- Docker volume 삭제 명령을 PR 설명 없이 실행 금지

## 릴리즈 전략

MVP 단계에서는 태그 기반으로만 간단히 관리합니다.

```text
v0.1.0-initial-scaffold
v0.2.0-agent-ingestion
v0.3.0-detection-correlation
v0.4.0-llm-dashboard
v1.0.0-mvp-demo
```

태그 생성:

```powershell
git tag v0.1.0-initial-scaffold
git push origin v0.1.0-initial-scaffold
```

## 권장 작업 순서

1. `docs/CONTRACTS.md` 기준으로 공용 계약 확정
2. A가 Ingestion API와 Agent 안정화
3. B가 Detection/Correlation 룰 고도화
4. C가 Incident Contract 기반 Dashboard/LLM/Alert 연결
5. Docker Compose 전체 E2E 검증
6. MVP 데모 태그 생성
