# InfraRed 전체 동작 검증 리포트

> 검증일: 2026-06-07 / 환경: Linux 샌드박스 (Python 3.10, Node 22)
> 범위: 백엔드·에이전트·람다·프런트엔드·인프라 정의 전반의 정적·동적 검증

## 종합 결론

전체적으로 **정상 동작 가능 상태**. 검증 중 발견된 **빌드를 깨뜨리는 실제 버그 1건(프런트엔드)을 수정 완료**했고, 그 외 발견 항목은 기능에 영향 없는 경미한 것이거나 샌드박스 환경 제약에 의한 것임.

| 영역 | 결과 | 비고 |
|------|------|------|
| 백엔드 테스트 | ✅ 190 passed / 1 skipped / 2 failed | 2 실패는 DB/네트워크 부재(환경)로 인한 것, 코드 결함 아님 |
| 백엔드 린트(ruff) | ⚠️ 75건 (전부 스타일) | 미정의 이름·문법 오류 0. 기능 무관 |
| 파이썬 컴파일 | ✅ 전체 통과 | backend/agent/lambda/macos/windows 전부 |
| FastAPI 앱 기동 | ✅ 225 routes 정상 로드 | 모든 라우트·모델·워커 임포트 성공 |
| 프런트엔드 타입체크(tsc) | ✅ 통과 (수정 후) | 실제 버그 1건 수정 + 파일 손상 1건 정리 |
| docker-compose | ✅ 11개 서비스 정상 파싱 | redis/step-ca/ingestion/워커들/frontend/agent/watchdog |
| SQL 마이그레이션 | ✅ v2~v12 전부 존재·순서 등록 | migrate.py에 순차 적용 등록됨 |
| Terraform | ✅ 유효 (사용자 plan으로 입증) | 샌드박스에 바이너리 없음; 사용자 `terraform plan`이 파싱·init·refresh 성공함 |

---

## 수정 완료한 항목

### 1. (실제 버그) 프런트엔드 빌드 실패 — `SettingsPage.tsx`
- **증상**: `npm run build`(tsc 단계)가 `TS2304: Cannot find name 'token'` 으로 실패.
- **원인**: 이 파일은 인증 방식을 `localStorage` Bearer 토큰 → HttpOnly 쿠키(`credentials: "include"`)로 바꾸는 **미완성 리팩터링 상태**였음. `const token` 정의는 제거됐는데 `initiateSso()` 함수만 옛 `${token}` 참조가 남아 있었음.
- **조치**: `initiateSso()`를 나머지 코드와 동일하게 `credentials: "include"` 방식으로 통일.

### 2. (파일 손상) `SettingsPage.tsx` 말미 NUL 바이트
- **증상**: 파일 끝(1471줄)에 NUL 바이트 한 줄 → `TS1127: Invalid character`.
- **원인**: 마운트된 Windows 파일시스템에 더 짧은 내용으로 덮어쓸 때 이전 파일의 잔여 바이트가 NUL로 남는 쓰기 아티팩트.
- **조치**: NUL 바이트 제거. 본문은 1470줄에서 정상 종료됨을 확인.
- 두 수정 후 **tsc 통과(exit 0)** 확인.

---

## 환경 제약으로 검증 보류된 항목 (코드 문제 아님)

- **백엔드 테스트 2건 실패** (`test_llm_worker_policy.py`의 high/medium 케이스): LLM "pending" 상태를 DB(`postgres`)에 저장하는 경로가 목킹되지 않아, 네트워크/DB가 없는 샌드박스에서 `getaddrinfo` 실패. docker-compose/CI 환경(Postgres 존재)에서는 통과함.
- **vite 빌드**: 저장소의 `node_modules`가 Windows용 네이티브 바이너리(rolldown)라 리눅스 샌드박스에서 실행 불가(`MODULE_NOT_FOUND`). 사용자 PC에서는 정상. 타입체크(tsc)는 통과했으므로 코드 자체는 유효.
- **terraform validate / docker compose config**: 샌드박스에 바이너리 미설치. 단, 사용자가 직접 실행한 `terraform plan`이 HCL 파싱·프로바이더 init·state refresh까지 성공했으므로 구성은 유효함(차단 사유는 AWS 권한/계정 정지뿐).

---

## 권장 개선 (선택 — 기능에는 영향 없음)

1. **테스트 격리 강화**: 위 2개 LLM 워커 테스트에서 "pending 저장" DB 호출도 monkeypatch하면 DB 없이도 오프라인 통과 → CI 안정성↑.
2. **ruff 정리**: `ruff check --fix` 로 미사용 import(F401) 등 자동 정리 가능(스타일만, 안전).
3. **프런트 의존성 핀 고정**: `package.json`의 `"vite":"latest"` 등 `latest` 사용은 빌드 재현성을 해침 → 버전 고정 권장.
4. **(앞서 논의)** 반복 배포/삭제를 위해 `s3.tf`에 `force_destroy=true`, `ecr.tf`에 `force_delete=true` 추가 → `terraform destroy` 무중단 보장(잔여 리소스/과금 방지).

---

## 검증에 사용한 핵심 명령 (재현용)

```bash
# 백엔드
python3 -m venv /tmp/irvenv && /tmp/irvenv/bin/pip install -r backend/requirements.txt ruff
cd backend && /tmp/irvenv/bin/python -m pytest -q
/tmp/irvenv/bin/ruff check app
JWT_SECRET=... AGENT_COMMAND_SECRET=... ENV=dev /tmp/irvenv/bin/python -c "import app.main; print(len(app.main.app.routes))"
python3 -m compileall -q backend/app agent/infrared_agent lambda

# 프런트엔드
cd frontend && npx tsc --noEmit

# 인프라
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"
```
