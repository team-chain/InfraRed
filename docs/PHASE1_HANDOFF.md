# Phase 1 Handoff — Auth Flow + Agent Install

Phase 1 작업 산출물 요약 + 동규님이 직접 실행해야 하는 단계 체크리스트.

---

## 산출물 (Code Changes)

### 1. First Admin Bootstrap
- **신규**: `backend/app/db/bootstrap_admin.py`
  - 환경변수 기반 멱등(idempotent) admin 부트스트랩 CLI
  - 필수 env: `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD`
  - 선택 env: `INITIAL_ADMIN_TENANT_ID`(기본 `default`), `INITIAL_ADMIN_TENANT_NAME`, `INITIAL_ADMIN_PLAN`(기본 `mvp`)
  - 동작: 테넌트 없으면 생성 → 사용자 없으면 생성(admin role + bcrypt) → `tenant_memberships` 추가. 모두 멱등.
- **수정**: `backend/app/db/migrate.py`
  - `seed.sql` 적용 직후 자동으로 `bootstrap_admin_on(conn)` 호출 (env 변수 있을 때만)
  - 실패해도 migrate 전체를 중단시키지 않음 (warn만 출력)
- **수정**: `Makefile` — `make bootstrap-admin` 타겟 추가
- **수정**: `.env.example` — `INITIAL_ADMIN_*` 5종 문서화 (모두 주석 처리, 명시적 활성화 필요)

### 2. Register Page Wire-up
- **수정**: `frontend/src/App.tsx`
  - `AuthView = "login" | "register"` state 추가
  - `RegisterPage` import + 라우팅
  - URL에 `?invite_email=...`이 있으면 자동으로 register view 진입
  - 가입 직후 자동으로 onboarding view로 이동 (기존엔 dashboard로 갔음)
- **수정**: `frontend/src/pages/Login.tsx`
  - `onGoToRegister` prop 추가 + "Sign up" 링크 표시

### 3. Invite System
- **수정**: `frontend/src/pages/Register.tsx`
  - URL 파라미터 `invite_email`, `tenant_id`, `role` 감지/prefill
  - 초대 모드면 이메일/테넌트 read-only로 잠금 + "초대받으셨습니다" 배너
  - role 필드는 invited 모드에서 숨김 (서버에서 pending_invitations로 자동 부여됨)
- **수정**: `frontend/src/pages/MembersPage.tsx`
  - 대기 초대 항목에 "초대 링크 복사" 버튼 추가 (clipboard API + fallback)
  - 이메일 자동 발송 wiring은 Phase 2의 SES 작업
- **이미 working tree에 있음**: `backend/app/ingestion/user_routes.py`
  - `/users/{tenant_id}/invite`, `/users/{tenant_id}/pending-invitations`, role/remove 등 완전 구현
  - `main.py:203`에 router 등록 확인됨

### 4. Onboarding Flow
- **수정**: `frontend/src/pages/OnboardingPage.tsx`
  - Step 3(연결 확인)이 **이전엔 가짜**였음 — 그냥 "완료" 화면만 표시
  - 이제는 `fetchOnboardingStatus()`를 5초마다 polling해서 실제 agent heartbeat 감지
  - 로딩 스피너 + 경과 시간 표시 + "건너뛰고 대시보드로 이동" 옵션
  - 각 단계 전환 시 `completeOnboardingStep(N)` 호출하여 백엔드 추적

### 5. Agent Install One-liner
- **재작성**: `scripts/install-agent.sh`
  - 이전엔 placeholder URL + 동작 안 하는 `pip install infrared-agent` — 실제 설치 불가능
  - 새 버전: **docker 모드(권장, 기본)** + **native 모드(git clone + venv, 폴백)**
  - `auto` 모드는 docker 존재하면 docker, 없으면 native
  - 환경변수/CLI 둘 다 지원: `INFRARED_TOKEN`, `INFRARED_TENANT_ID`, `INFRARED_SERVER_URL`, `INFRARED_AGENT_IMAGE`, `INFRARED_AGENT_REPO`
  - root 권한 + systemd 사전검증 + idempotent 재실행
- **이미 있음**: `backend/app/main.py:522` `GET /install-agent.sh` 엔드포인트가 이 파일을 그대로 serve

---

## 동규님이 직접 실행해야 하는 단계

### A. 코드 머지 (5분)
```bash
cd C:\InfraRed
git status                              # 변경/신규 파일 확인
git diff backend/app/db/migrate.py      # bootstrap_admin 통합 확인
git diff backend/app/ingestion/user_routes.py  # working tree에 있던 invite 로직 (큰 diff)
git add -A
git commit -m "Phase 1: first-admin bootstrap + register wire-up + invite UI + onboarding verify + install script"
git push origin <branch>
```

### B. EC2에 배포 (10분)
1. `.env` 또는 secrets manager에 다음 추가:
   ```bash
   INITIAL_ADMIN_EMAIL=ops@infrared.kr
   INITIAL_ADMIN_PASSWORD=<강력한 비밀번호, 8자 이상>
   INITIAL_ADMIN_TENANT_ID=infrared
   INITIAL_ADMIN_TENANT_NAME=InfraRed Internal
   INITIAL_ADMIN_PLAN=enterprise
   ```
2. 백엔드 이미지 빌드 + ECR push (`make aws-push` 또는 기존 CI)
3. ECS service update (또는 ec2의 `docker compose pull && docker compose up -d ingestion`)
4. 컨테이너 시작 시 `python -m app.db.migrate` 자동 실행 → 끝에서 bootstrap admin 자동 생성
5. 로그 확인:
   ```bash
   docker logs infrared-ingestion 2>&1 | grep bootstrap_admin
   # 기대: [bootstrap_admin] OK — created admin 'ops@infrared.kr' on tenant 'infrared' (user_id=...)
   ```

### C. 동작 검증 — 가입/로그인 흐름 (5분)
1. 브라우저로 `https://app.infrared.kr/` 접속
2. **로그인**: tenant=`infrared`, email=`ops@infrared.kr`, password=설정한 값 → Dashboard 진입
3. **Members 페이지** 이동 → 본인이 admin 역할로 보이는지 확인
4. **새 멤버 초대**: 이메일 + role 입력 → "초대" → pending invitation에 표시되는지
5. **초대 링크 복사**: pending 항목의 link 아이콘 클릭 → 시크릿 브라우저에서 붙여넣기
6. **Sign up**: prefilled email + tenant + 배너 보이는지 → 비밀번호 입력 → 가입 → onboarding 화면
7. **Onboarding**: 환경 선택(server) → install 화면에서 명령어 보이는지 → "설치 완료" → "Agent 연결 대기중..." 화면(아직 agent 없으니 영원히 대기) → "건너뛰고 대시보드로 이동"
8. **Members 재확인**: 초대받았던 사용자가 멤버 목록에 자동 합류되었는지

### D. Agent 설치 검증 — Dogfood EC2 (15분)
1. **사전 작업**: agent docker 이미지를 **공개** registry에 push (또는 ECR Public)
   - 현재 `139139347353.dkr.ecr.ap-northeast-2.amazonaws.com/infrared-dev-agent:latest`는 private
   - 옵션 1: `ghcr.io/<your-org>/infrared-agent:latest`로 push
   - 옵션 2: ECR Public Gallery에 push
   - 옵션 3: `--mode native`로 git clone 방식 사용 (public repo여야 함)
2. **install script URL**: `https://api.infrared.kr/install-agent.sh` 접근 확인
   ```bash
   curl -fsSL https://api.infrared.kr/install-agent.sh | head -3
   # 기대: #!/usr/bin/env bash 로 시작
   ```
3. **agent 토큰 발급**: 본인 admin 계정으로 로그인 → Onboarding 또는 Settings에서 API key 생성
4. **테스트 EC2에서 설치 실행**:
   ```bash
   ssh ubuntu@<test-ec2>
   curl -fsSL https://api.infrared.kr/install-agent.sh | sudo bash -s -- \
     --token "<발급받은 토큰>" \
     --tenant "infrared" \
     --server "https://api.infrared.kr" \
     --image "ghcr.io/<your-org>/infrared-agent:latest"
   ```
5. **연결 확인**:
   ```bash
   sudo systemctl status infrared-agent
   sudo journalctl -u infrared-agent -n 30
   ```
6. Dashboard → Assets 또는 Onboarding의 Step 3에서 **자동으로 "연결 완료" 화면 전환**되는지 확인

---

## 검증 — Smoke test 시나리오

이 6단계가 모두 막힘없이 흐르면 Phase 1 OK:

1. Fresh DB → migrate 실행 → bootstrap admin 자동 생성됨 (로그 확인)
2. 로그인 → Dashboard 진입
3. Members → 초대 발송 → 링크 복사 → 다른 브라우저에서 가입 → 자동 멤버 합류
4. 가입 사용자가 Onboarding 진입 → install 명령어 표시됨
5. install 명령어를 EC2에서 실행 → systemctl 서비스 활성화 → heartbeat 전송
6. Onboarding Step 3가 자동으로 "연결 완료"로 전환 → Dashboard 진입

---

## 알려진 한계 / Phase 2로 이월

- **이메일 자동 발송 없음**: 초대 링크는 owner가 수동으로 복사해서 전달해야 함 (Phase 2 SES 작업)
- **이메일 인증 / 비밀번호 재설정 없음**: Phase 2 또는 별도 작업
- **2FA/MFA UI 없음**: TOTP는 백엔드에 있으나 UI 미연결
- **`infrared.kr` 도메인이 실제로 배포되어 있어야** install one-liner가 동작 (또는 URL을 `api.infrared.kr` 같은 실제 도메인으로 교체)
- **Agent 공개 이미지 필요**: docker mode 사용하려면 public registry에 push 필요. 아니면 `--mode native` 사용.

---

## ⚠ 검증 시 주의사항

작업 중 bash sandbox와 file tool 사이 sync 문제가 있어, AI 측에서 `python3 -c "import ast..."` 같은 lint를 신뢰할 수 없었습니다.
**동규님 쪽 디스크의 파일은 file tool 기준으로 정상**입니다.
머지 전 다음을 직접 확인 권장:

```bash
cd C:\InfraRed
python -c "import ast; ast.parse(open('backend/app/db/migrate.py').read()); print('migrate.py OK')"
python -c "import ast; ast.parse(open('backend/app/db/bootstrap_admin.py').read()); print('bootstrap_admin.py OK')"
bash -n scripts/install-agent.sh && echo "install-agent.sh OK"
cd frontend && npx tsc --noEmit
```

타입/문법 오류 없으면 머지/배포 진행.
