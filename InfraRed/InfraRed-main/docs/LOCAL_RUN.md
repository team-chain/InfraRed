# 로컬 실행

## 1. 환경변수 준비

```powershell
Copy-Item .env.example .env
python scripts/generate_jwt.py --role agent
```

출력된 JWT를 `.env`의 `AGENT_TOKEN`에 붙여 넣습니다.

## 2. 전체 실행

```powershell
docker compose up --build
```

## 3. 샘플 이벤트 전송

```powershell
python scripts/send_test_event.py
```

## 4. 확인

```powershell
Invoke-RestMethod http://localhost:8000/healthz
Invoke-RestMethod http://localhost:8000/incidents
```

대시보드는 http://localhost:3000 에서 확인합니다.

## 문제 해결

- `.env`가 없으면 Compose의 `env_file: .env` 때문에 서비스가 뜨지 않습니다.
- `AGENT_TOKEN`이 placeholder면 Agent와 `send_test_event.py --token` 요청이 401을 받습니다.
- PostgreSQL 초기 schema를 다시 적용하려면 Docker volume을 지워야 합니다. 기존 데이터가 필요 없는 경우에만 실행하세요.
