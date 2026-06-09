# InfraRed 로컬 실행 가이드 (AWS 불필요)

> 목적: AWS 계정/자격증명 없이 InfraRed 전체 스택을 한 대의 머신에서 띄워 데모하기.
> 핵심: 이 시스템은 `LLM_PROVIDER=auto`(자격증명 없으면 정적 플레이북 대체), `CTI_PROVIDER=mock`,
>       로컬 postgres 기본값으로 **완전 오프라인 동작**하도록 설계돼 있음.

## 왜 별도 구성이 필요했나

레포의 `docker-compose.yml`은 **EC2 배포용**이라 로컬에서 바로 못 띄운다:
- 이미지를 옛 계정 ECR에서 pull (접근 불가)
- `env_file: /opt/infrared/.env` (EC2 절대경로)
- postgres 서비스 없음

그래서 로컬 전용 구성을 추가했다 (빌드용 Dockerfile은 `infra/docker/*.Dockerfile`에 이미 존재):
- `docker-compose.dev.yml` — Dockerfile에서 직접 빌드 + postgres·redis 포함
- `infra/docker/nginx.dev.conf` — 대시보드/API를 같은 오리진(:3000)으로 묶어 쿠키 인증 동작
- `run-local.sh` — .env 생성·토큰 발급·빌드·기동·헬스체크 한 방

## 실행

```bash
# 레포 루트에서
./run-local.sh
```

끝나면:
- 대시보드: http://localhost:3000  (로그인: `admin@infrared.local` / `infrared123`)
- API: http://localhost:8000  (`/healthz`, `/api/v1/debug/replay-events`)

종료/초기화:
```bash
./run-local.sh down      # 종료(데이터 유지)
./run-local.sh reset     # 볼륨·.env까지 삭제(완전 초기화)
```

## 데모 공격을 어떻게 주입하나

두 가지 방법 모두 이 로컬 스택과 호환된다.

1. **결정적 주입 (가장 안전)** — BAS 픽스처를 `debug/replay-events`로 재생.
   `backend/tests/detection/fixtures/scenarios/*.jsonl` 의 이벤트를 `POST http://localhost:8000/api/v1/debug/replay-events` 로 흘려보내면 실제 파이프라인(탐지→상관분석→대응)이 동작. (owner 토큰 필요, `ENV=local`이라 디버그 API 허용됨)

2. **2-VM 실제 공격 (가장 생생)** — `demo/DEMO_RUNBOOK.md` 참고.
   타깃 VM에서 이 로컬 스택을 띄우고, 공격자 VM에서 `demo/attack.sh <타깃IP>` 실행.
   에이전트가 호스트 `/var/log`(컨테이너에 read-only 마운트됨)와 FIM 경로를 감시해 실제 탐지.

## 알아둘 점

- **AI 분석(데모 5막)**: AWS Bedrock 자격증명이 없으면 정적 플레이북으로 자동 대체된다. 탐지·상관분석·자동대응(데모 핵심)은 영향 없음. AI 서술까지 라이브로 보이고 싶으면 `.env`에 `AWS_PROFILE` 또는 임시 키 + `LLM_PROVIDER=bedrock` 설정.
- **자동 차단의 물리적 효과**: 컨테이너 에이전트가 호스트 iptables를 조작하려면 권한이 필요하다(compose에 `NET_ADMIN`/`NET_RAW` 부여). 단일 머신 데모에선 차단이 대시보드에 "실행됨"으로 표시되는 수준으로 보고, "공격자 접속이 끊기는" 물리 장면은 2-VM 구성에서 보여주는 걸 권장.
- **최초 빌드**: 백엔드 이미지(WeasyPrint 등 포함)는 처음 빌드 시 수 분 걸린다. 두 번째부터는 캐시로 빠름.
- **검증 상태**: compose YAML 파싱·빌드 컨텍스트 경로·스크립트 문법은 정적 검증 완료. 단, 이 샌드박스엔 Docker가 없어 **실제 `up` 1회는 네 머신에서 리허설 필요**. 막히면 `docker compose -f docker-compose.dev.yml logs <서비스>` 로 확인.
```
```
