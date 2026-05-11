# 🔐 AI 기반 보안 위협 탐지 시스템 — 데모 시나리오

> **발표자**: 윤세빈 · 이동규  
> **예상 데모 시간**: 약 8~10분

---

## 사전 준비 체크리스트

발표 시작 전 아래 항목을 확인하세요.

- [ ] `docker-compose up -d` 로 전체 스택 기동 확인
- [ ] Redis, PostgreSQL 컨테이너 정상 실행 여부 확인
- [ ] 브라우저에서 대시보드(`http://localhost:3000`) 로그인 완료
- [ ] Discord 알림 채널 화면 대기 (알림 수신 확인용)
- [ ] 터미널 창 분할 (로그 모니터링용)

---

## STEP 1 — 허니팟 접근 시뮬레이션 (A파트 시연)

**담당: 윤세빈**  
**예상 소요: 1~2분**

### 시나리오 설명

> "지금부터 공격자가 허니팟에 접근하는 상황을 시뮬레이션합니다.
> 실제 환경에서는 외부 공격자가 SSH나 웹 포트를 스캔하게 됩니다."

### 실행 명령

```bash
# 터미널 1 — 이벤트 수집 에이전트 로그 확인
docker logs -f infrared-agent

# 터미널 2 — 공격 시뮬레이션 (공격자 IP 사용)
curl -X POST http://localhost:8000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.99.1",
    "dst_port": 22,
    "protocol": "SSH",
    "payload": "root login attempt"
  }'
```

### 확인 포인트

- 터미널 1에서 이벤트 캡처 로그 출력 확인
- Redis Stream에 이벤트가 적재되는 것을 확인

```bash
# Redis Stream 확인
docker exec -it infrared-redis redis-cli XLEN events:stream
```

**발표 멘트:**  
> "보시는 것처럼 공격자 이벤트가 Python 에이전트에 포착되어  
> Redis Stream에 즉시 적재됩니다. 이 단계가 A파트의 핵심입니다."

---

## STEP 2 — 실시간 대시보드 확인 (C파트 시연)

**담당: 윤세빈**  
**예상 소요: 2분**

### 시나리오 설명

> "이제 대시보드에서 실시간으로 이벤트가 반영되는 것을 확인합니다.
> SSE(Server-Sent Events)를 통해 새로고침 없이 자동으로 업데이트됩니다."

### 확인 포인트

1. **대시보드 접속** → `http://localhost:3000/dashboard`
2. 화면에 파란 카드(허니팟 방문자)가 새로 생성되는 것 확인
3. 카드 우측 상단의 **LLM 배지** 상태 변화 관찰:
   - `GRAY` — LLM 분석 대기 중
   - `ORANGE` — LLM 분석 진행 중
   - `GREEN` — 분석 완료

**발표 멘트:**  
> "방문자 카드가 실시간으로 나타납니다. 우측 배지가 회색 → 주황 → 초록으로  
> 바뀌는 것이 Claude AI의 분석 진행 상태를 나타냅니다."

---

## STEP 3 — 탐지 엔진 결과 확인 (B파트 시연)

**담당: 이동규**  
**예상 소요: 1~2분**

### 시나리오 설명

> "B파트에서는 Rule Engine이 이벤트를 MITRE ATT&CK 프레임워크로 분류합니다."

### 확인 포인트

```bash
# PostgreSQL에서 탐지 결과 조회
docker exec -it infrared-postgres psql -U postgres -d infrared \
  -c "SELECT src_ip, tactic, technique, severity, created_at FROM incidents ORDER BY created_at DESC LIMIT 5;"
```

예상 결과:
| src_ip | tactic | technique | severity |
|---|---|---|---|
| 192.168.99.1 | Initial Access | T1110 (Brute Force) | HIGH |

**발표 멘트:**  
> "Rule Engine이 SSH 브루트포스 공격으로 분류하고,  
> MITRE ATT&CK의 T1110 기법으로 자동 태깅했습니다."

---

## STEP 4 — Discord 알림 확인 (C파트 시연)

**담당: 윤세빈**  
**예상 소요: 1분**

### 시나리오 설명

> "2단계 알림 시스템을 확인합니다. 탐지 즉시 1차 알림이 가고,  
> Claude AI 분석이 완료되면 2차 알림이 자동으로 발송됩니다."

### 확인 포인트

**Discord 화면을 공유하며:**

1. **1차 알림** (탐지 즉시 발송)
   ```
   🚨 [ALERT] 새로운 위협 탐지
   IP: 192.168.99.1
   포트: 22 (SSH)
   분류: Brute Force
   심각도: HIGH
   ```

2. **2차 알림** (LLM 분석 완료 후 발송, 약 10~30초 후)
   ```
   🤖 [AI 분석 완료]
   공격 유형: SSH 브루트포스 (T1110)
   위험 수준: 높음
   권고 사항: 해당 IP 즉시 차단 및 관련 계정 비밀번호 변경 권고
   ```

**발표 멘트:**  
> "Debounce 처리로 짧은 시간에 대량 이벤트가 발생해도 알림이 폭주하지 않습니다."

---

## STEP 5 — Incident 상세 페이지 (C파트 시연)

**담당: 윤세빈**  
**예상 소요: 1분**

### 확인 포인트

1. 대시보드에서 방문자 카드 클릭 → Incident 상세 페이지 이동
2. **LLM 3줄 요약** 확인
3. **Evidence Timeline** 확인 (이벤트 발생 순서 타임라인)

**발표 멘트:**  
> "상세 페이지에서는 Claude가 생성한 3줄 요약과  
> 공격 흐름을 시간순으로 볼 수 있는 Evidence Timeline을 제공합니다."

---

## STEP 6 — IP 정책 설정 (C파트 시연)

**담당: 윤세빈**  
**예상 소요: 1분**

### 시나리오 설명

> "마지막으로 탐지된 공격 IP를 차단 정책에 추가하는 것을 보여드립니다."

### 확인 포인트

1. **Settings 페이지** (`http://localhost:3000/settings`) 접속
2. **IP Policy Manager** 탭 선택
3. `192.168.99.1` 을 차단 목록에 추가
4. **Auto-Response** 체크박스 활성화 → 이후 동일 IP 접근 시 자동 차단

**발표 멘트:**  
> "RBAC 권한이 있는 관리자만 이 설정에 접근할 수 있으며,  
> Auto-Response를 켜면 이후 동일 IP는 자동으로 차단됩니다."

---

## 데모 종료 — Q&A 안내

> "이상으로 데모를 마칩니다.  
> 허니팟 수집(A) → 룰 탐지(B) → AI 분석 & 알림(C) 의 전 과정을  
> 실시간으로 확인하셨습니다. 질문 있으시면 받겠습니다."

---

## 트러블슈팅 (혹시 모를 상황 대비)

| 상황 | 해결 방법 |
|---|---|
| 대시보드 이벤트 미표시 | Redis 연결 확인: `docker exec infrared-redis redis-cli ping` |
| Discord 알림 미수신 | `.env`의 `DISCORD_WEBHOOK_URL` 확인 |
| LLM 배지 GRAY 고착 | Claude API 키 및 네트워크 연결 확인 |
| DB 조회 오류 | PostgreSQL 컨테이너 재시작: `docker restart infrared-postgres` |

---

*본 시나리오는 발표 환경에 맞게 명령어와 IP를 조정하여 사용하세요.*
