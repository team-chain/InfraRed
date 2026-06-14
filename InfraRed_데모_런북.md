# InfraRed 데모 런북 (핫스팟 / 현재 IP 기준)
> 핵심 메시지: **"백신은 악성파일(시그니처)을 찾지만, InfraRed는 정상 도구(SSH·cron·cat)로 들어와도 그 '행동'을 잡는다."**

## ★ 현재 환경 값 (이번 데모 기준)
| 항목 | 값 |
|---|---|
| **대시보드** | https://infrared.kr  (조직 `chain` / `dkdevelop511@gmail.com` / `infrared511`) |
| **VM(피해자) IP** | **172.20.10.4**  (아이폰 핫스팟 대역) |
| **차단 허용 대역** | **172.20.10.0/28** (현재 핫스팟) |
| **미끼 계정** | `deploy` / `deploy123` (sudo) |
| **EC2(서버)** | `ec2-user@43.200.131.24` |

> ⚠️ **네트워크 바뀌면 IP·대역이 달라짐.** VM에서 `hostname -I`로 새 IP 확인 → 아래 5번으로 차단대역 갱신 → 명령의 `172.20.10.4`를 새 IP로 교체.

---

## 1. 머신 3대 (헷갈리지 말 것)
| 머신 | 역할 | 프롬프트 |
|---|---|---|
| **EC2** | InfraRed 서버·대시보드 | `[ec2-user@ip-10-0-1-225]$` |
| **VM** | 피해자 서버 + 에이전트 | `infra@infrared:~$` |
| **공격자 노트북** | 공격 발사 | cmd/PowerShell (핫스팟 연결) |

## 2. 발표 전 체크리스트
```bash
# EC2: 서버 살아있나
curl -sk https://localhost/healthz                      # → {"status":"ok"}
# VM: 에이전트 도나 + IP 확인
hostname -I                                             # → 172.20.10.4 (바뀌었으면 갱신)
sudo systemctl status infrared-agent --no-pager         # → active (running)
# 공격자 노트북: VM에 닿나
ping 172.20.10.4
```

---

## 3. 데모 시나리오 (막별: 공격자 행동 / 탐지 / 멘트)

| 막 | 공격자 행동 | InfraRed 탐지 | 멘트 |
|---|---|---|---|
| **1 침입** | SSH 비번 반복 시도 | **AUTH-001** 브루트포스(3회/5분) | "백신엔 직원 로그인 실패로 보입니다" |
| **2 침투** | `deploy123`으로 로그인 성공 | **AUTH-004** 실패→성공(크랙) | "수십 번 실패 후 성공 — 정상 아니죠" |
| **3 지속성** | authorized_keys·cron 백도어 | **FIM-001·FIM-003** (해시 변화) ★1~3막 critical 묶음 | "흩어진 행동을 스스로 이어붙입니다" |
| **4 정찰·미끼** | `cat /etc/shadow` | **AUDITD-002** 민감파일 접근 | "정상 사용자는 /etc/shadow 안 읽죠" |
| **5 임팩트** | `/tmp`에서 실행 | **EXEC-001** /tmp 실행 | "악성파일 없이 행동으로 잡힙니다" |
| **6 자동차단** 🎯 | (없음) | iptables로 공격자 IP 차단 → 세션 끊김 | "탐지부터 차단까지 자동. 몇 초였죠?" |

---

## 4. 발표 중 명령어 — 공격자 노트북 (cmd/PowerShell)

**① 침입 + 침투:**
```
ssh deploy@172.20.10.4
```
→ 비번 `deploy123` (그 전에 일부러 몇 번 틀리면 1막 브루트포스 연출)

**침투 후 — deploy 세션 안에서** (sudo 비번도 `deploy123`):
```bash
sudo cat /etc/shadow | head -3                                          # 4막 민감파일
echo 'ssh-rsa AAAA-ATTACKER' | sudo tee -a /root/.ssh/authorized_keys    # 3막 백도어키
echo '* * * * * root bash -i' | sudo tee /etc/cron.d/backdoor            # 3막 cron
cp /bin/sleep /tmp/.x && /tmp/.x 300 &                                   # 5막 /tmp 실행
```
→ **30~60초 뒤** 세션 멈춤 = 6막 자동차단. 새 터미널에서 `ssh deploy@172.20.10.4` → 안 됨.

> 💡 학생 참여형: 학생에게 `ssh deploy@172.20.10.4`를 직접 치게 → "내가 공격했는데 잡혔다" 체험.

**대시보드(https://infrared.kr)에서 보여줄 것:**
1. **인시던트** — 공격 실시간 표시 (AUTH·FIM·AUDITD·EXEC, 출처 IP = 공격자 172.20.10.x)
2. 인시던트 클릭 → **AI 분석**(Claude) 사람말 요약 + 킬체인 + 권장조치
3. **자동대응 로그** — BLOCK_IP 실행 기록
4. **KPI** — 탐지(MTTD)·대응(MTTR) 시간

---

## 5. 네트워크(IP) 바뀌었을 때 — 차단대역 갱신
새 핫스팟이면 그 대역(`ip addr`로 확인)을 차단 허용에 넣어야 6막이 됨. **현재는 172.20.10.0/28 이미 적용됨.**
```bash
# [EC2]
sudo sed -i '/^RESPONSE_DEMO_BLOCK_CIDRS=/d' /opt/infrared/.env
echo 'RESPONSE_DEMO_BLOCK_CIDRS=172.20.10.0/28,192.168.0.0/16' | sudo tee -a /opt/infrared/.env
sudo docker compose -f /opt/infrared/docker-compose.yml up -d --force-recreate ingestion incident-worker detection-worker
sudo docker restart infrared-proxy
# [VM]
sudo sed -i '/^DEMO_BLOCK_CIDRS=/d' /opt/infrared-agent/.env
echo 'DEMO_BLOCK_CIDRS=172.20.10.0/28,192.168.0.0/16' | sudo tee -a /opt/infrared-agent/.env
sudo systemctl restart infrared-agent
```

## 6. 복구 (차단 풀기 / 무대 초기화)
차단되면 공격자(=네 노트북) 접속이 끊김. **VM 콘솔(VMware 창)**에서:
```bash
sudo iptables -D INPUT -s <차단된IP> -j DROP      # 특정 IP 해제
sudo iptables -F INPUT                             # (안 되면) 전체 초기화
# 무대 초기화 (다음 리허설 전)
sudo rm -f /etc/cron.d/backdoor /tmp/.x
sudo truncate -s 0 /root/.ssh/authorized_keys
```

## 7. 자동차단 메커니즘 (Q&A 대비)
```
공격 → VM 에이전트가 로그 읽어 EC2로 전송(출처IP 포함)
→ 백엔드 탐지·상관분석 → critical → _is_safe_ip 판단(172.20.10.x는 demo대역 → 차단OK)
→ block_ip 명령 적재 → 에이전트가 ~30초마다 폴링해서 받음
→ 에이전트가 호스트에서 iptables -I INPUT -s <IP> -j DROP → 공격자 패킷 버려짐 → 세션 사망
```
- 차단 = iptables(DROP). 백엔드는 명령만, **실행은 VM 에이전트(root)**.
- 안전장치: 사설/루프백 기본 보호. demo 토글(172.20.10.0/28)로 **그 핫스팟 대역만** 예외. 루프백(127.x) 항상 보호.

## 8. 핵심 메시지 (마무리)
- "진짜 해커는 바이러스를 안 씁니다. **정상 도구(SSH·cron·cat)**로 들어와요."
- "백신은 시그니처(악성파일)를 보지만, **InfraRed는 행동을 봅니다.**"
- "탐지 → 상관분석 → AI 분석 → **자동 차단**까지, 사람 없이 몇 초 만에."
