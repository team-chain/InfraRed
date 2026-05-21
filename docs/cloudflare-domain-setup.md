# infrared.kr 도메인 연결 가이드 (Cloudflare 무료 플랜)

작성일: 2026-05-20
대상: 처음 도메인 연결 작업을 진행하는 운영자
목표 환경: 가비아 등록 도메인 + Cloudflare DNS/HTTPS + AWS EC2 단일 인스턴스

---

## 0. 이 가이드가 끝나면 어떻게 되나

| 항목 | 변경 전 | 변경 후 |
|---|---|---|
| 접속 주소 | `http://3.39.58.44:3000` | `https://app.infrared.kr` |
| 백엔드 API | `http://3.39.58.44:8000` | `https://api.infrared.kr` |
| 루트 도메인 | (안 씀) | `https://infrared.kr` → app로 리다이렉트 |
| HTTPS 인증서 | 없음 | Cloudflare 자동 발급/갱신 (영구 무료) |
| DDoS 방어 | 없음 | Cloudflare 기본 무료 |
| Origin IP 노출 | 그대로 (3.39.58.44 직접 노출) | Cloudflare 뒤로 숨김 |

추가 비용: **0원**. 인프라 변경 없이 도메인·DNS·HTTPS 한 번에.

---

## 1. 전체 작업 순서 한눈에

작업은 7단계로 나뉘고, 일부는 웹 클릭, 일부는 EC2/코드 작업입니다.

| 단계 | 내용 | 작업 장소 | 예상 시간 |
|---|---|---|---|
| 1 | Cloudflare 가입 + infrared.kr 등록 | cloudflare.com | 5분 |
| 2 | 가비아 nameserver를 Cloudflare로 변경 | my.gabia.com | 5분 + 전파 대기 |
| 3 | Cloudflare DNS 레코드 + SSL 모드 | cloudflare.com | 10분 |
| 4 | EC2에 Nginx reverse proxy 추가 | EC2 SSH | 20분 |
| 5 | 백엔드 CORS / 프론트엔드 API_BASE 갱신 | 로컬 코드 | 10분 |
| 6 | 이미지 빌드·푸시·배포·검증 | 로컬 + EC2 | 15분 |
| 7 | EC2 보안그룹 Cloudflare IP 화이트리스트 | AWS Console | 10분 |

총 소요 시간: 1~2시간 (DNS 전파 대기 제외)
가장 오래 걸리는 건 2단계 nameserver 전파 — 보통 10분~몇 시간, 드물게 24시간.

---

## 2. 사전 준비물 체크리스트

- [ ] 가비아 계정 로그인 가능 (infrared.kr 소유자 계정)
- [ ] AWS Console 로그인 가능 (보안그룹 수정 권한)
- [ ] EC2(3.39.58.44) SSH 접근 가능
- [ ] 로컬 PowerShell + `C:\InfraRed` 작업 환경
- [ ] 새로 만들 이메일 (Cloudflare 가입용 — 회사용 이메일 권장)

---

## 3. Phase 1 — Cloudflare 가입 + infrared.kr 등록

### 3.1 회원가입

1. 브라우저에서 https://dash.cloudflare.com/sign-up 접속
2. 이메일·비밀번호 입력 → **Create Account**
3. 이메일 확인 메일이 오면 인증 링크 클릭

### 3.2 도메인 추가

1. 대시보드 좌상단 **Add a Site** 클릭
2. 도메인 입력란에 `infrared.kr` 입력 → **Continue**
3. 플랜 선택 화면이 나옴 — 화면 맨 아래로 스크롤
4. **Free $0/month** 선택 → **Continue**
5. Cloudflare가 가비아의 기존 DNS 레코드를 가져오려고 시도 — 보통 비어있거나 가비아 기본 레코드만 있을 거예요. 그냥 **Continue**

### 3.3 Cloudflare nameserver 받기

다음 화면에 이런 메시지가 나옵니다:

> "Change your nameservers to activate Cloudflare on your domain"
>
> `xxxx.ns.cloudflare.com`
> `yyyy.ns.cloudflare.com`

이 두 nameserver 값을 **복사**해두세요. 사람마다 값이 다릅니다.

화면은 닫지 말고 그대로 두세요. 가비아에서 변경 후 이 화면에서 **Check nameservers** 버튼을 눌러야 합니다.

---

## 4. Phase 2 — 가비아 nameserver를 Cloudflare로 변경

### 4.1 가비아 도메인 관리 진입

1. https://my.gabia.com 로그인
2. 상단 메뉴 **My가비아** → **도메인 통합관리** (또는 **도메인 → 도메인 관리**)
3. `infrared.kr` 행 우측에 **관리** 버튼 클릭

### 4.2 nameserver 변경

1. 좌측 메뉴 **네임서버 설정** 클릭 (혹은 상단 탭에 있을 수도 있음)
2. "1차 네임서버"·"2차 네임서버" 입력 칸이 보여요. 기본값은 보통 `ns.gabia.co.kr` 같은 가비아 자체 값.
3. 1차 칸 값을 지우고 → Cloudflare가 알려준 첫 번째 nameserver 입력 (예: `xxxx.ns.cloudflare.com`)
4. 2차 칸 값을 지우고 → 두 번째 nameserver 입력 (예: `yyyy.ns.cloudflare.com`)
5. 3차·4차 네임서버 칸이 있으면 비워두기
6. **저장** 또는 **변경** 클릭
7. 보안 인증(SMS·이메일) 요구하면 그대로 진행
8. "네임서버 변경이 완료되었습니다" 메시지 확인

### 4.3 전파 대기

DNS 전파는 보통 10분~몇 시간 걸려요. 길게는 24시간.

전파 확인하는 방법:

**방법 A — Cloudflare 화면**
3.3에서 열어둔 Cloudflare 화면에서 **Check nameservers** 클릭. "Pending"이 "Active"로 바뀌면 완료.

**방법 B — 명령어 (PowerShell 또는 EC2)**
```bash
nslookup -type=NS infrared.kr
```
결과에 `xxxx.ns.cloudflare.com`이 나오면 전파 완료.

**방법 C — 웹 도구**
https://www.whatsmydns.net 에서 `infrared.kr` 입력, type=NS 선택. 전 세계 서버에서 Cloudflare nameserver가 보이면 완료.

> 💡 **전파 안 됐다고 패닉 금지** — 가비아는 변경 즉시 자기 서버에는 반영하지만 전 세계 DNS 캐시 갱신은 시간 걸려요. 30분 정도 기다린 후 다시 확인.

전파가 완료되면 Cloudflare 대시보드에서 "Great news! Cloudflare is now protecting your site" 메시지가 떠요. **Done**.

---

## 5. Phase 3 — Cloudflare DNS 레코드 + SSL 모드 설정

### 5.1 DNS 레코드 추가

1. Cloudflare 대시보드 → `infrared.kr` 클릭
2. 좌측 메뉴 **DNS** → **Records**
3. **Add record** 클릭 → 아래 표 그대로 3개 추가

| Type | Name | Content (IPv4) | Proxy status | TTL |
|---|---|---|---|---|
| A | `@` | `3.39.58.44` | Proxied (주황 구름) | Auto |
| A | `app` | `3.39.58.44` | Proxied (주황 구름) | Auto |
| A | `api` | `3.39.58.44` | Proxied (주황 구름) | Auto |

- `@`는 루트 도메인(infrared.kr)을 의미
- **Proxied(주황 구름)** 상태가 핵심 — DNS만 위임이 아니라 Cloudflare 프록시 사용. 회색 구름이면 HTTPS·DDoS 보호 안 됨.

### 5.2 SSL/TLS 모드 설정

1. 좌측 메뉴 **SSL/TLS** → **Overview**
2. SSL/TLS encryption mode를 **Full (strict)** 로 변경
3. **Full (strict)** 이 회색 처리(unavailable)면 일단 **Full** 선택 → Origin Certificate 발급 후 strict로 변경

### 5.3 Cloudflare Origin Certificate 발급 (EC2에서 사용할 인증서)

1. 좌측 메뉴 **SSL/TLS** → **Origin Server**
2. **Create Certificate** 클릭
3. 옵션 그대로 둠 (Let Cloudflare generate key, RSA 2048, 15 years)
4. Hostnames에 자동으로 `*.infrared.kr`, `infrared.kr` 들어가 있을 거예요. 맞으면 **Create**
5. 다음 화면에 **Origin Certificate**와 **Private Key** 두 개가 나옴.
6. 이 화면은 **딱 한 번만 보여줘요** — 둘 다 복사해서 텍스트 파일로 저장해두세요.

저장 방법 (로컬 PowerShell):
```powershell
mkdir C:\InfraRed\nginx\certs -Force
# 메모장 등으로 아래 두 파일 만들고 Cloudflare 화면 내용 그대로 붙여넣기
# C:\InfraRed\nginx\certs\origin.pem  ← Origin Certificate 전체 내용
# C:\InfraRed\nginx\certs\origin.key  ← Private Key 전체 내용
```

> ⚠️ **이 두 파일은 절대 git에 커밋하지 마세요**. `.gitignore`에 `nginx/certs/` 추가.

### 5.4 Always Use HTTPS 켜기

1. **SSL/TLS** → **Edge Certificates**
2. **Always Use HTTPS** 토글 ON
3. **Automatic HTTPS Rewrites** 토글 ON

---

## 6. Phase 4 — EC2에 Nginx reverse proxy 추가

목표 구조:
```
사용자 브라우저
   ↓ HTTPS
Cloudflare
   ↓ HTTPS (Origin Cert 검증)
EC2 Nginx :443
   ├─ Host: app.infrared.kr → frontend:3000
   ├─ Host: api.infrared.kr → ingestion:8000
   └─ Host: infrared.kr     → 301 redirect to app.infrared.kr
```

### 6.1 인증서를 EC2로 복사

로컬 PowerShell에서:
```powershell
# scp 또는 보안 복사
scp -i C:\InfraRed\infrared-key.pem C:\InfraRed\nginx\certs\origin.pem ec2-user@3.39.58.44:/tmp/
scp -i C:\InfraRed\infrared-key.pem C:\InfraRed\nginx\certs\origin.key ec2-user@3.39.58.44:/tmp/
```

EC2 SSH에서:
```bash
sudo mkdir -p /opt/infrared/nginx/certs
sudo mv /tmp/origin.pem /opt/infrared/nginx/certs/
sudo mv /tmp/origin.key /opt/infrared/nginx/certs/
sudo chmod 600 /opt/infrared/nginx/certs/origin.key
sudo chmod 644 /opt/infrared/nginx/certs/origin.pem
```

### 6.2 nginx.conf 작성

EC2에서:
```bash
sudo tee /opt/infrared/nginx/nginx.conf > /dev/null <<'EOF'
worker_processes auto;
events { worker_connections 1024; }

http {
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 50m;

    # Cloudflare 실제 클라이언트 IP 복원
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    real_ip_header CF-Connecting-IP;

    # HTTP → HTTPS 강제 (Cloudflare가 이미 처리하지만 안전망)
    server {
        listen 80;
        server_name infrared.kr app.infrared.kr api.infrared.kr;
        return 301 https://$host$request_uri;
    }

    # app.infrared.kr → frontend:3000
    server {
        listen 443 ssl;
        server_name app.infrared.kr;

        ssl_certificate     /etc/nginx/certs/origin.pem;
        ssl_certificate_key /etc/nginx/certs/origin.key;
        ssl_protocols       TLSv1.2 TLSv1.3;

        location / {
            proxy_pass http://frontend:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }

    # api.infrared.kr → ingestion:8000
    server {
        listen 443 ssl;
        server_name api.infrared.kr;

        ssl_certificate     /etc/nginx/certs/origin.pem;
        ssl_certificate_key /etc/nginx/certs/origin.key;
        ssl_protocols       TLSv1.2 TLSv1.3;

        location / {
            proxy_pass http://ingestion:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_read_timeout 300s;
        }

        # SSE 스트림 엔드포인트는 버퍼링 끄기
        location /events/stream {
            proxy_pass http://ingestion:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_buffering off;
            proxy_cache off;
            proxy_read_timeout 24h;
        }
    }

    # 루트 infrared.kr → app으로 301
    server {
        listen 443 ssl;
        server_name infrared.kr;

        ssl_certificate     /etc/nginx/certs/origin.pem;
        ssl_certificate_key /etc/nginx/certs/origin.key;

        return 301 https://app.infrared.kr$request_uri;
    }
}
EOF
```

### 6.3 docker-compose.yml에 nginx 서비스 추가

EC2에서:
```bash
sudo nano /opt/infrared/docker-compose.yml
```

`services:` 아래 적당한 위치(frontend 옆이 깔끔)에 다음 블록 추가:

```yaml
  nginx:
    image: nginx:1.27-alpine
    container_name: infrared-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/infrared/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/infrared/nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - frontend
      - ingestion
```

저장(Ctrl+O, Enter, Ctrl+X).

### 6.4 nginx 컨테이너 띄우기

```bash
cd /opt/infrared
docker compose up -d nginx
docker compose ps nginx
docker compose logs nginx --tail 20
```

기대 결과: `nginx ... Up`, 로그에 에러 없음.

에러가 나면 보통:
- 인증서 파일 경로 오타
- nginx.conf 문법 오류
- 80/443 포트가 다른 프로세스에 점유됨 (`sudo lsof -i :80`로 확인)

---

## 7. Phase 5 — 백엔드 CORS / 프론트엔드 API_BASE 갱신

### 7.1 백엔드 CORS allowed origins 추가

로컬 PowerShell:
```powershell
cd C:\InfraRed
```

`backend/app/main.py` 또는 `backend/app/config.py`에서 CORS allow_origins 설정 찾기:
```python
# 예시 — 실제 코드 위치는 다를 수 있음
app.add_middleware(
    CORSMiddleware,
    allow_origins=[...],
    ...
)
```

`allow_origins` 리스트에 다음 추가:
```python
"https://app.infrared.kr",
"https://infrared.kr",
```

또는 환경변수 기반이면 `/opt/infrared/.env`에서:
```bash
CORS_ALLOWED_ORIGINS=https://app.infrared.kr,https://infrared.kr,http://localhost:3000
```

### 7.2 프론트엔드 API_BASE 갱신

`C:\InfraRed\frontend\src\lib\api.ts` (또는 비슷한 파일)에서 API_BASE 찾기:
```typescript
const API_BASE = import.meta.env.VITE_API_BASE || "http://3.39.58.44:8000";
```

EC2의 frontend 컨테이너가 받는 환경변수에서 VITE_API_BASE를 새 값으로:

`/opt/infrared/.env`에 추가:
```bash
VITE_API_BASE=https://api.infrared.kr
```

> ⚠️ **Vite 빌드 시점 변수** — VITE_*는 빌드할 때 코드에 박혀 들어가요. EC2에서 .env만 바꿔도 안 되고, 이미지 빌드 시점에 들어가야 해요. frontend Dockerfile이 빌드 단계에서 .env를 읽는지 확인하거나, 런타임에 fetch하는 구조면 그대로 OK. 보통은 빌드 시점이라 이미지 재빌드 필요.

만약 런타임 설정으로 바꾸고 싶다면 `frontend/public/config.js` 같은 파일에서 `window.__CONFIG__.API_BASE`를 읽는 패턴으로 리팩터링 가능 — 이건 별도 작업.

### 7.3 (선택) ALLOWED_HOSTS / TRUSTED_ORIGINS

백엔드에 TrustedHostMiddleware나 CSRF 설정이 있으면 거기도 새 호스트 추가:
```python
allowed_hosts = ["api.infrared.kr", "localhost", "127.0.0.1"]
```

---

## 8. Phase 6 — 빌드 / 푸시 / 배포 / 검증

### 8.1 로컬 빌드·푸시
```powershell
cd C:\InfraRed
.\scripts\deploy.ps1 -PushOnly
```

### 8.2 EC2 pull·재기동
```bash
cd /opt/infrared
docker compose pull
docker compose up -d
docker compose ps
```

### 8.3 검증

**A. nginx → frontend/backend가 정상인가**
```bash
# EC2 내부에서 Host 헤더 지정해서 nginx에 직접 호출
curl -k -H "Host: app.infrared.kr" https://localhost/ | head -5
curl -k -H "Host: api.infrared.kr" https://localhost/healthz
```

**B. Cloudflare → EC2 통신이 되는가**
```bash
# 외부에서 도메인으로
curl -I https://app.infrared.kr
curl -I https://api.infrared.kr/healthz
```
기대: `HTTP/2 200` 또는 `HTTP/2 401`. `cf-ray:` 헤더가 보이면 Cloudflare를 거쳐서 응답 옴.

**C. 브라우저에서 실제 사용**
- 시크릿 창으로 https://app.infrared.kr 접속
- 자물쇠 아이콘이 잠긴 상태(HTTPS 정상)
- 로그인 → Sigma Marketplace / Settings / Members 페이지 정상 동작
- DevTools Network 탭에서 `https://api.infrared.kr/...` 호출 200/401(인증)

---

## 9. Phase 7 — Origin IP 보호 (보안그룹)

이 단계가 가장 중요해요. Cloudflare를 우회해서 EC2 IP로 직접 공격하는 걸 막습니다.

### 9.1 AWS Console에서

1. AWS Console → EC2 → 인스턴스 → 해당 인스턴스 클릭
2. 우측 하단 **Security** 탭 → 연결된 Security Group 클릭
3. **Inbound rules** → **Edit inbound rules**

### 9.2 규칙 재정의

기존 규칙 점검:
- ❌ **80** 포트: anywhere(0.0.0.0/0) → Cloudflare IP 대역으로 제한
- ❌ **443** 포트: anywhere → Cloudflare IP 대역으로 제한
- ❌ **3000** 포트: 외부 노출 → **삭제** (이제 nginx가 처리)
- ❌ **8000** 포트: 외부 노출 → **삭제**
- ✅ **22** 포트: 본인 IP만 (이미 그럴 거예요)

Cloudflare IP 대역 (2026년 기준, 최신 목록은 https://www.cloudflare.com/ips/):
```
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

15개 대역을 80/443 각각에 추가하는 게 번거로워요. 대안:
- AWS 매니지드 prefix list 사용 (Cloudflare가 제공하지는 않음, 본인 prefix list 만들기)
- 또는 Terraform/스크립트로 자동화

빠른 방법 — 일단 80/443은 0.0.0.0/0 유지하고, **3000/8000만 제거**해도 큰 이득. 나중에 IP 제한 추가.

### 9.3 검증

```bash
# EC2 외부에서 직접 IP로 시도 → 차단되어야 함
curl -v --connect-timeout 5 http://3.39.58.44:3000
curl -v --connect-timeout 5 http://3.39.58.44:8000
# Connection refused 또는 timeout 기대

# 도메인 경유는 정상
curl -I https://app.infrared.kr
```

---

## 10. 검증 체크리스트 (모두 통과해야 완료)

- [ ] https://app.infrared.kr 자물쇠 잠긴 상태로 접속됨
- [ ] 브라우저 주소창에 `Not Secure` 표시 없음
- [ ] 로그인 가능
- [ ] DevTools Network에서 API 호출이 `https://api.infrared.kr/...`로 나감
- [ ] CORS 에러 없음
- [ ] `https://infrared.kr` 접속 시 `https://app.infrared.kr`로 자동 이동
- [ ] `http://app.infrared.kr` (HTTP) 접속 시 HTTPS로 자동 이동
- [ ] `http://3.39.58.44:3000`은 더 이상 접근 안 됨 (보안그룹)
- [ ] Cloudflare 대시보드 Overview에 트래픽 그래프 데이터 흐름

---

## 11. 트러블슈팅

### 11.1 가비아 nameserver 변경 후 도메인이 안 풀림

원인: DNS 전파 시간차. 짧게는 10분, 길게는 24시간.

확인:
```bash
nslookup -type=NS infrared.kr 8.8.8.8
```
결과에 cloudflare ns가 보일 때까지 대기.

### 11.2 Cloudflare 대시보드가 계속 "Pending"

원인: 가비아 측 변경이 안 됐거나 전파 안 됨.

해결:
- 가비아 마이페이지에서 nameserver가 정말 cloudflare 값으로 저장됐는지 재확인
- 시간 더 기다리기
- Cloudflare 대시보드에서 **Check nameservers** 재클릭

### 11.3 522 Connection Timed Out (Cloudflare 에러)

원인: Cloudflare는 정상, EC2에 도달 못 함. nginx가 안 떠있거나 보안그룹이 막음.

확인:
```bash
docker compose ps nginx
sudo netstat -tlnp | grep -E ':(80|443)\s'
```
EC2 보안그룹 80/443 인바운드 허용 확인.

### 11.4 525 SSL Handshake Failed

원인: Cloudflare SSL mode가 Full(strict)인데 EC2 측 인증서가 self-signed이거나 만료.

해결:
- Cloudflare → SSL/TLS → Origin Server에서 인증서 다시 발급
- EC2의 `/opt/infrared/nginx/certs/origin.pem` 내용 확인 (BEGIN/END CERTIFICATE 정상인지)
- nginx 재기동: `docker compose restart nginx`

### 11.5 CORS 에러

증상: 브라우저 콘솔에 "Access to fetch at '...' has been blocked by CORS policy"

원인: 백엔드 CORS allow_origins에 `https://app.infrared.kr` 누락.

해결: 7.1 참고하여 추가 후 재배포.

### 11.6 무한 리다이렉트 (ERR_TOO_MANY_REDIRECTS)

원인: Cloudflare SSL mode가 **Flexible**이면 Cloudflare→EC2는 HTTP인데 nginx가 HTTPS로 강제 리다이렉트 → 루프.

해결: Cloudflare SSL mode를 **Full** 또는 **Full (strict)** 로 변경.

### 11.7 frontend가 옛 API_BASE를 가리킴

증상: 도메인으로 접속했는데도 콘솔 호출이 `http://3.39.58.44:8000`로 감.

원인: Vite는 빌드 시점에 환경변수를 코드에 박아넣음. 이미지 재빌드 안 했거나, 브라우저 캐시.

해결:
- 7.2의 VITE_API_BASE를 .env에 넣고 이미지 재빌드
- 시크릿 창에서 다시 접속
- 또는 frontend Dockerfile에 빌드 인자로 명시

### 11.8 SSE (이벤트 스트림) 끊김

원인: nginx가 SSE를 버퍼링하거나 짧은 timeout으로 끊음.

해결: 6.2의 nginx.conf 안 `/events/stream` 블록 확인 — `proxy_buffering off` + `proxy_read_timeout 24h` 필수.

---

## 12. 운영 팁

### 12.1 인증서 갱신
- Cloudflare Origin Certificate는 **15년 유효** — 사실상 갱신 신경 안 써도 됨
- Cloudflare Edge Certificate (사용자 ↔ Cloudflare)는 Cloudflare가 자동 갱신
- nginx 재시작이나 인증서 교체 불필요

### 12.2 트래픽 모니터링
- Cloudflare → 대시보드 → Analytics: 일별 요청 수, 차단된 위협, 상위 국가
- 무료 플랜도 기본 그래프 제공

### 12.3 WAF (방화벽) 규칙 추가
- Security → WAF → Custom rules
- 무료 플랜은 5개까지
- 예시: 특정 국가 차단, /admin 경로 IP 제한, User-Agent 차단

### 12.4 캐싱 설정
- API 응답은 캐싱하면 안 됨 — 기본값이 안전한 쪽으로 잡혀있어요
- 정적 자원(이미지·CSS·JS)은 Cloudflare가 자동 캐싱
- 캐시 무효화: Caching → Configuration → **Purge Everything**

### 12.5 백업
- Cloudflare 설정 자체는 별도 백업 불필요 (대시보드에 다 저장됨)
- 단, Origin Certificate의 Private Key는 분실 시 재발급해야 함 (EC2 nginx 인증서도 같이 교체)

### 12.6 무료 플랜 제한 알아두기
- 도메인 1개당 무료 (현재 충분)
- WAF custom rules: 5개
- Page Rules: 3개
- Image Resizing/Polish 등 일부 유료
- Argo Smart Routing: 유료
- 트래픽 자체는 무제한이지만 비정상적으로 폭증 시 Cloudflare가 유료 플랜 권유

---

## 13. 롤백 방법 (잘못됐을 때 되돌리기)

만약 도메인 변경 후 서비스에 문제가 생기면:

### 13.1 임시 — Cloudflare proxy만 끄기

Cloudflare DNS에서 각 레코드의 주황 구름 → **회색 구름**으로 변경.
즉시 DNS만 위임, HTTPS·프록시 비활성. EC2 직접 접근 복귀.

### 13.2 완전 롤백 — nameserver를 가비아로 되돌리기

1. 가비아 → 네임서버 설정 → 가비아 기본값으로 복구
   - `ns.gabia.co.kr`
   - `ns1.gabia.co.kr`
2. 24시간 정도 전파 대기
3. 브라우저로 다시 IP+포트 형태로 접근 (예전 상태)

### 13.3 nginx만 끄기 (EC2 측만)

```bash
cd /opt/infrared
docker compose stop nginx
docker compose rm -f nginx
# docker-compose.yml에서 nginx 서비스 블록 주석/삭제
```
이러면 EC2의 80/443은 비고, 3000/8000으로 직접 접근 가능. 보안그룹 80/443 닫고 3000/8000 다시 열기.

---

## 14. 자주 묻는 질문

**Q. Cloudflare 무료 플랜 트래픽 제한은?**
A. 트래픽 자체에는 제한이 없습니다. 다만 비정상적으로 큰 트래픽이면 Cloudflare가 유료 플랜을 권유할 수 있어요. 일반 SaaS MVP 트래픽은 충분히 무료로 커버 가능.

**Q. Cloudflare 가입 안 하고 가비아 DNS만으로 HTTPS 가능?**
A. 가능합니다. 그 경우 Nginx + Let's Encrypt 방식 사용. 다만 DDoS 방어·Origin IP 보호 등 부가 기능 없음.

**Q. 도메인을 가비아에서 다른 곳으로 옮기지 않아도 되나요?**
A. 네, **도메인 소유는 가비아 그대로**, **DNS 관리만 Cloudflare에 위임**하는 구조입니다. nameserver만 바꾸는 거라 도메인 자체는 가비아에 남아있어요.

**Q. 나중에 Cloudflare 떠나면?**
A. 가비아에서 nameserver를 원래 가비아 값으로 되돌리면 Cloudflare에서 빠져요. 락인 없음.

**Q. infrared.kr 같은 .kr 도메인은 Cloudflare에서 잘 동작?**
A. 네, .kr·.co.kr 모두 정상 지원됩니다. 다만 가비아에서 nameserver 변경 시 한국인터넷진흥원(KISA) 추가 인증을 요구할 수 있어요 — 화면 안내 따라 진행하면 됩니다.

**Q. Origin Certificate Private Key를 분실하면?**
A. Cloudflare → SSL/TLS → Origin Server에서 기존 인증서 폐기(Revoke) → 새로 발급. EC2의 nginx 인증서도 새 값으로 교체 후 nginx 재기동.

---

## 15. 다음 단계 (이 가이드 완료 후)

이 가이드가 끝나면 도메인·HTTPS는 완료. 그 다음에 권장 작업:

1. **셀프 회원가입 흐름 구현** — 외부 고객이 직접 가입할 수 있게
2. **랜딩 페이지** — `infrared.kr`을 단순 리다이렉트가 아니라 제품 소개 페이지로
3. **Stripe 결제 연동 검증** — 실제 구독 → 활성화 흐름
4. **에이전트 인스톨러** — 고객 endpoint 배포용 패키지
5. **mTLS 활성화** — agent ↔ server 통신 인증 강화
6. **상태 페이지** — `status.infrared.kr` (uptime/장애 공지)
7. **운영 모니터링** — CloudWatch, 알람, 온콜 체계

---

작성: 운영팀
질문/오류 발견 시 가이드 업데이트 권장
