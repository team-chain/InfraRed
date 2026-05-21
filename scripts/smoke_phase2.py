"""Phase 2 smoke test — 탐지 룰 + 자동 대응 end-to-end 검증.

audit 결과로 확인된 동작 가능 룰들을 가짜 이벤트로 트리거.
각 시나리오 실행 후 검증 명령어 안내.

사용법 (EC2에서):
  cd /opt/infrared

  # 1. 단일 시나리오
  sudo -E python3 scripts/smoke_phase2.py auth-brute
  sudo -E python3 scripts/smoke_phase2.py web-sqli
  sudo -E python3 scripts/smoke_phase2.py web-admin-scan
  sudo -E python3 scripts/smoke_phase2.py fim       # agent host에서만 동작
  sudo -E python3 scripts/smoke_phase2.py full-chain  # SSH compromise 시나리오

  # 2. 결과 검증
  sudo -E python3 scripts/smoke_phase2.py verify --ip 192.0.2.100

환경:
  .env 파일이 /opt/infrared/.env 또는 ./. env 에 있어야 함.
  JWT_SECRET, TENANT_ID, AGENT_TOKEN 등 사용.

검증 가능한 자동 대응:
  • iptables block (confidence ≥ 0.85, CRITICAL) → 10초 안에 차단
  • Redis deny-list (HIGH 이상) → API 미들웨어 403 즉시
  • Discord/email 알림 (CRITICAL) → 자동 발송
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as urlerror
from urllib import request

# ────────────────────────────────────────────────────────────────────────
# Defaults — .env로 override
# ────────────────────────────────────────────────────────────────────────
ATTACKER_IP = "192.0.2.100"  # TEST-NET-1, RFC 5737 — 실제 라우팅 안 됨
DEFAULT_INGEST_URL = "http://localhost:8000/ingest"


# ────────────────────────────────────────────────────────────────────────
# .env 로딩 + JWT 생성 (send_test_event.py와 동일 패턴)
# ────────────────────────────────────────────────────────────────────────
def load_env(paths: list[Path]) -> None:
    for path in paths:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join([
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ])
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64url(signature)}"


def make_agent_token() -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": os.getenv("AGENT_ID", "agent-001"),
        "tenant_id": os.getenv("TENANT_ID", "company-a"),
        "agent_id": os.getenv("AGENT_ID", "agent-001"),
        "role": "agent",
        "iss": os.getenv("JWT_ISSUER", "infrared"),
        "aud": os.getenv("JWT_AUDIENCE", "infrared-ingest"),
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + 3600,
    }
    secret = os.getenv("JWT_SECRET", "change-me-in-production-please")
    return encode_hs256(payload, secret)


def get_token() -> str:
    env_token = os.getenv("AGENT_TOKEN", "")
    if env_token and not env_token.startswith("replace-with"):
        return env_token
    return make_agent_token()


# ────────────────────────────────────────────────────────────────────────
# 이벤트 전송 유틸
# ────────────────────────────────────────────────────────────────────────
def send_event(envelope: dict, url: str, token: str) -> dict:
    body = json.dumps(envelope).encode("utf-8")
    req = request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urlerror.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code} from {url}: {body[:200]}", file=sys.stderr)
        raise


def make_envelope(
    raw_line: str,
    *,
    raw_source: str = "auth.log",
    event_index: int,
) -> dict:
    tenant_id = os.getenv("TENANT_ID", "company-a")
    agent_id = os.getenv("AGENT_ID", "agent-001")
    asset_id = os.getenv("ASSET_ID", "asset-001")
    eid = f"smoke-{int(time.time())}-{event_index:04d}"
    return {
        "event_id": eid,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "asset_id": asset_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_source": raw_source,
        "raw_line": raw_line,
        "file_inode": "smoke-test",
        "file_offset": event_index,
    }


# ────────────────────────────────────────────────────────────────────────
# 시나리오들
# ────────────────────────────────────────────────────────────────────────
def scenario_auth_brute(url: str, token: str, attacker_ip: str) -> None:
    """AUTH-001 + AUTH-003 트리거 — SSH brute force.

    audit: confidence ~0.90 → 자동 iptables block (10초 이내).
    """
    print(f"\n[1/2] AUTH brute force from {attacker_ip}")
    print(f"  보내는 이벤트: invalid user (AUTH-003) x3 + Failed password (AUTH-001) x10")

    base_ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    host = "demo-host"
    events = []
    # AUTH-003 — invalid user enumeration (2개 이상 트리거)
    for i, user in enumerate(["root", "admin", "oracle"]):
        events.append(
            f"{base_ts} {host} sshd[{1000+i}]: Invalid user {user} from {attacker_ip} port {40000+i}"
        )
    # AUTH-001 — Failed password (3개 이상 트리거, 더 보내서 confidence 높임)
    for i in range(10):
        events.append(
            f"{base_ts} {host} sshd[{2000+i}]: Failed password for root from {attacker_ip} port {41000+i} ssh2"
        )

    sent = 0
    for idx, line in enumerate(events):
        env = make_envelope(line, raw_source="auth.log", event_index=idx)
        try:
            send_event(env, url, token)
            sent += 1
        except Exception as e:
            print(f"  실패: {e}")

    print(f"  ✓ {sent}/{len(events)} 이벤트 전송됨")
    print(f"\n[2/2] 자동 대응 대기 (15초)...")
    time.sleep(15)
    print_verify_commands(attacker_ip)


def scenario_auth_then_success(url: str, token: str, attacker_ip: str) -> None:
    """AUTH-004 트리거 — Failed then success (credential compromise)."""
    print(f"\n[1/2] AUTH failed→success from {attacker_ip}")
    base_ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    host = "demo-host"
    events = []
    for i in range(5):
        events.append(
            f"{base_ts} {host} sshd[{3000+i}]: Failed password for root from {attacker_ip} port {42000+i} ssh2"
        )
    events.append(
        f"{base_ts} {host} sshd[3100]: Accepted password for root from {attacker_ip} port 42100 ssh2"
    )
    for idx, line in enumerate(events):
        env = make_envelope(line, raw_source="auth.log", event_index=idx)
        try:
            send_event(env, url, token)
        except Exception as e:
            print(f"  실패: {e}")
    print(f"  ✓ {len(events)} 이벤트 전송됨 (1 success 포함)")
    print(f"\n[2/2] 자동 대응 + 인시던트 escalation 대기 (15초)...")
    time.sleep(15)
    print_verify_commands(attacker_ip)


def scenario_web_sqli(url: str, token: str, attacker_ip: str) -> None:
    """WEB-005 트리거 — SQL injection in URL."""
    print(f"\n[1/2] WEB SQL injection from {attacker_ip}")
    base_ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    events = [
        f'{attacker_ip} - - [{base_ts}] "GET /api/users?id=1+UNION+SELECT+1,password,3+FROM+users HTTP/1.1" 500 1234 "-" "sqlmap/1.6"',
        f'{attacker_ip} - - [{base_ts}] "GET /search?q=%27+OR+1%3D1-- HTTP/1.1" 200 567 "-" "curl/7.74.0"',
        f'{attacker_ip} - - [{base_ts}] "POST /api/login HTTP/1.1" 401 89 "-" "Mozilla/5.0"',
        f'{attacker_ip} - - [{base_ts}] "GET /admin?page=../../etc/passwd HTTP/1.1" 403 12 "-" "nikto/2.1.6"',
    ]
    for idx, line in enumerate(events):
        env = make_envelope(line, raw_source="nginx", event_index=idx)
        try:
            send_event(env, url, token)
        except Exception as e:
            print(f"  실패: {e}")
    print(f"  ✓ {len(events)} nginx 이벤트 전송 (SQLi + path traversal + admin scan)")
    print(f"\n[2/2] 자동 대응 대기 (15초)...")
    time.sleep(15)
    print_verify_commands(attacker_ip)


def scenario_web_admin_scan(url: str, token: str, attacker_ip: str) -> None:
    """WEB-002 트리거 — 30+ admin path 요청."""
    print(f"\n[1/2] WEB admin scan from {attacker_ip} (35 requests)")
    base_ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    paths = [
        "/admin", "/admin/login", "/wp-admin", "/phpmyadmin", "/manager/html",
        "/.env", "/.git/config", "/server-status", "/admin/users", "/login",
    ]
    sent = 0
    for i in range(35):
        path = paths[i % len(paths)]
        line = f'{attacker_ip} - - [{base_ts}] "GET {path} HTTP/1.1" 404 12 "-" "curl/7.74"'
        env = make_envelope(line, raw_source="nginx", event_index=i)
        try:
            send_event(env, url, token)
            sent += 1
        except Exception:
            pass
    print(f"  ✓ {sent}/35 admin-scan 요청 전송")
    print(f"\n[2/2] 자동 대응 대기 (12초)...")
    time.sleep(12)
    print_verify_commands(attacker_ip)


def scenario_fim(url: str, token: str, attacker_ip: str) -> None:
    """FIM-001 트리거 — authorized_keys 변조 시뮬레이션.

    실제 변조는 agent host에서 root로 직접 해야 함.
    여기는 'agent가 그걸 감지해서 보낸' 이벤트를 직접 주입.
    """
    print(f"\n[1/2] FIM authorized_keys tamper from {attacker_ip}")
    line = json.dumps({
        "type": "fim.alert",
        "rule": "FIM-001",
        "path": "/root/.ssh/authorized_keys",
        "old_hash": "abc123",
        "new_hash": "def456",
        "source_ip": attacker_ip,
        "severity": "critical",
    })
    env = make_envelope(line, raw_source="agent.fim", event_index=0)
    try:
        send_event(env, url, token)
        print("  ✓ FIM 이벤트 전송")
    except Exception as e:
        print(f"  실패: {e}")
    print(f"\n[2/2] 자동 대응 대기 (12초)...")
    time.sleep(12)
    print_verify_commands(attacker_ip)


def scenario_full_chain(url: str, token: str, attacker_ip: str) -> None:
    """SSH compromise scenario — 전체 attack chain.

    audit: AUTH-003 + AUTH-001 + AUTH-004 + FIM-001 → SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE → CRITICAL
    """
    print(f"\n=== Full SSH compromise chain from {attacker_ip} ===")
    print("\n[Step 1] Reconnaissance — AUTH-003 invalid user")
    scenario_auth_brute(url, token, attacker_ip)
    time.sleep(3)
    print("\n[Step 2] Initial access — AUTH-004 failed→success")
    scenario_auth_then_success(url, token, attacker_ip)
    time.sleep(3)
    print("\n[Step 3] Persistence — FIM-001 authorized_keys")
    scenario_fim(url, token, attacker_ip)
    print("\n=== Chain 종료 — Dashboard에서 'SSH compromise' 시나리오 incident CRITICAL 확인 ===")


# ────────────────────────────────────────────────────────────────────────
# 검증 명령어 출력
# ────────────────────────────────────────────────────────────────────────
def print_verify_commands(attacker_ip: str) -> None:
    print(f"""
╭─ 검증 명령어 (별도 셸에서 sudo로 실행) ─────────────────────────╮
│                                                                  │
│ # 1. iptables에 차단 rule 들어왔는지                              │
│   sudo iptables -L INPUT -n --line-numbers | grep {attacker_ip}    │
│                                                                  │
│ # 2. 자동 대응 액션 로그 (jsonl append-only)                      │
│   sudo tail -20 /var/log/infrared/iptables_actions.jsonl 2>/dev/null │
│   또는 agent container 안:                                        │
│   sudo docker exec infrared-agent cat /var/log/infrared/iptables_actions.jsonl │
│                                                                  │
│ # 3. 인시던트 DB 직접 조회                                        │
│   sudo docker exec infrared-ingestion python -c "                 │
│ import asyncio, asyncpg, os                                       │
│ async def f():                                                    │
│     url = os.getenv('DATABASE_URL').replace('postgresql+asyncpg://','postgresql://').split('?')[0] │
│     c = await asyncpg.connect(url)                                │
│     rows = await c.fetch(\\\"SELECT incident_id, severity, mitre_technique, source_ip, status FROM incidents WHERE source_ip='{attacker_ip}' ORDER BY created_at DESC LIMIT 5\\\") │
│     for r in rows: print(dict(r))                                 │
│     await c.close()                                               │
│ asyncio.run(f())"                                                 │
│                                                                  │
│ # 4. Dashboard에서:                                               │
│   https://app.infrared.kr → Incidents 탭 → source_ip={attacker_ip}   │
│                                                                  │
│ # 5. ingestion log에서 자동대응 분기                              │
│   sudo docker logs infrared-ingestion --tail 100 2>&1 | grep -E "autoresponse|block_ip|denylist" │
│                                                                  │
╰──────────────────────────────────────────────────────────────────╯
""")


def verify_only(attacker_ip: str) -> None:
    """이벤트 전송 없이 검증 명령어만 실행/출력."""
    print(f"\n=== {attacker_ip} 차단 상태 검증 ===\n")

    print("[1] iptables rule:")
    try:
        out = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, check=False,
        )
        matched = [l for l in out.stdout.splitlines() if attacker_ip in l]
        if matched:
            for l in matched:
                print(f"  ✓ {l}")
        else:
            print(f"  ✗ {attacker_ip} 차단 rule 없음")
    except FileNotFoundError:
        print("  (iptables 명령 없음 — root + iptables 필요)")
    except Exception as e:
        print(f"  실행 오류: {e}")

    print("\n[2] /var/log/infrared/iptables_actions.jsonl (last 5):")
    log_path = Path("/var/log/infrared/iptables_actions.jsonl")
    if log_path.exists():
        for line in log_path.read_text().splitlines()[-5:]:
            print(f"  {line}")
    else:
        print(f"  (파일 없음: {log_path} — agent 컨테이너 내부일 수 있음)")

    print(f"\n[3] Dashboard 확인:")
    print(f"  https://app.infrared.kr → Incidents → source_ip={attacker_ip}")


# ────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "auth-brute":       scenario_auth_brute,
    "auth-fts":         scenario_auth_then_success,
    "web-sqli":         scenario_web_sqli,
    "web-admin-scan":   scenario_web_admin_scan,
    "fim":              scenario_fim,
    "full-chain":       scenario_full_chain,
}


def main() -> int:
    load_env([Path("/opt/infrared/.env"), Path(".env")])

    parser = argparse.ArgumentParser(description="InfraRed Phase 2 smoke test")
    parser.add_argument("scenario", nargs="?", choices=list(SCENARIOS) + ["verify", "list"], default="list")
    parser.add_argument("--url", default=os.getenv("INGEST_URL", DEFAULT_INGEST_URL))
    parser.add_argument("--ip", default=ATTACKER_IP, help="가짜 공격자 IP (default: TEST-NET-1)")
    args = parser.parse_args()

    if args.scenario == "list":
        print("Available scenarios:")
        for name, fn in SCENARIOS.items():
            doc = (fn.__doc__ or "").split("\n", 1)[0].strip()
            print(f"  {name:<18}  {doc}")
        print("  verify             검증만 (iptables / 로그 / dashboard URL)")
        return 0

    if args.scenario == "verify":
        verify_only(args.ip)
        return 0

    token = get_token()
    print(f"Target: {args.url}")
    print(f"Tenant: {os.getenv('TENANT_ID', 'company-a')} · Token: {token[:32]}...")
    print(f"Attacker IP (가짜): {args.ip}")
    print(f"Scenario: {args.scenario}")

    fn = SCENARIOS[args.scenario]
    fn(args.url, token, args.ip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
