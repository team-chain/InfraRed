#!/usr/bin/env python3
# =============================================================================
#  InfraRed 핸즈온 — 참가자용 공격 런처 (학생/교수가 직접 실행)
# -----------------------------------------------------------------------------
#  설정 불필요. 실행 중인 InfraRed 로컬 스택(run-local.sh)에 공격 이벤트를
#  실제 파이프라인(debug/replay-events)으로 주입하고, 무엇이 탐지될지 안내한다.
#  표준 라이브러리만 사용 (별도 설치 X).
#
#  사용법:  python3 try_attack.py
#           python3 try_attack.py --api http://localhost:8000
#
#  ⚠️ ENV=local/dev 에서만 debug API가 열린다. 운영(prod)에선 동작 안 함(의도).
# =============================================================================
from __future__ import annotations
import argparse, json, sys, time, urllib.request, urllib.error
from pathlib import Path

# 픽스처 위치: demo/ 기준 ../backend/tests/detection/fixtures/scenarios
FIX = Path(__file__).resolve().parent.parent / "backend" / "tests" / "detection" / "fixtures" / "scenarios"

C = {"g": "\033[1;32m", "y": "\033[1;33m", "r": "\033[1;31m", "c": "\033[1;36m", "0": "\033[0m"}
def cprint(col, *a): print(C[col] + " ".join(str(x) for x in a) + C["0"])

# 메뉴: (제목, 픽스처파일, 설명, 기대 탐지)
SCENARIOS = [
    ("SSH 브루트포스",            "auth_bruteforce.jsonl",
     "한 IP가 SSH 비밀번호를 반복 시도", "AUTH-001 (HIGH 인시던트)"),
    ("SSH 계정탈취 + 지속성",      "ssh_compromise_with_persistence.jsonl",
     "브루트포스→성공→authorized_keys 변조→정찰", "AUTH-004 + PERSIST-001 → CRITICAL 체인 시나리오"),
    ("웹쉘 침투",                  "webshell_infiltration.jsonl",
     "허니팟 탐색→웹쉘 업로드→원격코드실행", "WEB-HNY-001 + WEB-001 + EXEC-002 → WEBSHELL_INFILTRATION"),
    ("권한 상승",                  "privilege_escalation.jsonl",
     "로그인 성공→sudoers/passwd 변조", "PRIVILEGE_ESCALATION 시나리오"),
    ("랜섬웨어 전조",              "ransomware_precursor.jsonl",
     "의심 프로세스→대량 파일 변조→랜섬노트", "EXEC-003 → RANSOMWARE_PRECURSOR"),
    ("측면 이동",                  "lateral_movement.jsonl",
     "탈취 호스트에서 다른 내부 호스트로 확산", "LATERAL_MOVEMENT 시나리오"),
]

def _post(url: str, payload: dict, token: str | None = None) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())

def login(api: str) -> str:
    body = {"tenant_id": "company-a", "email": "admin@infrared.local", "password": "infrared123"}
    try:
        res = _post(f"{api}/auth/login", body)
        return res["access_token"]
    except urllib.error.URLError as e:
        cprint("r", f"[x] 백엔드에 연결 실패: {e}")
        cprint("y", "    run-local.sh 로 스택이 떠 있는지, --api 주소가 맞는지 확인하세요.")
        sys.exit(1)
    except Exception as e:
        cprint("r", f"[x] 로그인 실패: {e}")
        sys.exit(1)

def to_event(line: dict) -> dict:
    """픽스처 한 줄 → ReplayEventItem 스키마로 변환."""
    known = {"event_type", "source_ip", "user", "asset_id", "timestamp"}
    item = {
        "event_type": line.get("event_type", "unknown"),
        "asset_id": line.get("asset_id", "asset-demo-01"),
    }
    for k in ("source_ip", "user", "timestamp"):
        if line.get(k) is not None:
            item[k] = line[k]
    item["data"] = {k: v for k, v in line.items() if k not in known}
    return item

def run_scenario(api: str, token: str, fixture: str, expect: str) -> None:
    path = FIX / fixture
    if not path.exists():
        cprint("r", f"[x] 픽스처 없음: {path}")
        return
    events = [to_event(json.loads(l)) for l in path.read_text().splitlines() if l.strip()]
    cprint("c", f"\n→ {len(events)}개 공격 이벤트를 InfraRed로 주입합니다...")
    cprint("y", "  지금 대시보드(http://localhost:3000)를 보세요!\n")
    # 단계가 보이도록 몇 개씩 끊어서 주입
    chunk = 3
    for i in range(0, len(events), chunk):
        batch = events[i:i+chunk]
        try:
            res = _post(f"{api}/api/v1/debug/replay-events",
                        {"events": batch, "dry_run": False}, token)
            print(f"   주입 {min(i+chunk, len(events))}/{len(events)}  (replayed={res.get('replayed','?')})")
        except urllib.error.HTTPError as e:
            cprint("r", f"[x] 주입 실패 (HTTP {e.code}): {e.read().decode()[:200]}")
            return
        time.sleep(1.2)
    cprint("g", f"\n[✓] 완료! 대시보드에서 기대 탐지: {expect}")
    cprint("y", "   인시던트를 클릭해 타임라인·MITRE 매핑·자동대응을 확인하세요.\n")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    args = ap.parse_args()

    cprint("c", "=" * 60)
    cprint("c", "  InfraRed 핸즈온 — 직접 공격해보고 탐지를 확인하세요")
    cprint("c", "=" * 60)
    token = login(args.api)
    cprint("g", "[✓] 데모 환경 로그인 완료\n")

    while True:
        print("어떤 공격을 시도할까요?\n")
        for i, (title, _, desc, _) in enumerate(SCENARIOS, 1):
            print(f"  {i}. {title:<16} — {desc}")
        print("  0. 종료\n")
        sel = input("번호 선택> ").strip()
        if sel == "0":
            cprint("c", "수고하셨습니다!")
            return 0
        if not sel.isdigit() or not (1 <= int(sel) <= len(SCENARIOS)):
            cprint("y", "올바른 번호를 입력하세요.\n"); continue
        title, fixture, _, expect = SCENARIOS[int(sel) - 1]
        cprint("c", f"\n▶ '{title}' 공격을 실행합니다.")
        run_scenario(args.api, token, fixture, expect)
        input("계속하려면 Enter...")
        print()

if __name__ == "__main__":
    sys.exit(main())
