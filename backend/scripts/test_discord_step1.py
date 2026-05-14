"""
Discord 알림 단독 테스트 — Step 1: discord.py 함수 직접 호출
파이프라인(Redis/DB/LLM) 없이 Discord webhook만 있으면 즉시 실행 가능.

실제 이벤트 흐름 순서:
  [CORR] 상관관계 경보  <- 복수 IP 감지 (그룹핑 단계, Incident 생성 전)
     1   1차 즉시 알림  <- 개별 Incident 생성 직후
     2   2차 AI 분석   <- LLM 분석 완료 후
     3   대응 완료     <- Policy Engine 실행 후

사용법:
  cd backend
  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... python scripts/test_discord_step1.py [corr|1|2|3]

  corr = 상관관계 경보   (send_discord_correlation_alert)
  1    = 1차 즉시 알림   (send_discord_first_alert)
  2    = 2차 AI 분석    (send_discord_ai_analysis)
  3    = 대응 결과      (send_discord_response_result)
  인자 없음 = 실제 흐름 순서대로 모두 전송
"""
from __future__ import annotations

import asyncio
import os
import sys

# backend 루트를 path에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.dispatcher.discord import (
    send_discord_ai_analysis,
    send_discord_correlation_alert,
    send_discord_first_alert,
    send_discord_response_result,
)

WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
TENANT = "company-a"
INCIDENT_ID = "INC-TEST-0001"
ASSET = "web-prod-01"
SOURCE_IP = "203.0.113.45"


async def test_first_alert() -> None:
    """1차 즉시 알림 — Incident 생성 직후 (LLM 분석 전)"""
    print("▶ 1차 알림 전송 중...")
    ok = await send_discord_first_alert(
        incident_id=INCIDENT_ID,
        tenant_id=TENANT,
        severity="high",
        rule_id="AUTH-004",
        rule_description="인증 성공 전 다수 실패 (Brute-Force 후 성공)",
        asset_name=ASSET,
        source_ip=SOURCE_IP,
        playbook_summary=(
            "단기간 다수 로그인 실패 후 성공 이벤트 탐지. "
            "계정 탈취 또는 자격증명 스터핑 공격 가능성. "
            "해당 IP의 추가 활동을 즉시 모니터링 필요."
        ),
        webhook_url=WEBHOOK or None,
    )
    print(f"   {'성공' if ok else '실패 (webhook URL 없음)'}")


async def test_ai_analysis() -> None:
    """2차 AI 분석 완료 알림"""
    print("▶ 2차 AI 분석 알림 전송 중...")
    ok = await send_discord_ai_analysis(
        incident_id=INCIDENT_ID,
        tenant_id=TENANT,
        severity="high",
        asset_name=ASSET,
        event_type="인증 공격 (Brute-Force 후 계정 탈취)",
        summary=(
            "해당 IP(203.0.113.45)는 6분 내 847회 로그인 실패 후 "
            "admin 계정 로그인 성공. AbuseIPDB 악성 등록 이력 확인됨. "
            "계정 탈취 후 내부 권한 상승 시도 가능성 높음."
        ),
        kill_chain_stage="Credential Access",
        mitre_techniques=["T1110.001", "T1078"],
        auto_actions_taken=[
            {"type": "block_ip", "target": SOURCE_IP, "status": "success"},
        ],
        manual_actions_needed=[
            "admin 계정 패스워드 즉시 변경 및 세션 강제 만료",
            "해당 IP 대역 차단 여부 검토 (ASN: AS4134 CHINANET)",
            "로그인 성공 후 접근한 내부 리소스 감사",
        ],
        ai_confidence=0.87,
        analysis_elapsed_sec=23,
        webhook_url=WEBHOOK or None,
    )
    print(f"   {'성공' if ok else '실패 (webhook URL 없음)'}")


async def test_response_result() -> None:
    """3차 대응 결과 알림 — 자동 대응 실행 후"""
    print("▶ 대응 결과 알림 전송 중...")
    ok = await send_discord_response_result(
        incident_id=INCIDENT_ID,
        tenant_id=TENANT,
        severity="high",
        asset_name=ASSET,
        mode="auto",
        actions_taken=[
            {"type": "block_ip",      "target": SOURCE_IP,  "status": "success"},
            {"type": "disable_user",  "target": "admin",    "status": "success"},
            {"type": "revoke_session","target": "admin",    "status": "success"},
        ],
        actions_queued=[
            {"type": "notify_soc",    "target": "soc-team", "status": "queued"},
        ],
        webhook_url=WEBHOOK or None,
    )
    print(f"   {'성공' if ok else '실패 (webhook URL 없음)'}")


async def test_correlation_alert() -> None:
    """4차 상관관계 경보 — 복수 IP가 동일 자산 공격 시"""
    print("▶ 상관관계 경보 전송 중...")
    ok = await send_discord_correlation_alert(
        tenant_id=TENANT,
        asset_name=ASSET,
        source_ips=[
            "203.0.113.45",
            "198.51.100.22",
            "192.0.2.77",
            "45.33.32.156",
            "104.21.91.10",
        ],
        first_seen_at="2025-07-01T09:00:00+00:00",
        last_seen_at="2025-07-01T09:04:31+00:00",
        duration_sec=271,
        incident_count=5,
        mitre_technique="T1595.001",
        webhook_url=WEBHOOK or None,
    )
    print(f"   {'성공' if ok else '실패 (webhook URL 없음)'}")


async def main() -> None:
    if not WEBHOOK:
        print(
            "경고: DISCORD_WEBHOOK_URL 환경변수 없음.\n"
            "  export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...\n"
            "설정 없이 실행하면 webhook URL이 DB에서 읽히므로 DB 연결이 필요합니다.\n"
        )

    arg = sys.argv[1] if len(sys.argv) > 1 else "all"

    if arg == "corr":
        await test_correlation_alert()
    elif arg == "1":
        await test_first_alert()
    elif arg == "2":
        await test_ai_analysis()
    elif arg == "3":
        await test_response_result()
    else:
        # 실제 흐름 순서: 상관관계 경보 → 1차 → 2차 → 대응 완료
        await test_correlation_alert()
        print("   (3초 대기 - Discord rate limit)")
        await asyncio.sleep(3)
        await test_first_alert()
        await asyncio.sleep(3)
        await test_ai_analysis()
        await asyncio.sleep(3)
        await test_response_result()

    print("\n완료. Discord 채널에서 메시지를 확인하세요.")


if __name__ == "__main__":
    asyncio.run(main())
