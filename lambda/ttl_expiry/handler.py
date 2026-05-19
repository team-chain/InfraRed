"""
Lambda TTL Expiry Checker
EventBridge 5분 주기: 만료된 IP 차단 해제 명령 생성
"""
import json, os, logging
from datetime import datetime, timezone
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """만료된 차단 목록 조회 후 unblock 명령 생성 (DB 연동 없이 로그만)"""
    logger.info(f"TTL expiry check running at {datetime.now(timezone.utc).isoformat()}")
    # 실제 구현: DB에서 expires_at < NOW() AND reversed = false인 레코드 조회 후 agent_commands에 unblock 명령 추가
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
