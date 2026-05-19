"""
Lambda CTI Cache Refresher
EventBridge 1시간 주기: 고위험 IP CTI 캐시 갱신
"""
import json, os, logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info(f"CTI cache refresh at {datetime.now(timezone.utc).isoformat()}")
    # 실제 구현: 최근 24시간 블록된 IP 목록 조회 후 OTX 재조회 + Redis 캐시 갱신
    return {"status": "ok", "refreshed": 0}
