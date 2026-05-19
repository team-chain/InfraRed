"""
Detection Worker Lambda 핸들러 (SQS → Detection Pipeline).
v4.0 설계서 §5 하이브리드 아키텍처 참조.

SQS 이벤트 → NormalizedEvent 파싱 → DetectionRule 평가 → Signal 저장 → SQS signals 큐 발행.

환경변수:
  DATABASE_URL       — PostgreSQL 연결 문자열
  REDIS_URL          — Redis 연결 문자열 (캐시/CTI)
  SQS_SIGNALS_URL    — Signal 결과 큐 URL
  SQS_ENABLED        — true
"""
import json
import logging
import sys

sys.path.insert(0, "/var/task")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def handler(event: dict, context) -> dict:
    """
    SQS 트리거 Lambda 진입점.
    Records 배열에서 이벤트를 꺼내 탐지 파이프라인 실행.
    """
    import asyncio
    from app.workers.detection.worker import process_event_batch

    records = event.get("Records", [])
    if not records:
        return {"processed": 0}

    envelopes = []
    for record in records:
        try:
            body = json.loads(record["body"])
            payload = json.loads(body.get("payload", "{}"))
            envelopes.append(payload)
        except Exception as e:
            log.warning(f"Failed to parse SQS record: {e}")

    log.info(f"Processing {len(envelopes)} events from SQS")

    try:
        result = asyncio.run(process_event_batch(envelopes))
        return {"processed": len(envelopes), "signals": result.get("signals_created", 0)}
    except Exception as e:
        log.error(f"Detection batch processing failed: {e}", exc_info=True)
        raise  # Lambda가 메시지를 DLQ로 이동


def _ensure_process_event_batch():
    """
    detection worker에 batch 처리 함수가 없을 경우 폴백.
    실제로는 workers/detection/worker.py에 구현되어 있음.
    """
    pass
