"""
UEBA 모델 학습 Lambda 핸들러.
EventBridge 주 1회 (매주 일요일 새벽 2시) 실행.
v4.0 설계서 §7 참조.

환경변수:
  DATABASE_URL      — PostgreSQL 연결 문자열
  UEBA_MODEL_BUCKET — S3 버킷 (모델 저장)
  UEBA_ENABLED      — true
  AWS_REGION        — ap-northeast-2

EventBridge 이벤트 예시:
  {
    "tenant_ids": ["tenant-abc", "tenant-xyz"],
    "target_date": "2025-05-18"   (선택, 없으면 어제 날짜)
  }
"""
import json
import logging
import os
import sys

# Lambda 실행 환경에서 /var/task 기준 경로 설정
sys.path.insert(0, "/var/task")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def handler(event: dict, context) -> dict:
    """
    Lambda 진입점.

    두 단계를 순서대로 수행:
    1. run_ueba_daily_collection  — 어제 사용자 행동 프로파일 집계 및 저장
    2. run_ueba_training          — Isolation Forest + Autoencoder 재학습
    """
    import asyncio
    from app.workers.ueba.worker import run_ueba_daily_collection, run_ueba_training

    tenant_ids: list[str] = event.get("tenant_ids", [])
    target_date: str | None = event.get("target_date")

    if not tenant_ids:
        log.warning("No tenant_ids provided in event. Exiting.")
        return {"status": "skipped", "reason": "no tenant_ids"}

    results = []
    for tenant_id in tenant_ids:
        log.info(f"Processing tenant: {tenant_id}")
        try:
            # Step 1: 일일 프로파일 수집
            collection_result = asyncio.run(
                run_ueba_daily_collection(tenant_id, target_date)
            )
            log.info(f"Collection result for {tenant_id}: {collection_result}")

            # Step 2: 모델 학습
            training_result = asyncio.run(run_ueba_training(tenant_id))
            log.info(f"Training result for {tenant_id}: {training_result}")

            results.append({
                "tenant_id": tenant_id,
                "collection": collection_result,
                "training": training_result,
            })
        except Exception as e:
            log.error(f"UEBA processing failed for tenant {tenant_id}: {e}", exc_info=True)
            results.append({
                "tenant_id": tenant_id,
                "status": "error",
                "detail": str(e),
            })

    return {
        "processed": len(results),
        "results": results,
    }
