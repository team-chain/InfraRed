"""
SIGMA 룰 자동 동기화 Lambda 핸들러.
EventBridge 주 1회 (매주 월요일 새벽 3시) 실행.
v4.0 설계서 §8 참조.

환경변수:
  DATABASE_URL         — PostgreSQL 연결 문자열
  SIGMA_SYNC_ENABLED   — true
  GITHUB_TOKEN         — (선택) GitHub API rate limit 증가용

EventBridge 이벤트 예시:
  {
    "dry_run": false,
    "categories": ["linux", "windows", "web"]   (선택)
  }
"""
import logging
import sys

sys.path.insert(0, "/var/task")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def handler(event: dict, context) -> dict:
    """Lambda 진입점."""
    import asyncio
    from app.workers.sigma.syncer import sync_sigma_rules, CATEGORIES
    from app.ingestion.sigma_routes import db_upsert_sigma_rule

    dry_run: bool = event.get("dry_run", False)
    categories: list[str] = event.get("categories", CATEGORIES)

    log.info(f"SIGMA sync started. dry_run={dry_run}, categories={categories}")

    if dry_run:
        result = sync_sigma_rules(db_upsert_fn=None)
        log.info(f"Dry-run result: {result}")
        return {**result, "dry_run": True}

    # DB upsert 래퍼 (asyncio.run 사용)
    def sync_upsert(rule):
        try:
            asyncio.run(db_upsert_sigma_rule(rule))
        except Exception as e:
            log.warning(f"DB upsert failed for {rule.rule_id}: {e}")

    result = sync_sigma_rules(db_upsert_fn=sync_upsert)
    log.info(f"SIGMA sync complete: {result}")
    return {**result, "dry_run": False}
