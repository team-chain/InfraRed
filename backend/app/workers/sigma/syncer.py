"""
SigmaHQ 커뮤니티 룰 자동 동기화.
Lambda EventBridge 주 1회 실행.
"""
from __future__ import annotations
import json, logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from app.workers.sigma.parser import SigmaParser, SigmaRule

SIGMA_REPO_API = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules"
CATEGORIES = ["linux", "windows", "web"]


def fetch_sigma_rules(category: str, max_rules: int = 50) -> list[str]:
    """SigmaHQ GitHub에서 룰 YAML 목록 가져오기"""
    if not REQUESTS_AVAILABLE:
        logger.error("requests not available for SIGMA sync")
        return []

    rules = []
    try:
        url = f"{SIGMA_REPO_API}/{category}"
        resp = requests.get(url, timeout=30, headers={"Accept": "application/vnd.github.v3+json"})
        if resp.status_code != 200:
            logger.warning(f"GitHub API returned {resp.status_code} for {category}")
            return []

        files = resp.json()
        for file_info in files[:max_rules]:
            if not isinstance(file_info, dict):
                continue
            if not file_info.get("name", "").endswith(".yml"):
                continue
            download_url = file_info.get("download_url")
            if not download_url:
                continue
            try:
                content_resp = requests.get(download_url, timeout=10)
                if content_resp.status_code == 200:
                    rules.append(content_resp.text)
            except Exception as e:
                logger.debug(f"Rule fetch failed: {e}")
    except Exception as e:
        logger.error(f"SIGMA sync error for {category}: {e}")

    return rules


def sync_sigma_rules(db_upsert_fn=None) -> dict:
    """
    SigmaHQ GitHub에서 stable 룰 동기화.
    db_upsert_fn: 룰을 DB에 저장하는 함수 (없으면 로그만)
    """
    parser = SigmaParser()
    synced = 0
    skipped = 0
    errors = 0

    for category in CATEGORIES:
        rule_yamls = fetch_sigma_rules(category)
        for yaml_content in rule_yamls:
            try:
                sigma = parser.parse(yaml_content)
                if not sigma:
                    errors += 1
                    continue

                if sigma.status not in ("stable", "test"):
                    skipped += 1
                    continue

                infrared_rule = parser.to_infrared_rule(sigma)

                if db_upsert_fn:
                    db_upsert_fn(infrared_rule)
                else:
                    logger.debug(f"SIGMA rule parsed: {infrared_rule.rule_id} - {infrared_rule.display_name}")

                synced += 1
            except Exception as e:
                logger.error(f"SIGMA rule processing error: {e}")
                errors += 1

    result = {"synced": synced, "skipped": skipped, "errors": errors}
    logger.info(f"SIGMA sync complete: {result}")
    return result


# Lambda 진입점
def lambda_handler(event, context):
    result = sync_sigma_rules()
    return result
