"""
Integration Hub 테스트 & 설정 API 라우터.
v4.0 설계서 §10 — Slack / PagerDuty / Jira / Splunk 연동.

엔드포인트:
  POST /api/v1/integrations/slack/test      — Slack Webhook 테스트 메시지 전송
  POST /api/v1/integrations/pagerduty/test  — PagerDuty 테스트 이벤트 전송
  POST /api/v1/integrations/jira/test       — Jira 연결 확인 (프로젝트 조회)
  POST /api/v1/integrations/splunk/test     — Splunk HEC 연결 테스트
  GET  /api/v1/integrations/status          — 전체 어댑터 연결 상태
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.iam.rbac_v2 import require_any_role

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])
log = logging.getLogger(__name__)


def _slack():
    from app.integrations.slack_adapter import SlackAdapter
    return SlackAdapter()


def _pagerduty():
    from app.integrations.pagerduty_adapter import PagerDutyAdapter
    return PagerDutyAdapter()


def _jira():
    from app.integrations.jira_adapter import JiraAdapter
    return JiraAdapter()


def _splunk():
    from app.integrations.splunk_adapter import SplunkHECAdapter
    return SplunkHECAdapter()


# --- 요청 모델 ---

class SlackTestRequest(BaseModel):
    webhook_url: str
    channel: str = ""


class PagerDutyTestRequest(BaseModel):
    routing_key: str


class JiraTestRequest(BaseModel):
    server_url: str
    email: str
    api_token: str
    project_key: str


class SplunkTestRequest(BaseModel):
    hec_url: str
    hec_token: str


# --- POST /api/v1/integrations/slack/test ---

@router.post("/slack/test")
async def test_slack(
    body: SlackTestRequest,
    claims: dict = Depends(require_any_role(*["owner", "security_manager"])),
) -> dict:
    """Slack Webhook으로 테스트 메시지 전송."""
    if not body.webhook_url.startswith("https://hooks.slack.com/"):
        raise HTTPException(status_code=400, detail="유효하지 않은 Slack Webhook URL입니다.")

    adapter = _slack()
    config = {"webhook_url": body.webhook_url, "channel": body.channel}
    try:
        success = await adapter.send_test(config)
        if success:
            return {"status": "ok", "message": "Slack 테스트 메시지 전송 성공"}
        raise HTTPException(status_code=502, detail="Slack Webhook 응답 오류")
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"Slack test failed: {e}")
        raise HTTPException(status_code=502, detail=f"Slack 전송 실패: {e}")


# --- POST /api/v1/integrations/pagerduty/test ---

@router.post("/pagerduty/test")
async def test_pagerduty(
    body: PagerDutyTestRequest,
    claims: dict = Depends(require_any_role(*["owner", "security_manager"])),
) -> dict:
    """PagerDuty Events API v2로 테스트 이벤트 전송."""
    if len(body.routing_key) < 20:
        raise HTTPException(status_code=400, detail="유효하지 않은 PagerDuty Routing Key입니다.")

    adapter = _pagerduty()
    config = {"integration_key": body.routing_key}
    try:
        success = await adapter.send_test(config)
        if success:
            return {"status": "ok", "message": "PagerDuty 테스트 이벤트 전송 성공"}
        raise HTTPException(status_code=502, detail="PagerDuty API 응답 오류")
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"PagerDuty test failed: {e}")
        raise HTTPException(status_code=502, detail=f"PagerDuty 전송 실패: {e}")


# --- POST /api/v1/integrations/jira/test ---

@router.post("/jira/test")
async def test_jira(
    body: JiraTestRequest,
    claims: dict = Depends(require_any_role(*["owner", "security_manager"])),
) -> dict:
    """Jira REST API 연결 확인 (프로젝트 존재 여부 조회)."""
    adapter = _jira()
    config = {
        "server_url": body.server_url,
        "email": body.email,
        "api_token": body.api_token,
        "project_key": body.project_key,
    }
    try:
        success = await adapter.send_test(config)
        if success:
            return {"status": "ok", "message": f"Jira 프로젝트 '{body.project_key}' 연결 성공"}
        raise HTTPException(status_code=502, detail="Jira API 응답 오류")
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"Jira test failed: {e}")
        raise HTTPException(status_code=502, detail=f"Jira 연결 실패: {e}")


# --- POST /api/v1/integrations/splunk/test ---

@router.post("/splunk/test")
async def test_splunk(
    body: SplunkTestRequest,
    claims: dict = Depends(require_any_role(*["owner", "security_manager"])),
) -> dict:
    """Splunk HEC 연결 테스트."""
    adapter = _splunk()
    config = {"hec_url": body.hec_url, "hec_token": body.hec_token}
    try:
        success = await adapter.send_test(config)
        if success:
            return {"status": "ok", "message": "Splunk HEC 연결 성공"}
        raise HTTPException(status_code=502, detail="Splunk HEC 응답 오류")
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"Splunk test failed: {e}")
        raise HTTPException(status_code=502, detail=f"Splunk 연결 실패: {e}")


# --- GET /api/v1/integrations/status ---

@router.get("/status")
async def integration_status(
    claims: dict = Depends(require_any_role(*["analyst", "security_manager", "owner"])),
) -> dict:
    """
    테넌트 설정에 저장된 Integration 연결 상태 요약.
    실제 연결 테스트는 하지 않고 설정 존재 여부만 확인.
    """
    from app.db.connection import get_session
    from sqlalchemy import text

    tenant_id = claims["tenant_id"]
    try:
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT settings FROM tenants WHERE id = :tid
            """), {"tid": tenant_id})
            row = result.fetchone()
            s: dict = row.settings if row and row.settings else {}
    except Exception:
        s = {}

    return {
        "slack":      {"configured": bool(s.get("slack_webhook_url"))},
        "pagerduty":  {"configured": bool(s.get("pagerduty_routing_key"))},
        "jira":       {"configured": bool(s.get("jira_api_token") and s.get("jira_server_url"))},
        "splunk":     {"configured": bool(s.get("splunk_hec_token") and s.get("splunk_hec_url"))},
    }
