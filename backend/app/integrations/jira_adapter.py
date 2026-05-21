"""
Jira Integration Adapter - 인시던트 → Jira 티켓 자동 생성.
v4.0 설계서 §10.2 참조.
"""
from __future__ import annotations

import logging

from app.integrations.base import IncidentPayload, NotificationAdapter

logger = logging.getLogger(__name__)

try:
    from jira import JIRA
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False
    logger.warning("jira package not available. Install: pip install jira")


class JiraAdapter(NotificationAdapter):
    adapter_type = "jira"

    PRIORITY_MAP = {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    async def send_incident(self, incident: IncidentPayload, config: dict) -> bool:
        if not JIRA_AVAILABLE:
            logger.error("jira package not installed")
            return False

        server_url = config.get("server_url", "")
        email = config.get("email", "")
        api_token = config.get("api_token", "")
        project_key = config.get("project_key", "SEC")

        if not all([server_url, email, api_token]):
            logger.error("Jira config incomplete")
            return False

        try:
            jira = JIRA(server=server_url, basic_auth=(email, api_token))

            description = self._build_description(incident)

            issue = jira.create_issue(fields={
                "project": {"key": project_key},
                "summary": f"[InfraRed] {incident.severity} — {incident.display_name}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": self.PRIORITY_MAP.get(incident.severity, "Medium")},
                "labels": ["infrared-security", incident.severity.lower()],
            })

            logger.info(f"Jira ticket created: {issue.key}")
            return True
        except Exception as e:
            logger.error(f"Jira ticket creation failed: {e}")
            return False

    async def send_test(self, config: dict) -> bool:
        if not JIRA_AVAILABLE:
            return False
        try:
            jira = JIRA(
                server=config.get("server_url", ""),
                basic_auth=(config.get("email", ""), config.get("api_token", ""))
            )
            jira.projects()  # 연결 테스트
            return True
        except Exception as e:
            logger.error(f"Jira test failed: {e}")
            return False

    def _build_description(self, incident: IncidentPayload) -> str:
        actions_text = "\n".join(f"# {a}" for a in incident.recommended_actions) if incident.recommended_actions else "- 수동 조사 필요"
        return f"""h2. 인시던트 개요

*심각도:* {incident.severity}
*탐지 시각:* {incident.created_at}
*대상 자산:* {incident.asset_hostname} ({incident.asset_type}, {incident.asset_environment})
*공격자 IP:* {incident.source_ip}
*신뢰도:* {incident.confidence_score:.0%}
*시나리오:* {incident.scenario_id or '없음'}

h2. AI 분석
{incident.ai_summary or '분석 결과 없음'}

h2. MITRE ATT&CK
{', '.join(incident.mitre_techniques) or 'N/A'}

h2. 권장 조치
{actions_text}

h2. 대시보드 링크
[InfraRed에서 보기|{incident.dashboard_url or 'https://app.infrared.io'}]
"""
