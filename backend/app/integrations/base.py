"""
Integration Hub 기반 클래스.
모든 외부 알림 통합의 공통 인터페이스.
v4.0 설계서 §10 참조.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class IncidentPayload:
    """Integration Hub로 전달되는 인시던트 정보"""
    incident_id: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    display_name: str
    source_ip: str
    asset_hostname: str
    asset_type: str
    asset_environment: str = "prod"
    confidence_score: float = 0.0
    ai_summary: str = ""
    mitre_techniques: list = None
    scenario_id: str = ""
    campaign_id: str = ""
    approval_required: bool = False
    dashboard_url: str = ""
    created_at: str = ""
    recommended_actions: list = None

    def __post_init__(self):
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.recommended_actions is None:
            self.recommended_actions = []


class NotificationAdapter(ABC):
    """모든 알림 통합의 공통 인터페이스"""

    @abstractmethod
    async def send_incident(self, incident: IncidentPayload, config: dict) -> bool: ...

    @abstractmethod
    async def send_test(self, config: dict) -> bool: ...

    @property
    @abstractmethod
    def adapter_type(self) -> str: ...
