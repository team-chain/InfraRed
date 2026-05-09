"""Demo Signal contract — Honeypot /demo 방문자 정보 (설계서 6.5, 17.3).

incidents 테이블과 물리적으로 분리. demo_signal_id 체계 사용.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _new_demo_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d")
    return f"DEMO-{ts}-{uuid4().hex[:8]}"


class GeoInfo(BaseModel):
    """IP 기반 위치 추정 정보 (MaxMind GeoLite2)."""
    country: Optional[str] = None           # 예: "KR"
    region: Optional[str] = None            # 예: "Seoul"
    accuracy_radius: Optional[int] = None   # km 단위


class DeviceInfo(BaseModel):
    """User-Agent 파싱 결과 — 계열 추정만, 모델 확정 불가 (설계서 6.5 수집 데이터)."""
    device_type: Optional[str] = None    # "mobile" | "desktop" | "bot"
    os_family: Optional[str] = None      # "iOS" | "Android" | "Windows" 등
    browser_family: Optional[str] = None # "Safari" | "Chrome" 등
    accept_language: Optional[str] = None


class DemoSignal(BaseModel):
    """Honeypot /demo 경로 접근 이벤트.

    - Info 등급, Incident 승격 안 함
    - 24시간 TTL 후 자동 삭제 (개인정보 보호)
    - source_ip는 일부 마스킹 표시 (예: 121.135.xx.xx)
    - 원본 IP는 해시값으로만 중복 식별
    """
    demo_signal_id: str = Field(default_factory=_new_demo_id)
    tenant_id: str
    asset_id: str

    # IP — 평문 저장 안 함, 마스킹 + 해시만
    source_ip_masked: Optional[str] = None    # 예: "121.135.xx.xx"
    source_ip_hash: Optional[str] = None      # sha256(원본 IP)

    geo: Optional[GeoInfo] = None
    device: Optional[DeviceInfo] = None

    path: str = "/demo"
    severity: str = "info"
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None     # detected_at + 24h, DB에서 계산
