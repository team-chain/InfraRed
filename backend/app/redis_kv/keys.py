"""Redis key naming helpers."""
from __future__ import annotations

import hashlib


def _ns(tenant_id: str) -> str:
    return f"tenant:{tenant_id}"


def event_dedup(tenant_id: str, event_id: str) -> str:
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    return f"{_ns(tenant_id)}:event:dedup:{digest}"


def auth_fail_ip(tenant_id: str, asset_id: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:fail:ip:{asset_id}:{ip}"


def auth_fail_user_ip(tenant_id: str, asset_id: str, username: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:fail:user_ip:{asset_id}:{username}:{ip}"


def auth_invalid_user(tenant_id: str, asset_id: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:invalid:{asset_id}:{ip}"


def auth_known_ip(tenant_id: str, asset_id: str, username: str) -> str:
    return f"{_ns(tenant_id)}:auth:known_ip:{asset_id}:{username}"


def killchain_stage(tenant_id: str, asset_id: str, source_ip: str) -> str:
    return f"{_ns(tenant_id)}:killchain:{asset_id}:{source_ip}"


def cti_ip(ip: str) -> str:
    return f"cti:ip:{ip}"


def tenant_settings(tenant_id: str) -> str:
    return f"{_ns(tenant_id)}:settings"


def incident_dedup(
    tenant_id: str,
    rule_id: str,
    asset_id: str,
    ip: str,
    username: str,
) -> str:
    return f"{_ns(tenant_id)}:incident:dedup:{rule_id}:{asset_id}:{ip}:{username}"


def llm_cache(rule_id: str, severity: str, signal_type: str) -> str:
    return f"llm:cache:{rule_id}:{severity}:{signal_type}"


def llm_incident_cache(incident_id: str) -> str:
    return f"llm:cache:incident:{incident_id}"


# ── Web (nginx) rule keys ──────────────────────────────────────────────────────

def web_req_ip(tenant_id: str, asset_id: str, ip: str) -> str:
    """Sliding window of all web requests from one IP (WEB-002, WEB-003, WEB-004)."""
    return f"{_ns(tenant_id)}:web:req:ip:{asset_id}:{ip}"


def web_admin_req(tenant_id: str, asset_id: str, ip: str) -> str:
    """Sliding window of admin/login path hits from one IP (WEB-002)."""
    return f"{_ns(tenant_id)}:web:admin:{asset_id}:{ip}"


def web_404(tenant_id: str, asset_id: str, ip: str) -> str:
    """Sliding window of 404 responses from one IP (WEB-004)."""
    return f"{_ns(tenant_id)}:web:404:{asset_id}:{ip}"


# ── Credential Stuffing (AUTH-006A/B) ─────────────────────────────────────────

def auth_stuffing_user_to_ips(tenant_id: str, asset_id: str, username: str) -> str:
    """Set of source IPs that tried a single username — AUTH-006A (Credential Stuffing)."""
    return f"{_ns(tenant_id)}:auth:stuffing:user_to_ips:{asset_id}:{username}"


def auth_stuffing_ip_to_users(tenant_id: str, asset_id: str, source_ip: str) -> str:
    """Set of usernames tried from a single IP — AUTH-006B (Password Spraying)."""
    return f"{_ns(tenant_id)}:auth:stuffing:ip_to_users:{asset_id}:{source_ip}"


# ── DDoS Rate (NET-001, 2단계) ────────────────────────────────────────────────

def net_rate_ip(tenant_id: str, asset_id: str, ip: str) -> str:
    """HTTP request rate per IP for flood detection (NET-001)."""
    return f"{_ns(tenant_id)}:net:rate:{asset_id}:{ip}"


# ── Honeypot ─────────────────────────────────────────────────────────────────

def honeypot_visit(tenant_id: str, ip_hash: str) -> str:
    """SET NX — deduplicate honeypot visits per IP hash within 24h."""
    return f"{_ns(tenant_id)}:honeypot:visit:{ip_hash}"


# ── IP Policy (3종 분리) ───────────────────────────────────────────────────────

def policy_watchlist(tenant_id: str) -> str:
    """Set — Watchlist에 등록된 공격자 IP."""
    return f"{_ns(tenant_id)}:policy:watchlist"


def policy_denylist(tenant_id: str) -> str:
    """Set — 차단된 공격자 IP (운영 확장 시 enforcement 연동)."""
    return f"{_ns(tenant_id)}:policy:deny"


def policy_allowlist(tenant_id: str) -> str:
    """Set — 항상 허용하는 신뢰 IP (Threat IP Policy)."""
    return f"{_ns(tenant_id)}:policy:allow"


def policy_country_block(tenant_id: str) -> str:
    """Set — 차단할 국가 코드 (예: CN, RU, KP)."""
    return f"{_ns(tenant_id)}:policy:country_block"


def policy_agent_allow(tenant_id: str) -> str:
    """Set — Ingestion API에 이벤트를 보낼 수 있는 allowed agent_id 목록."""
    return f"{_ns(tenant_id)}:policy:agent:allow"


def policy_dashboard_allow(tenant_id: str) -> str:
    """Set — Dashboard 접근을 허용하는 IP/CIDR 목록 (직렬화된 문자열로 저장)."""
    return f"{_ns(tenant_id)}:policy:dashboard:allow"


def policy_autoresponse(tenant_id: str) -> str:
    """String (JSON) — severity별 자동 대응 정책."""
    return f"{_ns(tenant_id)}:autoresponse:policy"


def policy_version(tenant_id: str) -> str:
    """String — 정책 변경 시 atomic increment되는 버전 번호."""
    return f"{_ns(tenant_id)}:policy:version"


# ── Policy Pub/Sub 채널 ───────────────────────────────────────────────────────

POLICY_INVALIDATE_CHANNEL = "infrared:policy:invalidate"
"""Redis Pub/Sub 채널 — 정책 변경 시 모든 워커에 캐시 무효화 신호 발송."""


# ── Attack Chain Scenario (상관분석 엔진) ─────────────────────────────────────

def scenario_state(scenario_id: str, tenant_id: str, source_ip: str) -> str:
    """공격 체인 시나리오 진행 상태 (JSON 직렬화된 ScenarioState)."""
    return f"scenario:{scenario_id}:{tenant_id}:{source_ip}"


def lateral_movement_assets(tenant_id: str, source_ip: str) -> str:
    """Lateral Movement 탐지용 — source_ip별 접근한 asset_id SET."""
    return f"scenario:lateral:{tenant_id}:{source_ip}"
