"""Detection Confidence 가중치 공식 구현 (설계서 v3 Section 3).

calculate_detection_confidence()는 rule_id, 공격 체인 완성도(correlation_bonus),
자산 중요도, 신규성, 위협 인텔리전스, 예외 패널티를 종합해 0.0~1.0 점수를 반환한다.
"""
from __future__ import annotations

RULE_CONFIDENCE_TABLE: dict[str, float] = {
    "AUTH-001": 0.70,
    "AUTH-002": 0.65,
    "AUTH-003": 0.60,
    "AUTH-004": 0.85,
    "AUTH-006A": 0.75,
    "AUTH-006B": 0.75,
    "WEB-HNY-001": 0.80,
    "WEB-001": 0.70,
    "NET-001": 0.65,
    "PERSIST-001": 0.90,
    "FIM-001": 0.90,
    "PERSIST-002": 0.80,
    "FIM-003": 0.80,
    "PERSIST-003": 0.80,
    "FIM-005-SVC": 0.80,
    "ESCALATE-001": 0.90,
    "FIM-005": 0.90,
    "EXEC-001": 0.85,
    "EXEC-002": 0.95,
    "EXEC-003": 0.80,
    "TAMPER-001": 0.75,
    "TAMPER-002": 0.90,
}


def calculate_detection_confidence(
    rule_id: str,
    correlation_bonus: float = 0.0,
    asset_type: str | None = None,
    environment: str | None = None,
    exposure: str | None = None,
    contains_sensitive_data: bool = False,
    is_known_ip: bool = True,
    cti_abuse_score: int = 0,
    cti_is_known_malicious: bool = False,
    cti_is_tor_exit: bool = False,
    in_allowlist: bool = False,
    in_maintenance_window: bool = False,
    matches_benign_pattern: bool = False,
) -> tuple[float, dict]:
    """공격 탐지 신뢰도 점수를 계산한다.

    Args:
        rule_id: 탐지 룰 식별자 (예: "AUTH-001").
        correlation_bonus: 공격 체인 시나리오 완성도에 따라 외부에서 계산한 보너스.
        asset_type: 자산 유형 ("db", "bastion", "api" 등).
        environment: 배포 환경 ("prod", "staging" 등).
        exposure: 네트워크 노출 수준 ("public" 등).
        contains_sensitive_data: 민감 데이터 보유 여부.
        is_known_ip: 이미 알려진 IP 여부 (False면 신규 IP 보너스 적용).
        cti_abuse_score: AbuseIPDB 점수 (0~100).
        cti_is_known_malicious: 위협 인텔리전스상 알려진 악성 IP 여부.
        cti_is_tor_exit: Tor 출구 노드 여부.
        in_allowlist: 허용 목록 포함 여부 (대형 패널티).
        in_maintenance_window: 유지보수 시간 내 여부.
        matches_benign_pattern: 알려진 양성 패턴 일치 여부.

    Returns:
        (confidence_score, breakdown_dict) 튜플.
        confidence_score는 0.0~1.0 범위로 반올림된 값.
        breakdown_dict는 각 구성 요소를 담은 딕셔너리.
    """
    # Base: rule 고유 신뢰도
    rule_confidence = RULE_CONFIDENCE_TABLE.get(rule_id, 0.5)

    # Asset criticality bonus (최대 0.25)
    asset_bonus = 0.0
    if environment == "prod":
        asset_bonus += 0.10
    elif environment == "staging":
        asset_bonus += 0.03
    if asset_type == "db":
        asset_bonus += 0.15
    elif asset_type == "bastion":
        asset_bonus += 0.15
    elif asset_type == "api":
        asset_bonus += 0.08
    if exposure == "public":
        asset_bonus += 0.07
    if contains_sensitive_data:
        asset_bonus += 0.10
    asset_bonus = min(asset_bonus, 0.25)

    # Novelty bonus (최대 0.15)
    novelty_bonus = 0.0
    if not is_known_ip:
        novelty_bonus += 0.08
    novelty_bonus = min(novelty_bonus, 0.15)

    # Threat Intel bonus
    ti_bonus = 0.0
    if cti_is_known_malicious:
        ti_bonus = 0.20
    elif cti_abuse_score >= 70:
        ti_bonus = 0.15
    elif cti_abuse_score >= 30:
        ti_bonus = 0.08
    if cti_is_tor_exit:
        ti_bonus = max(ti_bonus, 0.12)

    # Penalties
    penalty = 0.0
    if in_allowlist:
        penalty += 0.60
    if in_maintenance_window:
        penalty += 0.30
    if matches_benign_pattern:
        penalty += 0.20

    # Final score
    raw = (
        rule_confidence
        + correlation_bonus
        + asset_bonus
        + novelty_bonus
        + ti_bonus
        - penalty
    )
    final = round(max(0.0, min(1.0, raw)), 3)

    breakdown = {
        "rule_confidence": rule_confidence,
        "correlation_bonus": correlation_bonus,
        "asset_bonus": asset_bonus,
        "novelty_bonus": novelty_bonus,
        "ti_bonus": ti_bonus,
        "penalty": penalty,
        "raw": round(raw, 3),
        "final": final,
    }
    return final, breakdown
