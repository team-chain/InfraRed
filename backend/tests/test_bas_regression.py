"""BAS 회귀 테스트 — v3.0 설계서 Section 7

Breach and Attack Simulation (BAS) 탐지 회귀 테스트셋.
DB / 실제 Redis 불필요 — fakeredis.aioredis 사용.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.common.constants import EventType, RuleId
from app.models.envelope import NormalizedEvent
from app.workers.detection.confidence import (
    RULE_CONFIDENCE_TABLE,
    calculate_detection_confidence,
)
from app.workers.correlation.attack_chain import (
    SCENARIOS,
    AttackChainMatcher,
)
from app.workers.detection.web_rules import (
    evaluate_honeypot,
    evaluate_web_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)


def _web_event(
    *,
    event_id: str = "bas-evt-001",
    request_path: str = "/",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
    source_ip: str = "203.0.113.1",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        tenant_id="bas-tenant",
        asset_id="bas-asset",
        agent_id="bas-agent",
        event_type=EventType.WEB_REQUEST,
        timestamp=_ts(),
        source_ip=source_ip,
        request_path=request_path,
        status_code=status_code,
        user_agent=user_agent,
    )


# ---------------------------------------------------------------------------
# Section 1: Detection Confidence 회귀 테스트
# ---------------------------------------------------------------------------

class TestDetectionConfidenceRegression:
    """calculate_detection_confidence() 함수 회귀 테스트."""

    def test_all_rule_ids_base_score_in_valid_range(self) -> None:
        """RULE_CONFIDENCE_TABLE의 모든 룰 ID에 대해 기본 신뢰도가 0~1 범위인지 확인."""
        for rule_id, base_score in RULE_CONFIDENCE_TABLE.items():
            assert 0.0 <= base_score <= 1.0, (
                f"{rule_id}: base_score={base_score} is out of [0, 1] range"
            )

    def test_final_score_in_valid_range_for_all_rules(self) -> None:
        """기본 파라미터로 호출 시 최종 점수가 0~1 범위인지 확인."""
        for rule_id in RULE_CONFIDENCE_TABLE:
            score, _ = calculate_detection_confidence(rule_id)
            assert 0.0 <= score <= 1.0, (
                f"{rule_id}: final score={score} is out of [0, 1] range"
            )

    def test_correlation_bonus_increases_score(self) -> None:
        """correlation_bonus가 최종 점수를 올리는지 확인."""
        rule_id = "AUTH-001"
        base_score, _ = calculate_detection_confidence(rule_id, correlation_bonus=0.0)
        bonused_score, _ = calculate_detection_confidence(rule_id, correlation_bonus=0.20)
        assert bonused_score > base_score

    def test_cti_known_malicious_increases_score(self) -> None:
        """cti_is_known_malicious=True 시 점수가 오르는지 확인."""
        rule_id = "AUTH-001"
        base_score, _ = calculate_detection_confidence(rule_id)
        cti_score, _ = calculate_detection_confidence(rule_id, cti_is_known_malicious=True)
        assert cti_score > base_score

    def test_cti_tor_exit_increases_score(self) -> None:
        """cti_is_tor_exit=True 시 점수가 오르는지 확인."""
        rule_id = "NET-001"
        base_score, _ = calculate_detection_confidence(rule_id)
        tor_score, _ = calculate_detection_confidence(rule_id, cti_is_tor_exit=True)
        assert tor_score > base_score

    def test_allowlist_penalty_decreases_score(self) -> None:
        """in_allowlist=True 시 점수가 낮아지는지 확인."""
        rule_id = "AUTH-004"
        base_score, _ = calculate_detection_confidence(rule_id)
        penalized_score, _ = calculate_detection_confidence(rule_id, in_allowlist=True)
        assert penalized_score < base_score

    def test_maintenance_window_penalty_decreases_score(self) -> None:
        """in_maintenance_window=True 시 점수가 낮아지는지 확인."""
        rule_id = "AUTH-004"
        base_score, _ = calculate_detection_confidence(rule_id)
        maint_score, _ = calculate_detection_confidence(rule_id, in_maintenance_window=True)
        assert maint_score < base_score

    def test_breakdown_contains_required_keys(self) -> None:
        """confidence_breakdown dict에 필수 키가 모두 있는지 확인."""
        required_keys = {
            "rule_confidence", "correlation_bonus", "asset_bonus",
            "novelty_bonus", "ti_bonus", "penalty", "raw", "final",
        }
        _, breakdown = calculate_detection_confidence("AUTH-001")
        for key in required_keys:
            assert key in breakdown, f"Missing key in breakdown: {key}"

    def test_breakdown_final_matches_returned_score(self) -> None:
        """breakdown['final']이 반환된 score와 일치하는지 확인."""
        score, breakdown = calculate_detection_confidence(
            "WEB-HNY-001",
            correlation_bonus=0.10,
            cti_is_known_malicious=True,
        )
        assert score == breakdown["final"]

    def test_score_capped_at_1_with_many_bonuses(self) -> None:
        """여러 보너스를 합산해도 최종 점수가 1.0을 초과하지 않는지 확인."""
        score, _ = calculate_detection_confidence(
            "EXEC-002",  # base 0.95
            correlation_bonus=0.35,
            cti_is_known_malicious=True,
            environment="prod",
            asset_type="db",
            exposure="public",
            contains_sensitive_data=True,
        )
        assert score <= 1.0

    def test_score_not_negative_with_heavy_penalty(self) -> None:
        """큰 패널티를 줘도 점수가 음수가 되지 않는지 확인."""
        score, _ = calculate_detection_confidence(
            "AUTH-001",
            in_allowlist=True,
            in_maintenance_window=True,
            matches_benign_pattern=True,
        )
        assert score >= 0.0

    def test_unknown_rule_id_uses_default_base_score(self) -> None:
        """RULE_CONFIDENCE_TABLE에 없는 룰 ID는 기본값 0.5를 사용하는지 확인."""
        score, breakdown = calculate_detection_confidence("UNKNOWN-999")
        assert breakdown["rule_confidence"] == 0.5
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Section 2: 공격 체인 시나리오 존재 확인
# ---------------------------------------------------------------------------

class TestAttackChainScenarios:
    """SCENARIOS 목록 및 각 시나리오 구조 검증."""

    EXPECTED_SCENARIO_IDS = {
        "SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE",
        "WEBSHELL_INFILTRATION",
        "PRIVILEGE_ESCALATION",
        "RANSOMWARE_PRECURSOR",
        "LATERAL_MOVEMENT",
    }

    def test_all_five_scenarios_exist(self) -> None:
        """5개 시나리오 ID가 모두 SCENARIOS에 존재하는지 확인."""
        actual_ids = {sc.id for sc in SCENARIOS}
        assert self.EXPECTED_SCENARIO_IDS == actual_ids

    def test_each_scenario_has_stages(self) -> None:
        """각 시나리오에 stages 목록이 정의되어 있는지 확인."""
        for sc in SCENARIOS:
            assert len(sc.stages) > 0, f"{sc.id}: stages is empty"

    def test_each_scenario_has_window_seconds(self) -> None:
        """각 시나리오에 window_seconds가 양수로 정의되어 있는지 확인."""
        for sc in SCENARIOS:
            assert sc.window_seconds > 0, f"{sc.id}: window_seconds must be positive"

    def test_each_scenario_has_confidence_bonus(self) -> None:
        """각 시나리오에 confidence_bonus가 0 초과로 정의되어 있는지 확인."""
        for sc in SCENARIOS:
            assert sc.confidence_bonus > 0.0, (
                f"{sc.id}: confidence_bonus must be > 0"
            )

    def test_ssh_compromise_scenario_structure(self) -> None:
        """SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE 시나리오 세부 구조 확인."""
        sc = next(s for s in SCENARIOS if s.id == "SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE")
        stage_names = [st.name for st in sc.stages]
        assert "initial_auth_attempt" in stage_names
        assert "successful_auth" in stage_names
        assert "persistence" in stage_names
        assert sc.confidence_bonus == 0.35
        assert sc.window_seconds == 600

    def test_ransomware_precursor_scenario_structure(self) -> None:
        """RANSOMWARE_PRECURSOR 시나리오 세부 구조 확인."""
        sc = next(s for s in SCENARIOS if s.id == "RANSOMWARE_PRECURSOR")
        stage_names = [st.name for st in sc.stages]
        assert "discovery" in stage_names
        assert "encryption_prep" in stage_names
        assert sc.auto_severity == "critical"

    def test_lateral_movement_has_min_distinct_assets(self) -> None:
        """LATERAL_MOVEMENT 시나리오의 multi_asset_auth 스테이지에 min_distinct_assets >= 3이 설정되어 있는지 확인."""
        sc = next(s for s in SCENARIOS if s.id == "LATERAL_MOVEMENT")
        stage = sc.stages[0]
        assert stage.min_distinct_assets >= 3


# ---------------------------------------------------------------------------
# Section 3: AttackChainMatcher 회귀 테스트
# ---------------------------------------------------------------------------

class TestAttackChainMatcher:
    """AttackChainMatcher.process_signal() 회귀 테스트 (fakeredis 사용)."""

    async def test_single_signal_returns_none(self, fake_redis) -> None:
        """단일 룰 시그널만으로는 시나리오가 완성되지 않아야 한다."""
        matcher = AttackChainMatcher(fake_redis)
        scenario, bonus = await matcher.process_signal(
            tenant_id="bas-tenant",
            signal_rule_id="AUTH-001",
            source_ip="10.0.0.1",
            asset_id="asset-001",
            now=1000.0,
        )
        assert scenario is None
        assert bonus == 0.0

    async def test_unknown_rule_returns_none(self, fake_redis) -> None:
        """RULE_TO_STAGES에 없는 룰 ID는 (None, 0.0)을 반환해야 한다."""
        matcher = AttackChainMatcher(fake_redis)
        scenario, bonus = await matcher.process_signal(
            tenant_id="bas-tenant",
            signal_rule_id="UNKNOWN-999",
            source_ip="10.0.0.2",
            asset_id="asset-001",
            now=1000.0,
        )
        assert scenario is None
        assert bonus == 0.0

    async def test_ssh_compromise_completes_with_full_chain(self, fake_redis) -> None:
        """AUTH-001 -> AUTH-004 -> PERSIST-001 순서로 시그널 입력 시 SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE 완성."""
        matcher = AttackChainMatcher(fake_redis)
        source_ip = "185.12.34.56"
        tenant = "bas-tenant"
        asset = "asset-ssh"
        base_ts = 1000.0

        # Stage 1: initial_auth_attempt (AUTH-001)
        sc1, b1 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="AUTH-001",
            source_ip=source_ip, asset_id=asset, now=base_ts,
        )
        assert sc1 is None, "첫 번째 스테이지만으로는 시나리오 완성 불가"

        # Stage 2: successful_auth (AUTH-004)
        sc2, b2 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="AUTH-004",
            source_ip=source_ip, asset_id=asset, now=base_ts + 30,
        )
        assert sc2 is None, "두 번째 스테이지만으로는 시나리오 완성 불가"

        # Stage 3: persistence (PERSIST-001) — 시나리오 완성
        sc3, b3 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="PERSIST-001",
            source_ip=source_ip, asset_id=asset, now=base_ts + 60,
        )
        assert sc3 is not None, "3단계 완료 후 시나리오가 완성되어야 함"
        assert sc3.id == "SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE"
        assert b3 == sc3.confidence_bonus

    async def test_privilege_escalation_scenario(self, fake_redis) -> None:
        """AUTH-002 -> ESCALATE-001 순서로 PRIVILEGE_ESCALATION 시나리오 완성."""
        matcher = AttackChainMatcher(fake_redis)
        source_ip = "99.88.77.66"
        tenant = "bas-tenant"
        asset = "asset-priv"
        base_ts = 2000.0

        # Stage 1: credential_access (AUTH-002)
        sc1, _ = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="AUTH-002",
            source_ip=source_ip, asset_id=asset, now=base_ts,
        )
        assert sc1 is None

        # Stage 2: escalation (ESCALATE-001)
        sc2, b2 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="ESCALATE-001",
            source_ip=source_ip, asset_id=asset, now=base_ts + 60,
        )
        assert sc2 is not None
        assert sc2.id == "PRIVILEGE_ESCALATION"
        assert b2 == 0.30

    async def test_ransomware_precursor_scenario(self, fake_redis) -> None:
        """EXEC-001 -> EXEC-003 순서로 RANSOMWARE_PRECURSOR 시나리오 완성."""
        matcher = AttackChainMatcher(fake_redis)
        source_ip = "55.44.33.22"
        tenant = "bas-tenant"
        asset = "asset-ransom"
        base_ts = 3000.0

        # Stage 1: discovery (EXEC-001)
        sc1, _ = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="EXEC-001",
            source_ip=source_ip, asset_id=asset, now=base_ts,
        )
        assert sc1 is None

        # Stage 2: encryption_prep (EXEC-003)
        sc2, b2 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="EXEC-003",
            source_ip=source_ip, asset_id=asset, now=base_ts + 30,
        )
        assert sc2 is not None
        assert sc2.id == "RANSOMWARE_PRECURSOR"
        assert b2 == sc2.confidence_bonus

    async def test_webshell_infiltration_required_stages(self, fake_redis) -> None:
        """WEB-001 -> EXEC-002 순서로 WEBSHELL_INFILTRATION 시나리오 완성 (WEB-HNY-001은 optional)."""
        matcher = AttackChainMatcher(fake_redis)
        source_ip = "77.66.55.44"
        tenant = "bas-tenant"
        asset = "asset-web"
        base_ts = 4000.0

        # Stage 2 (required): web_shell_access (WEB-001)
        sc1, _ = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="WEB-001",
            source_ip=source_ip, asset_id=asset, now=base_ts,
        )
        assert sc1 is None

        # Stage 3 (required): code_execution (EXEC-002)
        sc2, b2 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="EXEC-002",
            source_ip=source_ip, asset_id=asset, now=base_ts + 60,
        )
        assert sc2 is not None
        assert sc2.id == "WEBSHELL_INFILTRATION"
        assert b2 == 0.35

    async def test_process_signal_returns_tuple(self, fake_redis) -> None:
        """process_signal()이 항상 (scenario, bonus) 튜플을 반환하는지 확인."""
        matcher = AttackChainMatcher(fake_redis)
        result = await matcher.process_signal(
            tenant_id="bas-tenant",
            signal_rule_id="AUTH-001",
            source_ip="1.2.3.4",
            asset_id="asset-001",
            now=500.0,
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        scenario, bonus = result
        assert scenario is None or hasattr(scenario, "id")
        assert isinstance(bonus, float)

    async def test_scenario_expires_after_window(self, fake_redis) -> None:
        """window_seconds를 초과한 신호는 시나리오 진행 상태를 초기화해야 한다."""
        matcher = AttackChainMatcher(fake_redis)
        source_ip = "44.33.22.11"
        tenant = "bas-tenant"
        asset = "asset-expire"

        # RANSOMWARE_PRECURSOR window = 180초
        sc1, _ = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="EXEC-001",
            source_ip=source_ip, asset_id=asset, now=1000.0,
        )
        assert sc1 is None

        # 윈도우(180초) 초과 후 다음 스테이지 신호
        sc2, b2 = await matcher.process_signal(
            tenant_id=tenant, signal_rule_id="EXEC-003",
            source_ip=source_ip, asset_id=asset, now=1000.0 + 181,
        )
        # 윈도우 만료로 EXEC-001 상태가 리셋되어 EXEC-003 단독으로는 완성 불가
        assert sc2 is None


# ---------------------------------------------------------------------------
# Section 4: 탐지 룰 BAS 시뮬레이션
# ---------------------------------------------------------------------------

class TestDetectionRulesBASSimulation:
    """실제 탐지 룰 함수를 이용한 BAS 시뮬레이션 테스트."""

    # WEB-HNY-001 테스트 -------------------------------------------------------

    async def test_web_hny_001_detects_env_honeypot_path(self, fake_redis) -> None:
        """WEB-HNY-001: /.env 경로 접근이 탐지되어야 한다."""
        event = _web_event(request_path="/.env", status_code=200)
        signal = await evaluate_honeypot(fake_redis, event)
        assert signal is not None
        assert signal.rule_id == RuleId.WEB_HONEYPOT

    async def test_web_hny_001_detects_wp_login_honeypot(self, fake_redis) -> None:
        """WEB-HNY-001: /wp-login.php 경로 접근이 탐지되어야 한다."""
        event = _web_event(request_path="/wp-login.php", status_code=200)
        signal = await evaluate_honeypot(fake_redis, event)
        assert signal is not None
        assert signal.rule_id == RuleId.WEB_HONEYPOT

    async def test_web_hny_001_detects_phpmyadmin_honeypot(self, fake_redis) -> None:
        """WEB-HNY-001: /phpmyadmin 경로 접근이 탐지되어야 한다."""
        event = _web_event(request_path="/phpmyadmin", status_code=200)
        signal = await evaluate_honeypot(fake_redis, event)
        assert signal is not None
        assert "phpmyadmin" in (signal.notes or "").lower()

    async def test_web_hny_001_normal_path_not_detected(self, fake_redis) -> None:
        """WEB-HNY-001: 일반 경로는 탐지하지 않아야 한다."""
        event = _web_event(request_path="/api/v1/users", status_code=200)
        signal = await evaluate_honeypot(fake_redis, event)
        assert signal is None

    async def test_web_hny_001_demo_path_sets_is_demo(self, fake_redis) -> None:
        """WEB-HNY-001: /demo 경로는 is_demo=True로 탐지되어야 한다."""
        event = _web_event(request_path="/demo", status_code=200)
        signal = await evaluate_honeypot(fake_redis, event)
        assert signal is not None
        assert signal.is_demo is True

    # WEB-005: SQL Injection 테스트 -------------------------------------------

    async def test_web_005_detects_union_select(self, fake_redis) -> None:
        """WEB-005: UNION SELECT 패턴을 SQLi로 탐지해야 한다."""
        path = "/search?q=1 UNION SELECT username,password FROM users"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SQL_INJECTION in rule_ids

    async def test_web_005_detects_drop_table(self, fake_redis) -> None:
        """WEB-005: DROP TABLE 패턴을 SQLi로 탐지해야 한다."""
        path = "/admin/delete?id=1;drop+table+users"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SQL_INJECTION in rule_ids

    async def test_web_005_detects_sleep_injection(self, fake_redis) -> None:
        """WEB-005: sleep() 기반 시간 지연 SQLi 패턴을 탐지해야 한다."""
        path = "/login?user=admin%27+AND+sleep(5)--"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SQL_INJECTION in rule_ids

    async def test_web_005_normal_query_not_detected(self, fake_redis) -> None:
        """WEB-005: 정상 쿼리 파라미터는 SQLi로 탐지하지 않아야 한다."""
        path = "/products?name=widget&category=tools"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SQL_INJECTION not in rule_ids

    # WEB-006: Path Traversal 테스트 ------------------------------------------

    async def test_web_006_detects_dotdot_traversal(self, fake_redis) -> None:
        """WEB-006: ../../ 경로 탈출 패턴을 탐지해야 한다."""
        path = "/files/../../../../etc/passwd"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_PATH_TRAVERSAL in rule_ids

    async def test_web_006_detects_etc_passwd(self, fake_redis) -> None:
        """WEB-006: /etc/passwd 직접 접근 패턴을 탐지해야 한다."""
        path = "/download?file=/etc/passwd"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_PATH_TRAVERSAL in rule_ids

    async def test_web_006_detects_url_encoded_traversal(self, fake_redis) -> None:
        """WEB-006: URL 인코딩된 %2e%2e/ 탈출 패턴을 탐지해야 한다."""
        path = "/app/%2e%2e/%2e%2e/%2e%2e/etc/shadow"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_PATH_TRAVERSAL in rule_ids

    async def test_web_006_normal_path_not_detected(self, fake_redis) -> None:
        """WEB-006: 정상 경로는 Path Traversal로 탐지하지 않아야 한다."""
        path = "/static/css/main.css"
        event = _web_event(request_path=path, status_code=200)
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_PATH_TRAVERSAL not in rule_ids

    # EXEC-001 / TAMPER-001 — 신뢰도 테이블 BAS 확인 --------------------------

    def test_exec_001_in_confidence_table(self) -> None:
        """EXEC-001: RULE_CONFIDENCE_TABLE에 등록되어 있어야 한다."""
        assert "EXEC-001" in RULE_CONFIDENCE_TABLE
        assert RULE_CONFIDENCE_TABLE["EXEC-001"] >= 0.80

    def test_exec_001_confidence_with_tmp_execution_context(self) -> None:
        """EXEC-001: /tmp 경로 실행 시뮬레이션 — prod + public 자산에서 높은 점수."""
        score, breakdown = calculate_detection_confidence(
            "EXEC-001",
            environment="prod",
            exposure="public",
            is_known_ip=False,
        )
        # base(0.85) + prod(0.10) + public(0.07) + novelty(0.08) = 1.10 -> cap 1.0
        assert score >= 0.90, f"EXEC-001 BAS score too low: {score}"
        assert breakdown["rule_confidence"] == 0.85

    def test_tamper_001_in_confidence_table(self) -> None:
        """TAMPER-001: RULE_CONFIDENCE_TABLE에 등록되어 있어야 한다."""
        assert "TAMPER-001" in RULE_CONFIDENCE_TABLE
        assert RULE_CONFIDENCE_TABLE["TAMPER-001"] >= 0.70

    def test_tamper_001_confidence_with_agent_stop_context(self) -> None:
        """TAMPER-001: 에이전트 프로세스 중지 시뮬레이션 — CTI 악성 IP + prod 자산에서 높은 점수."""
        score, breakdown = calculate_detection_confidence(
            "TAMPER-001",
            environment="prod",
            cti_is_known_malicious=True,
            correlation_bonus=0.20,
        )
        # base(0.75) + prod(0.10) + cti(0.20) + corr(0.20) = 1.25 -> cap 1.0
        assert score >= 0.90, f"TAMPER-001 BAS score too low: {score}"
        assert breakdown["rule_confidence"] == 0.75

    def test_persist_001_in_confidence_table_high_base(self) -> None:
        """PERSIST-001: RULE_CONFIDENCE_TABLE에 높은 기본 점수(>=0.85)로 등록되어 있어야 한다."""
        assert "PERSIST-001" in RULE_CONFIDENCE_TABLE
        assert RULE_CONFIDENCE_TABLE["PERSIST-001"] >= 0.85

    # WEB-001: Web Shell 탐지 --------------------------------------------------

    async def test_web_001_detects_php_upload_webshell(self, fake_redis) -> None:
        """WEB-001: /uploads/shell.php HTTP 200 접근이 탐지되어야 한다."""
        event = _web_event(
            request_path="/uploads/shell.php",
            status_code=200,
        )
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SHELL_ACCESS in rule_ids

    async def test_web_001_not_fired_for_404(self, fake_redis) -> None:
        """WEB-001: /uploads/shell.php HTTP 404는 웹쉘로 탐지하지 않아야 한다."""
        event = _web_event(
            request_path="/uploads/shell.php",
            status_code=404,
        )
        signals = await evaluate_web_rules(fake_redis, event)
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_SHELL_ACCESS not in rule_ids


# ---------------------------------------------------------------------------
# Section 5: Benign 픽스처 — False Positive 방지 테스트 (설계서 v3 §9.3)
#
# "benign 케이스는 Critical/High Incident를 생성하지 않아야 한다"
# 각 픽스처 파일이 존재하고, 정상 트래픽 패턴을 담고 있음을 검증한다.
# ---------------------------------------------------------------------------

class TestBenignFixtures:
    """Benign 픽스처 파일 존재 여부 + confidence 패널티 동작 검증.

    설계서 v3 §9.1:
      - deploy_traffic.jsonl           → CI/CD allowlisted IP, no Critical
      - admin_maintenance_window.jsonl → Maintenance Window 중 정상 작업, 억제 필요
      - internal_monitoring.jsonl      → Prometheus/K8s 내부 allowlisted IP, 차단 금지
      - legitimate_admin_login.jsonl   → 정상 관리자 로그인, False Positive 없어야 함
    """

    FIXTURES_DIR = (
        Path(__file__).resolve().parent
        / "detection" / "fixtures" / "benign"
    )

    # ── 픽스처 파일 존재 확인 ──────────────────────────────────────────────

    def test_deploy_traffic_fixture_exists(self) -> None:
        """deploy_traffic.jsonl 픽스처 파일이 존재해야 한다."""
        assert (self.FIXTURES_DIR / "deploy_traffic.jsonl").exists()

    def test_admin_maintenance_window_fixture_exists(self) -> None:
        """admin_maintenance_window.jsonl 픽스처 파일이 존재해야 한다."""
        assert (self.FIXTURES_DIR / "admin_maintenance_window.jsonl").exists()

    def test_internal_monitoring_fixture_exists(self) -> None:
        """internal_monitoring.jsonl 픽스처 파일이 존재해야 한다."""
        assert (self.FIXTURES_DIR / "internal_monitoring.jsonl").exists()

    def test_legitimate_admin_login_fixture_exists(self) -> None:
        """legitimate_admin_login.jsonl 픽스처 파일이 존재해야 한다."""
        assert (self.FIXTURES_DIR / "legitimate_admin_login.jsonl").exists()

    # ── 픽스처 내용 유효성 확인 ───────────────────────────────────────────

    def test_all_benign_fixtures_are_valid_jsonl(self) -> None:
        """모든 benign JSONL 픽스처가 유효한 JSON Lines 형식이어야 한다."""
        import json
        for fixture_file in self.FIXTURES_DIR.glob("*.jsonl"):
            with open(fixture_file) as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            assert len(lines) > 0, f"{fixture_file.name}: 빈 파일"
            for i, line in enumerate(lines, 1):
                try:
                    json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AssertionError(
                        f"{fixture_file.name}:{i} — 유효하지 않은 JSON: {exc}"
                    )

    def test_admin_maintenance_window_fixture_has_maintenance_flag(self) -> None:
        """admin_maintenance_window.jsonl 이벤트는 maintenance_window=true 플래그를 가져야 한다."""
        import json
        fixture = self.FIXTURES_DIR / "admin_maintenance_window.jsonl"
        with open(fixture) as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        maintenance_flagged = [e for e in events if e.get("maintenance_window")]
        assert len(maintenance_flagged) >= 5, (
            f"유지보수 창 플래그가 충분하지 않음: {len(maintenance_flagged)}개"
        )

    def test_internal_monitoring_fixture_has_allowlisted_flag(self) -> None:
        """internal_monitoring.jsonl 이벤트는 allowlisted=true 플래그를 가져야 한다."""
        import json
        fixture = self.FIXTURES_DIR / "internal_monitoring.jsonl"
        with open(fixture) as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        allowlisted = [e for e in events if e.get("allowlisted")]
        assert len(allowlisted) >= 5, (
            f"Allowlist 플래그가 충분하지 않음: {len(allowlisted)}개"
        )

    # ── Confidence 패널티 동작 검증 ────────────────────────────────────────

    def test_allowlist_penalty_suppresses_critical_threshold(self) -> None:
        """Allowlist 트래픽은 confidence 패널티로 Critical 임계값(0.85) 미만이어야 한다.

        설계서 v3 §3.1: in_allowlist → penalty += 0.60
        AUTH-001 base=0.70: 0.70 - 0.60 = 0.10 → 자동 차단 임계값 미달
        """
        score, breakdown = calculate_detection_confidence(
            "AUTH-001",
            in_allowlist=True,
        )
        assert score < 0.85, (
            f"Allowlist 트래픽이 Critical 임계값을 초과함: {score:.3f}"
        )
        assert breakdown["penalty"] < 0, "Allowlist 패널티는 음수여야 한다"

    def test_maintenance_window_penalty_suppresses_score(self) -> None:
        """Maintenance Window 트래픽은 신뢰도가 충분히 낮아야 한다.

        설계서 v3 §3.1: in_maintenance_window → penalty += 0.30
        AUTH-001 base=0.70: 0.70 - 0.30 = 0.40 → alert 임계값 미달 가능
        """
        score, breakdown = calculate_detection_confidence(
            "AUTH-001",
            in_maintenance_window=True,
        )
        assert score <= 0.50, (
            f"Maintenance Window 트래픽 신뢰도가 너무 높음: {score:.3f}"
        )

    def test_benign_pattern_penalty_reduces_score(self) -> None:
        """정상 배포 패턴은 benign_pattern 패널티를 받아야 한다.

        설계서 v3 §3.1: matches_benign_pattern → penalty += 0.20
        """
        score_with_penalty, _ = calculate_detection_confidence(
            "AUTH-001",
            matches_benign_pattern=True,
        )
        score_without_penalty, _ = calculate_detection_confidence(
            "AUTH-001",
            matches_benign_pattern=False,
        )
        assert score_with_penalty < score_without_penalty, (
            "Benign 패턴 패널티가 점수를 낮춰야 한다"
        )

    def test_deploy_traffic_no_honeypot_path(self) -> None:
        """deploy_traffic.jsonl의 경로는 Honeypot 탐지 대상이 아니어야 한다."""
        import json
        fixture = self.FIXTURES_DIR / "deploy_traffic.jsonl"
        honeypot_patterns = {
            "/.env", "/phpmyadmin", "/wp-admin", "/wp-login.php",
            "/admin.php", "/shell.php", "/.git/config",
        }
        with open(fixture) as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        web_events = [e for e in events if "path" in e]
        for event in web_events:
            path = event["path"]
            for pattern in honeypot_patterns:
                assert pattern not in path, (
                    f"deploy_traffic 픽스처에 Honeypot 경로 포함됨: {path}"
                )
