"""공격 체인 상관분석 엔진 (설계서 v3).

5개의 Named Attack Scenario를 정의하고, 시그널이 들어올 때마다
Redis에 진행 상태를 추적하여 시나리오가 완성되면 (scenario, bonus)를 반환한다.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from redis.asyncio import Redis

from app.redis_kv import keys


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ScenarioStage:
    name: str
    rule_ids: list[str]
    required: bool = True
    min_distinct_assets: int = 1


@dataclass
class AttackScenario:
    id: str
    display_name: str
    window_seconds: int
    auto_severity: str
    confidence_bonus: float
    stages: list[ScenarioStage]


@dataclass
class ScenarioState:
    scenario_id: str
    completed_stages: list[str]
    first_seen_at: float  # unix timestamp
    source_ip: str
    asset_id: str


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

SCENARIOS: list[AttackScenario] = [
    AttackScenario(
        id="SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE",
        display_name="SSH Account Compromise with Persistence",
        window_seconds=600,
        auto_severity="critical",
        confidence_bonus=0.35,
        stages=[
            ScenarioStage(
                name="initial_auth_attempt",
                rule_ids=["AUTH-001", "AUTH-006A", "AUTH-006B"],
                required=True,
            ),
            ScenarioStage(
                name="successful_auth",
                rule_ids=["AUTH-004"],
                required=True,
            ),
            ScenarioStage(
                name="persistence",
                rule_ids=["PERSIST-001", "FIM-001", "PERSIST-002", "PERSIST-003"],
                required=True,
            ),
        ],
    ),
    AttackScenario(
        id="WEBSHELL_INFILTRATION",
        display_name="Webshell Infiltration",
        window_seconds=1200,
        auto_severity="critical",
        confidence_bonus=0.35,
        stages=[
            ScenarioStage(
                name="honeypot_probe",
                rule_ids=["WEB-HNY-001"],
                required=False,
            ),
            ScenarioStage(
                name="web_shell_access",
                rule_ids=["WEB-001"],
                required=True,
            ),
            ScenarioStage(
                name="code_execution",
                rule_ids=["EXEC-002"],
                required=True,
            ),
        ],
    ),
    AttackScenario(
        id="PRIVILEGE_ESCALATION",
        display_name="Privilege Escalation",
        window_seconds=300,
        auto_severity="high",
        confidence_bonus=0.30,
        stages=[
            ScenarioStage(
                name="credential_access",
                rule_ids=["AUTH-002", "AUTH-004"],
                required=True,
            ),
            ScenarioStage(
                name="escalation",
                rule_ids=["ESCALATE-001", "FIM-005"],
                required=True,
            ),
        ],
    ),
    AttackScenario(
        id="RANSOMWARE_PRECURSOR",
        display_name="Ransomware Precursor",
        window_seconds=180,
        auto_severity="critical",
        confidence_bonus=0.30,
        stages=[
            ScenarioStage(
                name="discovery",
                rule_ids=["EXEC-001"],
                required=True,
            ),
            ScenarioStage(
                name="encryption_prep",
                rule_ids=["EXEC-003"],
                required=True,
            ),
        ],
    ),
    AttackScenario(
        id="LATERAL_MOVEMENT",
        display_name="Lateral Movement",
        window_seconds=600,
        auto_severity="high",
        confidence_bonus=0.20,
        stages=[
            ScenarioStage(
                name="multi_asset_auth",
                rule_ids=["AUTH-004"],
                required=True,
                min_distinct_assets=3,
            ),
        ],
    ),
]

# rule_id -> [(scenario, stage_index), ...]  매핑을 미리 계산해 둔다.
_RULE_TO_STAGES: dict[str, list[tuple[AttackScenario, int]]] = {}
for _sc in SCENARIOS:
    for _idx, _stage in enumerate(_sc.stages):
        for _rid in _stage.rule_ids:
            _RULE_TO_STAGES.setdefault(_rid, []).append((_sc, _idx))


# ---------------------------------------------------------------------------
# AttackChainMatcher
# ---------------------------------------------------------------------------

class AttackChainMatcher:
    """Redis를 사용해 시나리오별 진행 상태를 추적하고, 완성 시 결과를 반환한다."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process_signal(
        self,
        tenant_id: str,
        signal_rule_id: str,
        source_ip: str,
        asset_id: str,
        now: float | None = None,
    ) -> tuple[AttackScenario | None, float]:
        """시그널을 처리하고 시나리오가 완성되면 (scenario, bonus)를 반환한다.

        Args:
            tenant_id: 테넌트 식별자.
            signal_rule_id: 탐지된 룰 ID 문자열 (예: "AUTH-001").
            source_ip: 공격 소스 IP.
            asset_id: 대상 자산 ID.
            now: 현재 unix timestamp (테스트용; None이면 time.time() 사용).

        Returns:
            시나리오가 완성됐으면 (AttackScenario, confidence_bonus),
            아니면 (None, 0.0).
        """
        if now is None:
            now = time.time()

        matched_scenarios = _RULE_TO_STAGES.get(signal_rule_id, [])
        if not matched_scenarios:
            return None, 0.0

        for scenario, stage_idx in matched_scenarios:
            # LATERAL_MOVEMENT는 별도 처리
            if scenario.id == "LATERAL_MOVEMENT":
                result = await self._process_lateral_movement(
                    tenant_id, source_ip, asset_id, scenario, now
                )
                if result:
                    return scenario, scenario.confidence_bonus
                continue

            # 일반 시나리오 처리
            result = await self._process_scenario_stage(
                tenant_id, signal_rule_id, source_ip, asset_id,
                scenario, stage_idx, now,
            )
            if result:
                return scenario, scenario.confidence_bonus

        return None, 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _process_lateral_movement(
        self,
        tenant_id: str,
        source_ip: str,
        asset_id: str,
        scenario: AttackScenario,
        now: float,
    ) -> bool:
        """같은 source_ip로 접근한 distinct asset_id 수를 추적해 임계값 도달 시 True."""
        key = keys.lateral_movement_assets(tenant_id, source_ip)
        pipe = self.redis.pipeline()
        pipe.sadd(key, asset_id)
        pipe.expire(key, scenario.window_seconds)
        pipe.scard(key)
        results = await pipe.execute()
        distinct_count: int = results[2]

        required_assets = scenario.stages[0].min_distinct_assets
        return distinct_count >= required_assets

    async def _process_scenario_stage(
        self,
        tenant_id: str,
        signal_rule_id: str,
        source_ip: str,
        asset_id: str,
        scenario: AttackScenario,
        stage_idx: int,
        now: float,
    ) -> bool:
        """시나리오 진행 상태를 Redis에서 읽고 갱신한 뒤, 완성 여부를 반환한다."""
        redis_key = keys.scenario_state(scenario.id, tenant_id, source_ip)
        raw = await self.redis.get(redis_key)

        if raw is not None:
            state_dict = json.loads(raw)
            completed: list[str] = state_dict.get("completed_stages", [])
            first_seen_at: float = state_dict.get("first_seen_at", now)
        else:
            completed = []
            first_seen_at = now

        # 윈도우 만료 체크 (Redis TTL이 있지만 명시적으로 확인)
        if now - first_seen_at > scenario.window_seconds:
            completed = []
            first_seen_at = now

        stage = scenario.stages[stage_idx]
        stage_name = stage.name

        # 이미 완성된 스테이지면 스킵
        if stage_name not in completed:
            # 순서 제약: 이전 required 스테이지가 모두 완료되어 있어야 추가 가능
            if self._can_advance_to(scenario, stage_idx, completed):
                completed.append(stage_name)

        # 상태 저장
        new_state = {
            "completed_stages": completed,
            "first_seen_at": first_seen_at,
            "source_ip": source_ip,
            "asset_id": asset_id,
        }
        await self.redis.set(
            redis_key,
            json.dumps(new_state),
            ex=scenario.window_seconds,
        )

        # 완성 판정: 모든 required 스테이지가 completed에 있어야 함
        return self._is_scenario_complete(scenario, completed)

    def _can_advance_to(
        self,
        scenario: AttackScenario,
        stage_idx: int,
        completed: list[str],
    ) -> bool:
        """이전 required 스테이지가 모두 완료됐는지 확인한다."""
        for i in range(stage_idx):
            prev_stage = scenario.stages[i]
            if prev_stage.required and prev_stage.name not in completed:
                return False
        return True

    def _is_scenario_complete(
        self,
        scenario: AttackScenario,
        completed: list[str],
    ) -> bool:
        """모든 required 스테이지가 완료됐으면 True."""
        for stage in scenario.stages:
            if stage.required and stage.name not in completed:
                return False
        return True
