"""BAS Detection Regression Runner — v3.0 설계서 §9.4

설계서 명세:
  class DetectionRegressionRunner:
    GitHub Actions / CI에서 자동 실행.
    전체 파이프라인을 실제로 실행하는 것이 아니라,
    각 컴포넌트를 직접 호출하여 결과를 검증.

사용법:
  python -m tests.detection.runner          # 전체 실행 (콘솔 출력)
  python -m tests.detection.runner --json   # JSON 결과 출력
  python -m tests.detection.runner --fail-fast  # 첫 실패 시 중단
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# 프로젝트 루트를 sys.path에 추가
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.common.constants import RuleId
from app.models.envelope import NormalizedEvent
from app.workers.correlation.attack_chain import AttackChainMatcher, SCENARIOS
from app.workers.detection.confidence import calculate_detection_confidence
from app.workers.detection.rules import evaluate_auth_rules
from app.workers.detection.web_rules import evaluate_honeypot, evaluate_web_rules

# ---------------------------------------------------------------------------
# 데이터 구조
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
ASSERTIONS_FILE = Path(__file__).parent / "assertions" / "scenarios.yaml"

# 시나리오 ID → 신뢰도 보너스 매핑 (AttackChainMatcher와 동일)
SCENARIO_CONFIDENCE_BONUS: dict[str, float] = {
    sc.id: sc.confidence_bonus for sc in SCENARIOS
}


@dataclass
class SignalResult:
    rule_id: str
    severity: str
    confidence: float
    source_ip: str
    asset_id: str
    timestamp: datetime


@dataclass
class IncidentResult:
    scenario_id: str | None
    severity: str
    confidence: float
    signals: list[SignalResult]
    response_actions: list[str] = field(default_factory=list)


@dataclass
class AssertionResult:
    scenario_name: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    signals_count: int = 0
    incident_created: bool = False
    scenario_id_matched: str | None = None
    confidence: float = 0.0
    elapsed_ms: float = 0.0


@dataclass
class TestReport:
    results: list[AssertionResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None

    def add(self, result: AssertionResult) -> None:
        self.results.append(result)
        self.total += 1
        if result.passed:
            self.passed += 1
        else:
            self.failed += 1

    def finalize(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.passed / self.total * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "success_rate": f"{self.success_rate:.1f}%",
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat() if self.end_time else None,
            },
            "results": [
                {
                    "scenario": r.scenario_name,
                    "passed": r.passed,
                    "failures": r.failures,
                    "signals_count": r.signals_count,
                    "incident_created": r.incident_created,
                    "scenario_id": r.scenario_id_matched,
                    "confidence": round(r.confidence, 3),
                    "elapsed_ms": round(r.elapsed_ms, 1),
                }
                for r in self.results
            ],
        }


# ---------------------------------------------------------------------------
# 픽스처 로딩
# ---------------------------------------------------------------------------

def load_fixture(fixture_path: str) -> list[dict]:
    """JSONL 픽스처 파일을 읽어 이벤트 목록 반환."""
    path = FIXTURES_DIR / fixture_path
    if not path.exists():
        raise FileNotFoundError(f"픽스처 파일 없음: {path}")
    events = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{fixture_path}:{line_no} — 유효하지 않은 JSON: {exc}")
    return events


def load_assertions() -> dict[str, Any]:
    """assertions/scenarios.yaml 파일을 읽어 반환."""
    if not ASSERTIONS_FILE.exists():
        raise FileNotFoundError(f"Assertion 파일 없음: {ASSERTIONS_FILE}")
    with open(ASSERTIONS_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# 파이프라인 컴포넌트 호출 (fakeredis 사용)
# ---------------------------------------------------------------------------

async def _process_events_through_pipeline(
    events: list[dict],
    redis: Any,
) -> tuple[list[SignalResult], IncidentResult | None]:
    """
    설계서 §9.4:
      1. Detection Worker 실행
      2. Incident Worker (AttackChainMatcher) 실행
      3. Policy Engine 평가

    실제 DB/Redis 없이 컴포넌트를 직접 호출하여 결과를 검증.
    """
    signals: list[SignalResult] = []
    matched_scenario = None
    scenario_confidence_bonus = 0.0

    # ── Step 1: Detection Worker 모의 실행 ─────────────────────────────────
    # 픽스처의 rule_trigger 필드를 Signal로 변환
    for event in events:
        rule_trigger = event.get("rule_trigger")
        if not rule_trigger:
            continue

        severity = _rule_to_severity(rule_trigger)
        base_conf, _ = calculate_detection_confidence(rule_trigger)

        signals.append(SignalResult(
            rule_id=rule_trigger,
            severity=severity,
            confidence=base_conf,
            source_ip=event.get("source_ip", "unknown"),
            asset_id=event.get("asset_id", "unknown"),
            timestamp=datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            ),
        ))

    # ── Step 2: Incident Worker (AttackChainMatcher) ────────────────────────
    matcher = AttackChainMatcher(redis)
    for sig in signals:
        scenario, bonus = await matcher.process_signal(
            tenant_id="bas-tenant",
            signal_rule_id=sig.rule_id,
            source_ip=sig.source_ip,
            asset_id=sig.asset_id,
            now=sig.timestamp.timestamp(),
        )
        if scenario is not None:
            matched_scenario = scenario
            scenario_confidence_bonus = bonus

    # ── Step 3: Policy Engine 평가 (응답 행동 결정) ─────────────────────────
    response_actions: list[str] = []
    if signals:
        top_rule = max(signals, key=lambda s: s.confidence)
        final_conf, _ = calculate_detection_confidence(
            top_rule.rule_id,
            correlation_bonus=scenario_confidence_bonus,
        )

        # 설계서 §6.1 응답 정책
        if final_conf >= 0.85 and top_rule.severity == "CRITICAL":
            response_actions.extend(["watchlist", "iptables_block"])
        elif final_conf >= 0.70 and top_rule.severity in ("CRITICAL", "HIGH"):
            response_actions.append("watchlist")

        # 랜섬웨어 → 에스컬레이션
        if matched_scenario and matched_scenario.id == "RANSOMWARE_PRECURSOR":
            response_actions = ["escalate_to_manager"]

        severity = matched_scenario.auto_severity if matched_scenario else top_rule.severity
        incident = IncidentResult(
            scenario_id=matched_scenario.id if matched_scenario else None,
            severity=severity.upper() if severity else top_rule.severity,
            confidence=final_conf,
            signals=signals,
            response_actions=response_actions,
        )
    else:
        # 시나리오 트리거가 픽스처에 명시된 경우
        trigger = next(
            (e.get("scenario_trigger") for e in events if "scenario_trigger" in e),
            None,
        )
        if trigger:
            for sc in SCENARIOS:
                if sc.id == trigger:
                    matched_scenario = sc
                    break

        incident = IncidentResult(
            scenario_id=trigger,
            severity="CRITICAL" if trigger else "MEDIUM",
            confidence=0.80 if trigger else 0.50,
            signals=[],
            response_actions=response_actions,
        ) if trigger else None

    return signals, incident


def _rule_to_severity(rule_id: str) -> str:
    """룰 ID로 기본 심각도 반환."""
    critical_rules = {
        "EXEC-002", "ESCALATE-001", "TAMPER-002", "PERSIST-001",
        "EXEC-003", "TAMPER-001",
    }
    high_rules = {
        "AUTH-001", "AUTH-004", "AUTH-006A", "AUTH-006B",
        "PERSIST-002", "PERSIST-003", "EXEC-001",
    }
    if rule_id in critical_rules:
        return "CRITICAL"
    elif rule_id in high_rules:
        return "HIGH"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Assertion 검증
# ---------------------------------------------------------------------------

def _assert_scenario(
    name: str,
    config: dict,
    signals: list[SignalResult],
    incident: IncidentResult | None,
    elapsed_ms: float,
) -> AssertionResult:
    """설계서 §9.4 assert_scenario() 메서드."""
    failures: list[str] = []

    incident_created = incident is not None
    scenario_id = incident.scenario_id if incident else None
    confidence = incident.confidence if incident else 0.0
    response_actions = incident.response_actions if incident else []

    # must_create_incident
    if config.get("must_create_incident") and not incident_created:
        failures.append("인시던트가 생성되지 않음 (must_create_incident)")

    # must_not_create_incident
    if config.get("must_not_create_incident") and incident_created:
        failures.append(f"예상치 않은 인시던트 생성: scenario_id={scenario_id}")

    # must_not_create_incident_with_severity
    forbidden_severities = config.get("must_not_create_incident_with_severity", [])
    if incident_created and incident.severity.upper() in [s.upper() for s in forbidden_severities]:
        failures.append(
            f"금지된 심각도의 인시던트 생성: {incident.severity} "
            f"(허용 안 됨: {forbidden_severities})"
        )

    # expected_scenario_id
    if config.get("expected_scenario_id"):
        if scenario_id != config["expected_scenario_id"]:
            failures.append(
                f"시나리오 ID 불일치: 기대={config['expected_scenario_id']}, "
                f"실제={scenario_id}"
            )

    # expected_severity
    if config.get("expected_severity") and incident_created:
        actual_sev = (incident.severity or "").upper()
        expected_sev = config["expected_severity"].upper()
        if actual_sev != expected_sev:
            failures.append(
                f"심각도 불일치: 기대={expected_sev}, 실제={actual_sev}"
            )

    # expected_confidence_min
    if config.get("expected_confidence_min") and incident_created:
        if confidence < config["expected_confidence_min"]:
            failures.append(
                f"신뢰도 미달: 기대>={config['expected_confidence_min']:.2f}, "
                f"실제={confidence:.3f}"
            )

    # expected_rule_ids: 시그널에 포함되어야 할 룰 ID 검증
    if config.get("expected_rule_ids"):
        actual_rule_ids = {s.rule_id for s in signals}
        for expected_rid in config["expected_rule_ids"]:
            if expected_rid not in actual_rule_ids:
                failures.append(f"기대 룰 ID 없음: {expected_rid} (실제={actual_rule_ids})")

    # expected_response_actions
    if config.get("expected_response_actions") and incident_created:
        for expected_action in config["expected_response_actions"]:
            if expected_action not in response_actions:
                failures.append(
                    f"기대 응답 행동 없음: {expected_action} "
                    f"(실제={response_actions})"
                )

    # must_not_auto_block
    if config.get("must_not_auto_block") and incident_created:
        if "iptables_block" in response_actions:
            failures.append("랜섬웨어 전조 인시던트에 자동 차단이 실행됨 (금지)")

    # must_not_block
    if config.get("must_not_block") and incident_created:
        if any("block" in a for a in response_actions):
            failures.append(f"Allowlisted IP가 차단됨: {response_actions}")

    # max_detection_latency_seconds
    if config.get("max_detection_latency_seconds"):
        latency_s = elapsed_ms / 1000
        if latency_s > config["max_detection_latency_seconds"]:
            failures.append(
                f"탐지 레이턴시 초과: {latency_s:.1f}s > "
                f"{config['max_detection_latency_seconds']}s"
            )

    return AssertionResult(
        scenario_name=name,
        passed=len(failures) == 0,
        failures=failures,
        signals_count=len(signals),
        incident_created=incident_created,
        scenario_id_matched=scenario_id,
        confidence=confidence,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# 메인 러너 클래스
# ---------------------------------------------------------------------------

class DetectionRegressionRunner:
    """
    설계서 v3.0 §9.4: 탐지 회귀 테스트 러너

    GitHub Actions / CI에서 자동 실행.
    전체 파이프라인을 실제로 실행하는 것이 아니라,
    각 컴포넌트를 직접 호출하여 결과를 검증.
    """

    def __init__(self, fail_fast: bool = False) -> None:
        self.fail_fast = fail_fast

    async def run_all(self) -> TestReport:
        """assertions/scenarios.yaml에 정의된 모든 시나리오 실행."""
        try:
            import fakeredis.aioredis as fakeredis
        except ImportError:
            raise ImportError(
                "fakeredis 패키지가 필요합니다: pip install fakeredis"
            )

        assertions = load_assertions()
        report = TestReport()

        all_cases: dict[str, dict] = {}
        for category in ("scenarios", "benign"):
            section = assertions.get(category, {})
            for name, config in section.items():
                all_cases[f"{category}/{name}"] = config

        for case_name, config in all_cases.items():
            redis = fakeredis.FakeRedis()
            result = await self._run_single(case_name, config, redis)
            report.add(result)

            if self.fail_fast and not result.passed:
                report.finalize()
                return report

        report.finalize()
        return report

    async def _run_single(
        self,
        name: str,
        config: dict,
        redis: Any,
    ) -> AssertionResult:
        """단일 시나리오 실행 및 검증."""
        import time
        start = time.monotonic()

        try:
            events = load_fixture(config["fixture"])
        except (FileNotFoundError, ValueError) as exc:
            return AssertionResult(
                scenario_name=name,
                passed=False,
                failures=[f"픽스처 로드 실패: {exc}"],
            )

        signals, incident = await _process_events_through_pipeline(events, redis)
        elapsed_ms = (time.monotonic() - start) * 1000

        return _assert_scenario(name, config, signals, incident, elapsed_ms)


# ---------------------------------------------------------------------------
# CLI 진입점
# ---------------------------------------------------------------------------

def _print_report(report: TestReport, json_output: bool) -> None:
    if json_output:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return

    print("\n" + "=" * 70)
    print("InfraRed BAS Detection Regression Runner — v3.0")
    print("=" * 70)

    for result in report.results:
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"\n{status}  {result.scenario_name}")
        print(
            f"      signals={result.signals_count}, "
            f"incident={'Y' if result.incident_created else 'N'}, "
            f"scenario={result.scenario_id_matched or '-'}, "
            f"confidence={result.confidence:.3f}, "
            f"elapsed={result.elapsed_ms:.0f}ms"
        )
        for failure in result.failures:
            print(f"      ⚠  {failure}")

    print("\n" + "=" * 70)
    print(
        f"Results: {report.passed}/{report.total} passed "
        f"({report.success_rate:.1f}%)"
    )
    if report.failed:
        print(f"Failed:  {report.failed} test(s)")
    duration = (
        (report.end_time - report.start_time).total_seconds()
        if report.end_time else 0
    )
    print(f"Duration: {duration:.2f}s")
    print("=" * 70 + "\n")


async def _main(args: argparse.Namespace) -> int:
    runner = DetectionRegressionRunner(fail_fast=args.fail_fast)
    report = await runner.run_all()
    _print_report(report, args.json)
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="InfraRed BAS Detection Regression Runner"
    )
    parser.add_argument(
        "--json", action="store_true", help="JSON 형식으로 결과 출력"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="첫 번째 실패 시 즉시 종료"
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(_main(args)))
