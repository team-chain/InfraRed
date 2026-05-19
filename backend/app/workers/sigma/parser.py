"""
SIGMA 룰 파서 + InfraRed 탐지 룰 변환.
v4.0 설계서 §8 참조.
"""
from __future__ import annotations
import re, logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class SigmaRule:
    title: str
    rule_id: str
    status: str         # stable / experimental / deprecated
    description: str
    tags: list[str]
    logsource: dict
    detection: dict
    level: str          # critical / high / medium / low / informational
    custom_meta: dict = field(default_factory=dict)


@dataclass
class DetectionRule:
    rule_id: str
    display_name: str
    source: str
    severity: str
    mitre_techniques: list[str]
    condition: Optional[Callable] = None
    base_confidence: float = 0.65
    metadata: dict = field(default_factory=dict)


LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "LOW",
}


class SigmaParser:
    """SIGMA 룰 YAML → InfraRed DetectionRule 변환"""

    def parse(self, yaml_content: str) -> Optional[SigmaRule]:
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available")
            return None
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                return None
            return SigmaRule(
                title=data.get("title", ""),
                rule_id=str(data.get("id", "")),
                status=data.get("status", "experimental"),
                description=data.get("description", ""),
                tags=data.get("tags", []),
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                level=data.get("level", "medium"),
            )
        except Exception as e:
            logger.error(f"SIGMA parse error: {e}")
            return None

    def to_infrared_rule(self, sigma: SigmaRule) -> DetectionRule:
        """SIGMA → InfraRed 내부 룰 형식"""
        mitre_tags = [t for t in sigma.tags if re.match(r"attack\.t\d+", t, re.I)]
        mitre_techniques = [t.replace("attack.", "").upper() for t in mitre_tags]

        safe_id = re.sub(r"[^a-zA-Z0-9]", "", sigma.rule_id[:8]).upper()
        rule_id = f"SIGMA-{safe_id}" if safe_id else "SIGMA-UNKNOWN"

        severity = LEVEL_TO_SEVERITY.get(sigma.level.lower(), "MEDIUM")
        base_confidence = 0.65 if sigma.status == "experimental" else 0.75

        condition_fn = self._compile_condition(sigma.detection)

        return DetectionRule(
            rule_id=rule_id,
            display_name=sigma.title,
            source="sigma_community",
            severity=severity,
            mitre_techniques=mitre_techniques,
            condition=condition_fn,
            base_confidence=base_confidence,
            metadata={
                "sigma_id": sigma.rule_id,
                "sigma_status": sigma.status,
                "sigma_title": sigma.title,
                "logsource": sigma.logsource,
                "tags": sigma.tags,
            },
        )

    def _compile_condition(self, detection: dict) -> Callable[[dict], bool]:
        """SIGMA detection 블록 → Python 평가 함수"""
        if not detection:
            return lambda e: False

        selections = {k: v for k, v in detection.items() if k != "condition"}
        condition_str = str(detection.get("condition", "selection"))

        def evaluator(event: dict) -> bool:
            results = {}
            for sel_name, criteria in selections.items():
                results[sel_name] = self._match_selection(event, criteria)

            # 조건 식 평가 (간단한 AND/OR/NOT 지원)
            expr = condition_str
            for name, result in results.items():
                expr = expr.replace(name, str(result))

            # 안전한 eval (실 운영에서는 AST 기반으로 교체)
            try:
                return bool(eval(expr, {"__builtins__": {}}, {}))
            except Exception:
                return False

        return evaluator

    def _match_selection(self, event: dict, criteria: Any) -> bool:
        """선택 조건 매칭"""
        if isinstance(criteria, dict):
            for field_expr, value in criteria.items():
                field_name = field_expr.split("|")[0]  # 파이프 수정자 제거
                modifier = field_expr.split("|")[1] if "|" in field_expr else "contains"

                event_val = str(event.get(field_name, ""))

                if isinstance(value, list):
                    if modifier == "contains":
                        if not any(str(v).lower() in event_val.lower() for v in value):
                            return False
                    elif modifier == "endswith":
                        if not any(event_val.lower().endswith(str(v).lower()) for v in value):
                            return False
                    elif modifier == "startswith":
                        if not any(event_val.lower().startswith(str(v).lower()) for v in value):
                            return False
                elif isinstance(value, str):
                    if str(value).lower() not in event_val.lower():
                        return False
                elif isinstance(value, (int, float)):
                    try:
                        if float(event_val) != float(value):
                            return False
                    except ValueError:
                        return False
        elif isinstance(criteria, list):
            return any(self._match_selection(event, c) for c in criteria)
        return True
