"""LLM Provider 인터페이스 (Phase 3-A).

설계서 3-A: AWS Bedrock Claude는 포트폴리오/컴플라이언스 가치 유지.
운영 비용 최적화를 위해 Provider 교체 가능 구조 도입.

환경변수:
  LLM_PROVIDER=bedrock   → BedrockProvider (기본, 컴플라이언스)
  LLM_PROVIDER=anthropic → AnthropicProvider (비용 최적화, claude-haiku)
  LLM_PROVIDER=static    → StaticProvider (Bedrock 없을 때 fallback)
  LLM_PROVIDER=auto      → Bedrock 설정 있으면 Bedrock, 없으면 Static
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Protocol, runtime_checkable

from app.common.logging import get_logger
from app.config import get_settings
from app.models.llm import LLMResult
from app.workers.llm.sanitizer import (
    build_safe_prompt,
    sanitize_evidence_list,
    validate_llm_output,
)
from app.workers.llm.playbook import playbook_from_contract, summarize_with_playbook

log = get_logger(__name__)


@runtime_checkable
class LLMProvider(Protocol):
    """LLM Provider 프로토콜."""
    async def analyze(self, contract: dict[str, Any]) -> LLMResult: ...


# ============================================================
# Bedrock Provider
# ============================================================

class BedrockProvider:
    """AWS Bedrock Claude 분석 Provider.

    컴플라이언스/포트폴리오 환경 기본값.
    데이터가 모델 학습에 사용되지 않고 AWS 바운더리 내에 머뭄.
    """

    async def analyze(self, contract: dict[str, Any]) -> LLMResult:
        from app.workers.llm.bedrock import analyze_with_bedrock
        return await analyze_with_bedrock(contract)


# ============================================================
# Anthropic Direct Provider
# ============================================================

class AnthropicProvider:
    """Anthropic API 직접 호출 Provider.

    운영 비용 최적화 환경. claude-haiku 사용.
    환경변수 USE_BEDROCK=false 설정 시 활성화.
    """

    def __init__(self):
        self.settings = get_settings()

    def _get_client(self):
        try:
            import anthropic  # noqa: PLC0415
            return anthropic.Anthropic(api_key=self.settings.anthropic_api_key)
        except ImportError:
            raise RuntimeError("anthropic 패키지가 설치되지 않았습니다: pip install anthropic")

    def _invoke(self, contract: dict[str, Any]) -> dict[str, Any]:
        client = self._get_client()
        prompt_text = build_safe_prompt(contract)

        response = client.messages.create(
            model=self.settings.anthropic_model_id,
            max_tokens=2048,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt_text}],
        )
        text = response.content[0].text

        # JSON 파싱
        from app.workers.llm.bedrock import _json_from_text  # noqa: PLC0415
        return _json_from_text(text)

    async def analyze(self, contract: dict[str, Any]) -> LLMResult:
        fallback = playbook_from_contract(contract)
        try:
            data = await asyncio.to_thread(self._invoke, contract)
            output = validate_llm_output(data)
            return LLMResult(
                incident_id=contract["incident"]["incident_id"],
                plain_summary=output.plain_summary,
                attack_intent=output.attack_intent,
                kill_chain_analysis=output.kill_chain_analysis,
                recommended_actions=output.recommended_actions,
                confidence_note=output.confidence_note,
                model=self.settings.anthropic_model_id,
                cached=False,
                generated_at=fallback.generated_at,
            )
        except Exception as exc:
            log.exception("anthropic_analysis_failed", error=type(exc).__name__)
            return fallback


# ============================================================
# Static Provider (Playbook fallback)
# ============================================================

class StaticProvider:
    """정적 Playbook 기반 Provider. Bedrock/Anthropic 없을 때 사용."""

    async def analyze(self, contract: dict[str, Any]) -> LLMResult:
        return playbook_from_contract(contract)


# ============================================================
# Provider 팩토리
# ============================================================

def get_provider() -> LLMProvider:
    """설정에 따라 적절한 LLM Provider 반환."""
    settings = get_settings()
    provider_name = settings.llm_provider

    if provider_name == "static":
        return StaticProvider()

    if provider_name == "anthropic":
        return AnthropicProvider()

    if provider_name == "bedrock":
        return BedrockProvider()

    # auto 모드: Bedrock 설정 있으면 Bedrock, 없으면 Static
    if settings.llm_enabled:
        return BedrockProvider()

    return StaticProvider()


# ============================================================
# Phase 3-B: 개선된 캐시 키 (evidence hash 포함)
# ============================================================

def build_cache_key(contract: dict[str, Any]) -> str:
    """증거 해시를 포함한 캐시 키 생성.

    설계서 3-B: 기존 rule+severity 기반 캐시는 증거가 다르면 잘못된 캐시 반환.
    수정: tenant_id + rule_id + severity + evidence_hash 조합.
    """
    incident = contract.get("incident", {})
    evidence = contract.get("evidence", [])

    tenant_id = incident.get("tenant_id", "")
    rule_id = incident.get("primary_rule_id") or incident.get("rule_id", "")
    severity = incident.get("severity", "")

    # 증거 ID 목록으로 해시 생성
    evidence_ids = sorted(
        str(e.get("signal_id") or e.get("id") or e.get("timestamp", ""))
        for e in evidence
    )
    evidence_hash = hashlib.sha256(
        json.dumps(evidence_ids, sort_keys=True).encode()
    ).hexdigest()[:16]

    return f"llm:cache:{tenant_id}:{rule_id}:{severity}:{evidence_hash}"
