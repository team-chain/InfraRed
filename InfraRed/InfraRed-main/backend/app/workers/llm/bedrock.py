"""Optional AWS Bedrock Claude integration."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3

from app.config import get_settings
from app.models.llm import LLMResult
from app.workers.llm.playbook import summarize_with_playbook


def _invoke_bedrock(contract: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    client = boto3.client("bedrock-runtime", region_name=settings.bedrock_region)
    prompt = {
        "role": "user",
        "content": (
            "You are a SOC analyst. Return strict JSON with keys plain_summary, "
            "attack_intent, kill_chain_analysis, recommended_actions, confidence_note. "
            "Use exactly three concise sentences in plain_summary. Do not include raw logs.\n\n"
            f"Incident contract:\n{json.dumps(contract, default=str)}"
        ),
    }
    response = client.invoke_model(
        modelId=settings.bedrock_model_id,
        body=json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 800,
                "temperature": 0.1,
                "messages": [prompt],
            }
        ),
    )
    body = json.loads(response["body"].read())
    text = body["content"][0]["text"]
    return json.loads(text)


async def analyze_with_bedrock(contract: dict[str, Any]) -> LLMResult:
    settings = get_settings()
    if not settings.llm_enabled:
        return summarize_with_playbook(contract)
    try:
        data = await asyncio.to_thread(_invoke_bedrock, contract)
    except Exception:
        return summarize_with_playbook(contract)

    fallback = summarize_with_playbook(contract)
    return LLMResult(
        incident_id=contract["incident"]["incident_id"],
        plain_summary=data.get("plain_summary") or fallback.plain_summary,
        attack_intent=data.get("attack_intent") or fallback.attack_intent,
        kill_chain_analysis=data.get("kill_chain_analysis") or fallback.kill_chain_analysis,
        recommended_actions=data.get("recommended_actions") or fallback.recommended_actions,
        confidence_note=data.get("confidence_note") or fallback.confidence_note,
        model=settings.bedrock_model_id,
        cached=False,
        generated_at=fallback.generated_at,
    )
