"""AWS Bedrock Claude integration with Static Playbook fallback."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3

from app.common.logging import get_logger
from app.config import get_settings
from app.models.llm import LLMResult
from app.workers.llm.playbook import summarize_with_playbook


log = get_logger(__name__)


def _repair_json(text: str) -> str:
    """Best-effort repair for truncated JSON: close open strings, arrays, objects."""
    depth_brace = 0
    depth_bracket = 0
    in_string = False
    escape_next = False
    last_good = 0
    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
        if not in_string:
            if ch == "{":
                depth_brace += 1
            elif ch == "}":
                depth_brace -= 1
            elif ch == "[":
                depth_bracket += 1
            elif ch == "]":
                depth_bracket -= 1
            last_good = i
    result = text[: last_good + 1].rstrip().rstrip(",")
    if in_string:
        result += '"'
    result += "]" * depth_bracket
    result += "}" * depth_brace
    return result


def _json_from_text(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end >= start:
        cleaned = cleaned[start : end + 1]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return json.loads(_repair_json(cleaned))


def _string_value(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or fallback
    if isinstance(value, dict):
        parts = []
        for key, nested_value in value.items():
            if nested_value is None:
                continue
            label = str(key).replace("_", " ").strip().capitalize()
            if isinstance(nested_value, (dict, list)):
                rendered = json.dumps(nested_value, ensure_ascii=False)
            else:
                rendered = str(nested_value)
            parts.append(f"{label}: {rendered}")
        return ". ".join(parts) or fallback
    if isinstance(value, list):
        parts = [
            json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item)
            for item in value
            if item is not None
        ]
        return "; ".join(parts) or fallback
    return str(value).strip() or fallback


def _list_of_strings(value: Any, fallback: list[str]) -> list[str]:
    if value is None:
        return fallback
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else fallback
    if isinstance(value, list):
        actions = [_string_value(item, "") for item in value]
        actions = [action for action in actions if action]
        return actions or fallback
    rendered = _string_value(value, "")
    return [rendered] if rendered else fallback


def _bedrock_client():
    settings = get_settings()
    session_kwargs: dict[str, str] = {}
    if settings.aws_profile:
        session_kwargs["profile_name"] = settings.aws_profile

    session = boto3.Session(**session_kwargs)
    client_kwargs: dict[str, str] = {"region_name": settings.bedrock_region}
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        client_kwargs["aws_access_key_id"] = settings.aws_access_key_id
        client_kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
    if settings.aws_session_token:
        client_kwargs["aws_session_token"] = settings.aws_session_token
    return session.client("bedrock-runtime", **client_kwargs)


def _invoke_bedrock(contract: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    client = _bedrock_client()
    prompt = {
        "role": "user",
        "content": (
            "You are a SOC analyst for an SSH security product. "
            "IMPORTANT: Respond entirely in Korean (한국어). "
            "Return strict JSON only with keys: plain_summary, attack_intent, "
            "kill_chain_analysis, recommended_actions, confidence_note. "
            "plain_summary must be exactly three concise sentences for an executive. "
            "recommended_actions must be an array of 3 to 5 concrete actions. "
            "Do not include raw logs, credentials, or secrets.\n\n"
            f"Incident contract:\n{json.dumps(contract, default=str)}"
        ),
    }
    response = client.invoke_model(
        modelId=settings.bedrock_model_id,
        body=json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2048,
                "temperature": 0.1,
                "messages": [prompt],
            }
        ),
    )
    body = json.loads(response["body"].read())
    text = body["content"][0]["text"]
    return _json_from_text(text)


async def analyze_with_bedrock(contract: dict[str, Any]) -> LLMResult:
    settings = get_settings()
    fallback = summarize_with_playbook(contract)
    if not settings.llm_enabled:
        return fallback

    try:
        data = await asyncio.to_thread(_invoke_bedrock, contract)
    except Exception as exc:  # noqa: BLE001
        log.exception("bedrock_analysis_failed", error=str(exc))
        return fallback

    return LLMResult(
        incident_id=contract["incident"]["incident_id"],
        plain_summary=_string_value(data.get("plain_summary"), fallback.plain_summary),
        attack_intent=_string_value(data.get("attack_intent"), fallback.attack_intent),
        kill_chain_analysis=_string_value(data.get("kill_chain_analysis"), fallback.kill_chain_analysis),
        recommended_actions=_list_of_strings(data.get("recommended_actions"), fallback.recommended_actions),
        confidence_note=_string_value(data.get("confidence_note"), fallback.confidence_note),
        model=settings.bedrock_model_id,
        cached=False,
        generated_at=fallback.generated_at,
    )
