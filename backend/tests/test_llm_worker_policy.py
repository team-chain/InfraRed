from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.llm import LLMResult
from app.workers.llm import worker


def _contract(severity: str) -> dict:
    return {
        "incident": {
            "incident_id": f"INC-{severity.upper()}",
            "severity": severity,
        }
    }


def _result(incident_id: str = "INC-TEST") -> LLMResult:
    return LLMResult(
        incident_id=incident_id,
        plain_summary="summary",
        attack_intent="intent",
        kill_chain_analysis="analysis",
        recommended_actions=["action"],
        confidence_note="confidence",
        generated_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_high_incident_uses_bedrock_and_dispatches(monkeypatch):
    calls: dict[str, object] = {}

    async def fetch(incident_id: str, tenant_id: str) -> dict:
        calls["fetch"] = (incident_id, tenant_id)
        return _contract("high")

    async def analyze(contract: dict, *, refresh: bool = False, force_static: bool = False) -> LLMResult:
        calls["analyze"] = (refresh, force_static)
        return _result(contract["incident"]["incident_id"])

    async def save(result: LLMResult, tenant_id: str) -> None:
        calls["save"] = (result.incident_id, tenant_id)

    async def dispatch(tenant_id: str, result: LLMResult, severity: str = "high"):
        calls["dispatch"] = (tenant_id, result.incident_id, severity)
        return SimpleNamespace(discord_sent=True, email_sent=False)

    monkeypatch.setattr(worker, "fetch_incident_contract", fetch)
    monkeypatch.setattr(worker, "analyze_contract_with_cache", analyze)
    monkeypatch.setattr(worker, "save_llm_result", save)
    monkeypatch.setattr(worker, "dispatch_incident_alert", dispatch)

    outcome = await worker.process_incident("INC-HIGH", "company-a", refresh=False)

    assert calls["analyze"] == (False, False)
    assert calls["save"] == ("INC-HIGH", "company-a")
    assert calls["dispatch"] == ("company-a", "INC-HIGH", "high")
    assert outcome["analysis_mode"] == "bedrock"
    assert outcome["dispatch_attempted"] is True
    assert outcome["discord_sent"] is True


@pytest.mark.asyncio
async def test_medium_incident_uses_static_playbook_without_dispatch(monkeypatch):
    calls: dict[str, object] = {}

    async def fetch(incident_id: str, tenant_id: str) -> dict:
        return _contract("medium")

    async def analyze(contract: dict, *, refresh: bool = False, force_static: bool = False) -> LLMResult:
        calls["analyze"] = (refresh, force_static)
        return _result(contract["incident"]["incident_id"])

    async def save(result: LLMResult, tenant_id: str) -> None:
        calls["save"] = (result.incident_id, tenant_id)

    async def dispatch(*args, **kwargs):
        calls["dispatch"] = True
        return SimpleNamespace(discord_sent=True, email_sent=False)

    monkeypatch.setattr(worker, "fetch_incident_contract", fetch)
    monkeypatch.setattr(worker, "analyze_contract_with_cache", analyze)
    monkeypatch.setattr(worker, "save_llm_result", save)
    monkeypatch.setattr(worker, "dispatch_incident_alert", dispatch)

    outcome = await worker.process_incident("INC-MEDIUM", "company-a", refresh=False)

    assert calls["analyze"] == (False, True)
    assert calls["save"] == ("INC-MEDIUM", "company-a")
    assert "dispatch" not in calls
    assert outcome["analysis_mode"] == "static_playbook"
    assert outcome["dispatch_attempted"] is False


@pytest.mark.asyncio
async def test_info_incident_is_stored_only_without_llm_or_dispatch(monkeypatch):
    calls: dict[str, object] = {}

    async def fetch(incident_id: str, tenant_id: str) -> dict:
        return _contract("info")

    async def analyze(*args, **kwargs) -> LLMResult:
        calls["analyze"] = True
        return _result()

    async def save(*args, **kwargs) -> None:
        calls["save"] = True

    async def dispatch(*args, **kwargs):
        calls["dispatch"] = True
        return SimpleNamespace(discord_sent=True, email_sent=False)

    monkeypatch.setattr(worker, "fetch_incident_contract", fetch)
    monkeypatch.setattr(worker, "analyze_contract_with_cache", analyze)
    monkeypatch.setattr(worker, "save_llm_result", save)
    monkeypatch.setattr(worker, "dispatch_incident_alert", dispatch)

    outcome = await worker.process_incident("INC-INFO", "company-a", refresh=False)

    assert "analyze" not in calls
    assert "save" not in calls
    assert "dispatch" not in calls
    assert outcome["analysis_mode"] == "stored_only"
    assert outcome["dispatch_attempted"] is False
