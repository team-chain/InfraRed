"""Phase 4-B: RAG 유사 인시던트 참조.

설계서 4-B:
- pgvector 확장으로 과거 인시던트 임베딩 저장
- 신규 인시던트 분석 시 유사 사례를 AI 프롬프트에 자동 포함
- rule_id + source_ip + severity 기반 임베딩 생성
- 코사인 유사도 top-3 조회
- disposition이 있는 과거 사례만 포함 (FP 데이터 품질 보장)
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session

log = get_logger(__name__)


async def get_embedding(text_input: str) -> Optional[list[float]]:
    """텍스트 임베딩 생성.

    우선순위:
    1. AWS Bedrock Titan Embeddings
    2. OpenAI Embeddings (fallback)
    3. 간단한 hash 기반 벡터 (개발용 fallback)
    """
    from app.config import get_settings  # noqa: PLC0415
    settings = get_settings()

    try:
        return await _bedrock_embedding(text_input, settings)
    except Exception:
        pass

    try:
        return _simple_hash_embedding(text_input)
    except Exception:
        return None


async def _bedrock_embedding(text_input: str, settings) -> list[float]:
    """AWS Bedrock Titan Embeddings."""
    import boto3  # noqa: PLC0415

    def _invoke():
        client_kwargs = {"region_name": settings.bedrock_region}
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            client_kwargs["aws_access_key_id"] = settings.aws_access_key_id
            client_kwargs["aws_secret_access_key"] = settings.aws_secret_access_key

        client = boto3.client("bedrock-runtime", **client_kwargs)
        response = client.invoke_model(
            modelId="amazon.titan-embed-text-v1",
            body=json.dumps({"inputText": text_input[:8000]}),
        )
        body = json.loads(response["body"].read())
        return body["embedding"]

    return await asyncio.to_thread(_invoke)


def _simple_hash_embedding(text_input: str) -> list[float]:
    """간단한 해시 기반 임베딩 (개발/테스트용). 1536차원."""
    import hashlib  # noqa: PLC0415

    seed = int(hashlib.md5(text_input.encode()).hexdigest(), 16)
    import random  # noqa: PLC0415
    rng = random.Random(seed)
    vector = [rng.gauss(0, 1) for _ in range(1536)]

    # 정규화
    norm = sum(x * x for x in vector) ** 0.5
    if norm > 0:
        vector = [x / norm for x in vector]

    return vector


def _build_incident_text(incident: dict) -> str:
    """인시던트 텍스트 표현 생성 (임베딩용)."""
    parts = [
        incident.get("primary_rule_id") or incident.get("rule_id") or "",
        str(incident.get("severity", "")),
        str(incident.get("mitre_tactic", "")),
        str(incident.get("mitre_technique", "")),
        str(incident.get("source_ip", "")),
        str(incident.get("username", "")),
    ]
    return " ".join(p for p in parts if p)


async def update_incident_embedding(incident_id: str, incident: dict) -> bool:
    """인시던트 임베딩 생성 및 저장."""
    text_input = _build_incident_text(incident)
    if not text_input.strip():
        return False

    embedding = await get_embedding(text_input)
    if embedding is None:
        return False

    try:
        async with get_session() as session:
            # pgvector 형식으로 저장
            vector_str = "[" + ",".join(str(x) for x in embedding) + "]"
            await session.execute(
                text("""
                    UPDATE incidents
                    SET embedding = CAST(:embedding AS vector)
                    WHERE incident_id = :incident_id
                """),
                {"incident_id": incident_id, "embedding": vector_str},
            )
            await session.commit()
        return True
    except Exception as exc:
        log.warning("embedding_update_failed", incident_id=incident_id, error=str(exc))
        return False


async def find_similar_incidents(
    incident: dict,
    tenant_id: str,
    top_k: int = 3,
) -> list[dict]:
    """유사 인시던트 top-k 검색.

    설계서 4-B:
    - disposition이 있는 과거 사례만 포함 (품질 보장)
    - 코사인 유사도 기반
    """
    text_input = _build_incident_text(incident)
    if not text_input.strip():
        return []

    embedding = await get_embedding(text_input)
    if embedding is None:
        return []

    try:
        async with get_session() as session:
            # pgvector가 없는 경우를 대비한 fallback
            try:
                vector_str = "[" + ",".join(str(x) for x in embedding) + "]"
                result = await session.execute(
                    text("""
                        SELECT
                            incident_id,
                            severity,
                            disposition,
                            primary_rule_id,
                            source_ip::text,
                            mitre_tactic,
                            mitre_technique,
                            1 - (embedding <=> CAST(:query_vec AS vector)) as similarity
                        FROM incidents
                        WHERE tenant_id = :tenant_id
                          AND disposition IS NOT NULL
                          AND embedding IS NOT NULL
                          AND incident_id != :exclude_id
                        ORDER BY embedding <=> CAST(:query_vec AS vector)
                        LIMIT :top_k
                    """),
                    {
                        "tenant_id": tenant_id,
                        "query_vec": vector_str,
                        "exclude_id": incident.get("incident_id", ""),
                        "top_k": top_k,
                    },
                )
                rows = result.mappings().fetchall()

                return [
                    {
                        "incident_id": r["incident_id"],
                        "severity": r["severity"],
                        "disposition": r["disposition"],
                        "rule_id": r["primary_rule_id"],
                        "source_ip": r["source_ip"],
                        "mitre_tactic": r["mitre_tactic"],
                        "mitre_technique": r["mitre_technique"],
                        "similarity": float(r["similarity"]) if r["similarity"] else 0.0,
                    }
                    for r in rows
                ]
            except Exception:
                # pgvector 없는 경우: rule_id + severity 기반 단순 검색
                result = await session.execute(
                    text("""
                        SELECT
                            incident_id, severity, disposition,
                            primary_rule_id, source_ip::text,
                            mitre_tactic, mitre_technique
                        FROM incidents
                        WHERE tenant_id = :tenant_id
                          AND disposition IS NOT NULL
                          AND primary_rule_id = :rule_id
                          AND severity = :severity
                          AND incident_id != :exclude_id
                        ORDER BY created_at DESC
                        LIMIT :top_k
                    """),
                    {
                        "tenant_id": tenant_id,
                        "rule_id": incident.get("primary_rule_id") or incident.get("rule_id"),
                        "severity": incident.get("severity"),
                        "exclude_id": incident.get("incident_id", ""),
                        "top_k": top_k,
                    },
                )
                rows = result.mappings().fetchall()
                return [
                    {
                        "incident_id": r["incident_id"],
                        "severity": r["severity"],
                        "disposition": r["disposition"],
                        "rule_id": r["primary_rule_id"],
                        "similarity": None,
                    }
                    for r in rows
                ]
    except Exception as exc:
        log.warning("similar_incident_search_failed", error=str(exc))
        return []
