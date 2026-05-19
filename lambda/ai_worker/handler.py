"""
Lambda AI Worker — InfraRed (설계서 2.6절)

트리거: SQS infrared-ai-tasks.fifo
역할: 인시던트 AI 분석 (Bedrock Claude) → DB 저장
비용: Lambda 1M 요청/월 무료. Bedrock 호출 비용만 발생
Fallback: Bedrock 장애 시 Static Playbook 자동 전환 (Degraded Mode)
"""
import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS 클라이언트 ────────────────────────────────────────────
REGION = os.environ.get("BEDROCK_REGION") or os.environ.get("AWS_REGION", "ap-northeast-2")
DB_HOST = os.environ["POSTGRES_HOST"]
DB_PORT = os.environ.get("POSTGRES_PORT", "5432")
DB_NAME = os.environ.get("POSTGRES_DB", "infrared")
DB_USER = os.environ["POSTGRES_USER"]
DB_PASS = os.environ["POSTGRES_PASSWORD"]

bedrock = boto3.client("bedrock-runtime", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)

# ── Bedrock 모델 선택 (설계서 2.6절) ─────────────────────────
# Critical/High → Claude Sonnet (정확도 우선)
# Medium/Low/Info → Claude Haiku (비용 절감)
MODEL_HAIKU = "anthropic.claude-haiku-4-5-20251001"
MODEL_SONNET = "anthropic.claude-sonnet-4-6"


def get_model(severity: str) -> str:
    if severity.lower() in ("critical", "high"):
        return MODEL_SONNET
    return MODEL_HAIKU


# ── Bedrock 분석 ─────────────────────────────────────────────
def analyze_with_bedrock(incident: dict, model_id: str) -> dict:
    """Claude로 인시던트 분석 수행."""
    prompt = build_analysis_prompt(incident)

    response = bedrock.invoke_model(
        modelId=model_id,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }),
    )

    result = json.loads(response["body"].read())
    content = result["content"][0]["text"]

    return {
        "model": model_id,
        "analysis": content,
        "provider": "bedrock",
        "tokens_used": result.get("usage", {}).get("output_tokens", 0),
    }


def build_analysis_prompt(incident: dict) -> str:
    """LLM 인젝션 방어: 필드별 안전한 추출 후 프롬프트 조립."""
    incident_id = str(incident.get("incident_id", ""))[:50]
    severity = str(incident.get("severity", "Unknown"))[:20]
    rule_ids = json.dumps(incident.get("rule_ids", []))[:200]
    signal_count = int(incident.get("signal_count", 0))
    tenant_id = str(incident.get("tenant_id", ""))[:50]
    source_ips = json.dumps(incident.get("source_ips", []))[:200]

    return f"""당신은 보안 사고 분석 전문가입니다. 다음 인시던트를 분석해주세요.

인시던트 정보:
- ID: {incident_id}
- 심각도: {severity}
- 탐지된 룰: {rule_ids}
- 관련 시그널 수: {signal_count}
- 출발지 IP 목록: {source_ips}

다음 항목으로 분석하세요:
1. 공격 패턴 요약 (1-2문장)
2. 위협 수준 평가 (LOW/MEDIUM/HIGH/CRITICAL)
3. 즉시 권장 조치 (3가지 이내)
4. 추가 모니터링 포인트

JSON 형식으로 응답하세요:
{{"summary": "...", "threat_level": "...", "actions": [...], "monitoring": [...]}}"""


# ── Static Playbook Fallback (Degraded Mode) ─────────────────
STATIC_PLAYBOOKS: dict[str, dict] = {
    "critical": {
        "summary": "[Degraded Mode] AI 분석 불가. Critical 인시던트 — 즉시 수동 검토 필요.",
        "threat_level": "CRITICAL",
        "actions": [
            "즉시 관련 시스템 격리 검토",
            "보안 담당자에게 에스컬레이션",
            "관련 로그 보존 (증거 수집)",
        ],
        "monitoring": ["네트워크 트래픽 이상 여부", "계정 접근 패턴"],
        "provider": "static_playbook",
    },
    "high": {
        "summary": "[Degraded Mode] AI 분석 불가. High 인시던트 — 30분 내 검토 필요.",
        "threat_level": "HIGH",
        "actions": [
            "의심 IP/계정 Watchlist 등록",
            "추가 탐지 룰 활성화 검토",
            "인시던트 티켓 생성 및 담당자 지정",
        ],
        "monitoring": ["관련 소스 IP 행동 패턴", "인증 실패 추이"],
        "provider": "static_playbook",
    },
    "default": {
        "summary": "[Degraded Mode] AI 분석 불가. 표준 절차에 따라 처리하세요.",
        "threat_level": "MEDIUM",
        "actions": [
            "인시던트 상세 내용 검토",
            "관련 시그널 타임라인 확인",
            "필요 시 에스컬레이션",
        ],
        "monitoring": ["이벤트 발생 빈도"],
        "provider": "static_playbook",
    },
}


def get_static_playbook(severity: str) -> dict:
    return STATIC_PLAYBOOKS.get(severity.lower(), STATIC_PLAYBOOKS["default"])


# ── DB 저장 ───────────────────────────────────────────────────
def save_ai_analysis(incident_id: str, analysis: dict) -> None:
    """AI 분석 결과를 RDS에 저장."""
    import psycopg2  # Lambda Layer 또는 패키지에 포함

    conn = psycopg2.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=10,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incident_ai_analyses
                    (incident_id, model, analysis, provider, tokens_used, created_at)
                VALUES (%s, %s, %s::jsonb, %s, %s, NOW())
                ON CONFLICT (incident_id) DO UPDATE SET
                    model = EXCLUDED.model,
                    analysis = EXCLUDED.analysis,
                    provider = EXCLUDED.provider,
                    tokens_used = EXCLUDED.tokens_used,
                    updated_at = NOW()
                """,
                (
                    incident_id,
                    analysis.get("model", "static"),
                    json.dumps(analysis),
                    analysis.get("provider", "unknown"),
                    analysis.get("tokens_used", 0),
                ),
            )
        conn.commit()
        logger.info(f"AI 분석 저장 완료: incident_id={incident_id}, provider={analysis.get('provider')}")
    finally:
        conn.close()


# ── Lambda Handler ────────────────────────────────────────────
def handler(event: dict, context: Any) -> dict:
    """
    SQS infrared-ai-tasks.fifo 트리거.
    메시지 형식: {"incident_id": "...", "severity": "...", "rule_ids": [...], ...}
    """
    processed = 0
    failed = 0

    for record in event.get("Records", []):
        body: dict = {}
        incident_id = "unknown"

        try:
            body = json.loads(record["body"])
            incident_id = body.get("incident_id", "unknown")
            severity = body.get("severity", "medium")

            logger.info(f"AI 분석 시작: incident_id={incident_id}, severity={severity}")

            model_id = get_model(severity)

            try:
                # Bedrock 분석 시도
                analysis = analyze_with_bedrock(body, model_id)
                logger.info(f"Bedrock 분석 성공: model={model_id}, tokens={analysis.get('tokens_used')}")
            except Exception as bedrock_err:
                # Fallback: Static Playbook (Degraded Mode)
                logger.warning(f"Bedrock 실패, Static Playbook 전환: {bedrock_err}")
                analysis = get_static_playbook(severity)

            save_ai_analysis(incident_id, analysis)
            processed += 1

        except Exception as e:
            logger.error(f"AI Worker 처리 실패: incident_id={incident_id}, error={e}", exc_info=True)
            failed += 1
            # SQS가 자동 재시도 (maxReceiveCount=3 후 DLQ 이동)
            raise  # SQS partial batch 처리를 위해 re-raise

    logger.info(f"배치 처리 완료: processed={processed}, failed={failed}")
    return {"processed": processed, "failed": failed}
