"""
Bedrock 3단계 AI 호출 티어링 + S3 응답 캐시.
v4.0 설계서 §3 참조.
"""
from __future__ import annotations
import hashlib, json, logging, io
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
import boto3
from app.config import get_settings

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    summary: str
    ai_called: bool = False
    cost_usd: float = 0.0
    cache_hit: bool = False
    model_used: str = ""


class S3BedrockCache:
    BUCKET = "infrared-bedrock-cache"
    TTL_HOURS = 24

    def __init__(self):
        settings = get_settings()
        kwargs = {"region_name": settings.s3_region}
        if settings.aws_access_key_id:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        if settings.aws_session_token:
            kwargs["aws_session_token"] = settings.aws_session_token
        self.s3 = boto3.client("s3", **kwargs)
        if settings.s3_bucket:
            self.BUCKET = settings.s3_bucket

    def _build_cache_key(self, rule_id: str, source_asn: str, scenario_id: str) -> str:
        components = [rule_id or "unknown", source_asn or "unknown", scenario_id or "none"]
        return hashlib.md5(":".join(components).encode()).hexdigest()

    def get(self, cache_key: str) -> Optional[str]:
        try:
            obj = self.s3.get_object(Bucket=self.BUCKET, Key=f"bedrock-cache/{cache_key}.json")
            data = json.loads(obj["Body"].read())
            cached_at = datetime.fromisoformat(data["cached_at"])
            if datetime.utcnow() - cached_at > timedelta(hours=self.TTL_HOURS):
                return None
            return data["response"]
        except Exception:
            return None

    def set(self, cache_key: str, response: str) -> None:
        try:
            self.s3.put_object(
                Bucket=self.BUCKET,
                Key=f"bedrock-cache/{cache_key}.json",
                Body=json.dumps({"response": response, "cached_at": datetime.utcnow().isoformat()}),
                ContentType="application/json",
            )
        except Exception as e:
            logger.warning(f"S3 cache set failed: {e}")


class BedrockTieredAnalyzer:
    """CRITICAL→Haiku3.5, HIGH→Haiku3, MEDIUM/LOW→템플릿"""

    TIER_CONFIG = {
        "CRITICAL": {
            "model": "anthropic.claude-3-5-haiku-20241022-v1:0",
            "max_tokens": 1000,
            "cost_per_call_usd": 0.005,
        },
        "HIGH": {
            "model": "anthropic.claude-3-haiku-20240307-v1:0",
            "max_tokens": 600,
            "cost_per_call_usd": 0.0015,
        },
        "MEDIUM": None,
        "LOW": None,
    }

    TEMPLATE_MESSAGES = {
        "MEDIUM": "반복적인 패턴의 이벤트가 감지되었습니다. 임계값 미달로 자동 모니터링 중이며, 임계값 초과 시 인시던트로 승격됩니다.",
        "LOW": "정보성 이벤트입니다. 현재 위협 수준이 낮아 추가 조치가 필요하지 않습니다.",
    }

    def __init__(self):
        self.cache = S3BedrockCache()
        settings = get_settings()
        kwargs = {"region_name": settings.bedrock_region}
        if settings.aws_access_key_id:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        self.bedrock = boto3.client("bedrock-runtime", **kwargs)

    def analyze(
        self,
        severity: str,
        rule_id: str = "",
        source_asn: str = "",
        scenario_id: str = "",
        source_ip: str = "",
        asset_hostname: str = "",
        asset_type: str = "",
        asset_env: str = "",
        signals_summary: str = "",
        confidence_score: float = 0.0,
        confidence_breakdown: dict = None,
        mitre_techniques: list = None,
    ) -> AnalysisResult:
        severity = severity.upper()
        tier = self.TIER_CONFIG.get(severity)

        if tier is None:
            return AnalysisResult(
                summary=self.TEMPLATE_MESSAGES.get(severity, "이벤트가 감지되었습니다."),
                ai_called=False,
                cost_usd=0.0,
            )

        cache_key = self.cache._build_cache_key(rule_id, source_asn, scenario_id)
        cached = self.cache.get(cache_key)
        if cached:
            return AnalysisResult(summary=cached, ai_called=False, cost_usd=0.0, cache_hit=True, model_used=tier["model"])

        prompt = f"""보안 인시던트 분석 요청

심각도: {severity}
시나리오: {scenario_id or '없음'}
공격자 IP: {source_ip}
대상 자산: {asset_hostname} ({asset_type}, {asset_env})
탐지된 신호:
{signals_summary}
신뢰도 점수: {confidence_score} (근거: {json.dumps(confidence_breakdown or {}, ensure_ascii=False)})
MITRE ATT&CK: {', '.join(mitre_techniques or [])}
"""
        try:
            response = self.bedrock.invoke_model(
                modelId=tier["model"],
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": tier["max_tokens"],
                    "messages": [{"role": "user", "content": prompt}],
                    "system": "당신은 보안 분석 전문가입니다. 주어진 보안 인시던트를 간결하게 분석하고, 공격자의 의도와 권장 조치를 3~5문장으로 요약하세요. 불필요한 서두나 마무리 없이 분석 내용만 출력하세요.",
                }),
            )
            body = json.loads(response["body"].read())
            summary = body["content"][0]["text"]
            self.cache.set(cache_key, summary)
            return AnalysisResult(
                summary=summary,
                ai_called=True,
                cost_usd=tier["cost_per_call_usd"],
                model_used=tier["model"],
            )
        except Exception as e:
            logger.error(f"Bedrock tiered call failed: {e}")
            return AnalysisResult(
                summary=f"AI 분석 실패: {str(e)[:100]}. 수동 조사 필요.",
                ai_called=False,
                cost_usd=0.0,
            )
