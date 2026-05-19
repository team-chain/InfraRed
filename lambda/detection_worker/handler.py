"""
Lambda Detection Worker
SQS infrared-events → 룰 매치 → SQS infrared-signals
"""
import json, os, sys, logging
sys.path.insert(0, "/var/task")
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "ap-northeast-2"))
SQS_SIGNALS_URL = os.environ.get("SQS_SIGNALS_URL", "")

RULE_CONFIDENCE = {
    "AUTH-001": 0.70, "AUTH-002": 0.65, "AUTH-003": 0.60,
    "AUTH-004": 0.85, "AUTH-006A": 0.75, "AUTH-006B": 0.75,
    "WEB-HNY-001": 0.80, "WEB-001": 0.70, "NET-001": 0.65,
    "PERSIST-001": 0.90, "PERSIST-002": 0.80, "PERSIST-003": 0.80,
    "ESCALATE-001": 0.90, "EXEC-001": 0.85, "EXEC-002": 0.95,
    "EXEC-003": 0.80, "TAMPER-001": 0.75, "TAMPER-002": 0.90,
    # v8.0 rule IDs
    "TRAVEL-001": 0.90,          # Impossible Travel (MITRE T1078)
    "EXEC-ANCESTRY-001": 0.95,   # Process Ancestry — 확정 위험 쌍 (MITRE T1059)
    "EXEC-ANCESTRY-002": 0.70,   # Process Ancestry — 학습 외 페어 (MITRE T1059)
    "TAMPER-LOG-001": 0.90,      # Log Entropy — 엔트로피 폭증 (랜섬웨어) (MITRE T1486)
    "TAMPER-LOG-002": 0.85,      # Log Entropy — 엔트로피 급감 (로그 와이핑) (MITRE T1070.002)
    "CANARY-API-001": 0.95,      # Canary API Token 무단 접근 (MITRE T1552.005)
    "EXEC-FIRST-001": 0.95,      # 최초 실행 시스템 바이너리 (MITRE T1554)
    "EXEC-FIRST-002": 0.80,      # 최초 실행 일반 바이너리
    "DECEPTION-003": 0.95,       # AWS Honey Key 사용 감지 (MITRE T1552.005)
}


def match_rules(event: dict) -> list[dict]:
    """간략한 룰 매칭 (전체 룰은 EC2 Detection Worker에 있음)"""
    signals = []
    event_type = event.get("event_type", "")

    # AUTH-001: SSH brute force
    if event_type == "ssh_login_failed":
        signals.append({
            "rule_id": "AUTH-001",
            "severity": "HIGH",
            "confidence": RULE_CONFIDENCE["AUTH-001"],
            "source_event": event,
        })

    # AUTH-004: fail then success
    if event_type == "login_success" and event.get("preceded_by_failures"):
        signals.append({
            "rule_id": "AUTH-004",
            "severity": "CRITICAL",
            "confidence": RULE_CONFIDENCE["AUTH-004"],
            "source_event": event,
        })

    # EXEC-001: /tmp execution
    if event_type == "suspicious_process_execution":
        signals.append({
            "rule_id": "EXEC-001",
            "severity": "HIGH",
            "confidence": RULE_CONFIDENCE["EXEC-001"],
            "source_event": event,
        })

    # EXEC-002: webserver shell spawn
    if event_type == "webserver_shell_spawn":
        signals.append({
            "rule_id": "EXEC-002",
            "severity": "CRITICAL",
            "confidence": RULE_CONFIDENCE["EXEC-002"],
            "source_event": event,
        })

    # PERSIST-001: authorized_keys
    if event_type in ("authorized_keys_modified", "authorized_keys_created"):
        signals.append({
            "rule_id": "PERSIST-001",
            "severity": "HIGH",
            "confidence": RULE_CONFIDENCE["PERSIST-001"],
            "source_event": event,
        })

    # TAMPER
    if event_type in ("agent_unexpectedly_stopped", "log_file_truncated", "log_file_deleted"):
        rule_id = "TAMPER-001" if "stopped" in event_type else "TAMPER-002"
        signals.append({
            "rule_id": rule_id,
            "severity": "CRITICAL",
            "confidence": RULE_CONFIDENCE.get(rule_id, 0.75),
            "source_event": event,
        })

    # v8.0: TRAVEL-001 — Impossible Travel

    # v8.0: TRAVEL-001 — Impossible Travel
    if event_type == "impossible_travel":
        signals.append({
            "rule_id": "TRAVEL-001",
            "severity": "HIGH",
            "confidence": RULE_CONFIDENCE["TRAVEL-001"],
            "mitre": "T1078",
            "source_event": event,
        })

    # v8.0: EXEC-ANCESTRY-001/002 — Process Ancestry Tripwire
    if event_type == "suspicious_process_ancestry":
        rule_id = event.get("rule_id", "EXEC-ANCESTRY-001")
        signals.append({
            "rule_id": rule_id,
            "severity": "CRITICAL" if rule_id == "EXEC-ANCESTRY-001" else "MEDIUM",
            "confidence": RULE_CONFIDENCE.get(rule_id, 0.85),
            "mitre": "T1059",
            "source_event": event,
        })

    # v8.0: TAMPER-LOG-001/002 — Log Entropy Sentinel
    if event_type == "log_entropy_anomaly":
        rule_id = event.get("rule_id", "TAMPER-LOG-001")
        severity = "CRITICAL" if rule_id == "TAMPER-LOG-001" else "HIGH"
        signals.append({
            "rule_id": rule_id,
            "severity": severity,
            "confidence": RULE_CONFIDENCE.get(rule_id, 0.88),
            "mitre": "T1486" if rule_id == "TAMPER-LOG-001" else "T1070.002",
            "source_event": event,
        })

    # v8.0: CANARY-API-001 — Canary API Token Access
    if event_type == "canary_token_accessed":
        signals.append({
            "rule_id": "CANARY-API-001",
            "severity": "CRITICAL",
            "confidence": RULE_CONFIDENCE["CANARY-API-001"],
            "mitre": "T1552.005",
            "source_event": event,
        })

    # v8.0: EXEC-FIRST-001/002 — First Execution Tripwire
    if event_type == "first_execution":
        rule_id = event.get("rule_id", "EXEC-FIRST-001")
        severity = "CRITICAL" if rule_id == "EXEC-FIRST-001" else "HIGH"
        signals.append({
            "rule_id": rule_id,
            "severity": severity,
            "confidence": RULE_CONFIDENCE.get(rule_id, 0.88),
            "mitre": "T1554",
            "source_event": event,
        })

    # v8.0: DECEPTION-003 — AWS Honey Key Used
    if event_type == "honey_key_used":
        signals.append({
            "rule_id": "DECEPTION-003",
            "severity": "CRITICAL",
            "confidence": RULE_CONFIDENCE["DECEPTION-003"],
            "mitre": "T1552.005",
            "source_event": event,
        })

    return signals


def lambda_handler(event, context):
    processed = 0
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
            signals = match_rules(body)
            for signal in signals:
                signal["tenant_id"] = body.get("tenant_id", "")
                signal["agent_id"] = body.get("agent_id", "")
                signal["timestamp"] = body.get("timestamp", "")
                if SQS_SIGNALS_URL:
                    sqs.send_message(
                        QueueUrl=SQS_SIGNALS_URL,
                        MessageBody=json.dumps(signal, default=str),
                    )
                    logger.info(f"Signal published: {signal['rule_id']}")
            processed += 1
        except Exception as e:
            logger.error(f"Record processing failed: {e}")
    return {"processed": processed}
