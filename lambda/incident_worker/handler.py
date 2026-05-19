"""
Lambda Incident Worker
SQS infrared-signals → 상관분석 → DB 저장 + SQS infrared-incidents
"""
import json, os, sys, logging, hashlib
from datetime import datetime
sys.path.insert(0, "/var/task")
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "ap-northeast-2"))
SQS_INCIDENTS_URL = os.environ.get("SQS_INCIDENTS_URL", "")

SCENARIO_STAGES = {
    "SSH_ACCOUNT_COMPROMISE_WITH_PERSISTENCE": [
        ["AUTH-001", "AUTH-006A", "AUTH-006B"],  # stage 1: brute force
        ["AUTH-004"],                              # stage 2: success
        ["PERSIST-001", "PERSIST-002", "PERSIST-003"],  # stage 3: persistence
    ],
    "WEBSHELL_INFILTRATION": [
        ["WEB-HNY-001"],  # recon (optional)
        ["WEB-001"],       # webshell access
        ["EXEC-002"],      # shell execution
    ],
    "RANSOMWARE_PRECURSOR": [
        ["EXEC-001"],  # malicious execution
        ["EXEC-003"],  # bulk file mod
    ],
}

# In-memory state (Lambda는 warm start 시 재사용됨)
scenario_states = {}


def check_scenarios(signal: dict) -> list[str]:
    """완성된 시나리오 ID 반환"""
    rule_id = signal.get("rule_id", "")
    tenant_id = signal.get("tenant_id", "")
    source_ip = signal.get("source_event", {}).get("source_ip", "")
    asset_id = signal.get("source_event", {}).get("asset_id", "")

    completed = []
    for scenario_id, stages in SCENARIO_STAGES.items():
        key = f"{scenario_id}:{tenant_id}:{source_ip}"
        state = scenario_states.get(key, [])

        for i, stage_rules in enumerate(stages):
            if i in state:
                continue
            if rule_id in stage_rules:
                state.append(i)
                scenario_states[key] = state
                break

        if len(state) >= sum(1 for s in stages if True):  # all required
            completed.append(scenario_id)
            del scenario_states[key]

    return completed


def lambda_handler(event, context):
    processed = 0
    for record in event.get("Records", []):
        try:
            signal = json.loads(record["body"])
            matched_scenarios = check_scenarios(signal)

            incident = {
                "signal": signal,
                "matched_scenarios": matched_scenarios,
                "severity": signal.get("severity", "MEDIUM"),
                "confidence": signal.get("confidence", 0.5),
                "tenant_id": signal.get("tenant_id", ""),
                "timestamp": datetime.utcnow().isoformat(),
            }

            if matched_scenarios:
                incident["severity"] = "CRITICAL"
                incident["confidence"] = min(1.0, signal.get("confidence", 0.5) + 0.35)

            if SQS_INCIDENTS_URL:
                sqs.send_message(
                    QueueUrl=SQS_INCIDENTS_URL,
                    MessageBody=json.dumps(incident, default=str),
                )
                logger.info(f"Incident published: scenarios={matched_scenarios}")

            processed += 1
        except Exception as e:
            logger.error(f"Signal processing failed: {e}")
    return {"processed": processed}
