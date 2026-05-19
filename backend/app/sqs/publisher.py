import boto3, json, logging
from app.config import get_settings

logger = logging.getLogger(__name__)

class SQSPublisher:
    def __init__(self):
        settings = get_settings()
        self._client = None
        self._settings = settings

    @property
    def client(self):
        if self._client is None:
            s = self._settings
            kwargs = {"region_name": s.s3_region}
            if s.aws_access_key_id:
                kwargs["aws_access_key_id"] = s.aws_access_key_id
                kwargs["aws_secret_access_key"] = s.aws_secret_access_key
            if s.aws_session_token:
                kwargs["aws_session_token"] = s.aws_session_token
            self._client = boto3.client("sqs", **kwargs)
        return self._client

    async def publish_event(self, event_dict: dict, queue_url: str, tenant_id: str = "", severity: str = "INFO") -> bool:
        # SQS 발행, 실패시 False 반환 (Redis fallback 사용)
        try:
            attrs = {}
            if tenant_id:
                attrs["tenant_id"] = {"DataType": "String", "StringValue": tenant_id}
            if severity:
                attrs["severity"] = {"DataType": "String", "StringValue": severity}
            self.client.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(event_dict, default=str),
                MessageAttributes=attrs,
            )
            return True
        except Exception as e:
            logger.warning(f"SQS publish failed (will use Redis fallback): {e}")
            return False


_publisher: SQSPublisher | None = None


def get_sqs_publisher() -> SQSPublisher:
    global _publisher
    if _publisher is None:
        _publisher = SQSPublisher()
    return _publisher
