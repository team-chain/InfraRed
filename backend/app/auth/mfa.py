"""
TOTP 기반 MFA (Google Authenticator 호환).
v4.0 설계서 §9.2 참조.
"""
from __future__ import annotations
import secrets, logging, base64
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import pyotp
    import qrcode
    from io import BytesIO
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    logger.warning("pyotp/qrcode not available. MFA disabled.")

try:
    from cryptography.fernet import Fernet
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

from app.config import get_settings


def _get_fernet():
    """Fernet 인스턴스 반환. fernet_key 미설정 시 None 반환 (base64 fallback 사용).

    운영 환경에서는 반드시 FERNET_KEY 환경변수를 설정해야 한다.
    개발/테스트 환경에서는 None 반환 → base64 plain 저장 (암호화 없음).
    """
    settings = get_settings()
    if not settings.fernet_key:
        return None  # base64 fallback — 운영 환경에서 FERNET_KEY 필수
    try:
        return Fernet(settings.fernet_key.encode()) if FERNET_AVAILABLE else None
    except Exception:
        return None


@dataclass
class MFASetupResult:
    qr_code_base64: str
    encrypted_secret: str
    backup_codes: list[str]
    totp_uri: str


class MFAHandler:
    """TOTP MFA 등록 및 검증"""

    ISSUER = "InfraRed Security"

    def setup_mfa(self, user_email: str) -> MFASetupResult:
        """MFA 등록 — 시크릿 생성 + QR 코드"""
        if not PYOTP_AVAILABLE:
            raise RuntimeError("pyotp not installed. Run: pip install pyotp qrcode[pil]")

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otp_uri = totp.provisioning_uri(name=user_email, issuer_name=self.ISSUER)

        # QR 코드 생성
        img = qrcode.make(otp_uri)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        # 시크릿 암호화
        fernet = _get_fernet()
        encrypted_secret = ""
        if fernet and FERNET_AVAILABLE:
            encrypted_secret = fernet.encrypt(secret.encode()).decode()
        else:
            encrypted_secret = base64.b64encode(secret.encode()).decode()

        backup_codes = self._generate_backup_codes()

        return MFASetupResult(
            qr_code_base64=qr_base64,
            encrypted_secret=encrypted_secret,
            backup_codes=backup_codes,
            totp_uri=otp_uri,
        )

    def verify_totp(self, encrypted_secret: str, token: str) -> bool:
        """TOTP 토큰 검증 (30초 윈도우 ±1 허용)"""
        if not PYOTP_AVAILABLE:
            return False

        try:
            fernet = _get_fernet()
            if fernet and FERNET_AVAILABLE:
                secret = fernet.decrypt(encrypted_secret.encode()).decode()
            else:
                secret = base64.b64decode(encrypted_secret.encode()).decode()

            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception as e:
            logger.error(f"TOTP verification failed: {e}")
            return False

    def verify_backup_code(self, stored_codes: list[str], code: str) -> tuple[bool, list[str]]:
        """백업 코드 검증 (사용된 코드 제거).

        대소문자·하이픈 무시 비교. secrets.compare_digest로 타이밍 공격 방어.
        """
        code_clean = code.strip().upper().replace("-", "")
        for i, stored in enumerate(stored_codes):
            stored_clean = stored.strip().upper().replace("-", "")
            # compare_digest는 동일 길이여야 함 → 길이 다르면 스킵
            if len(stored_clean) != len(code_clean):
                continue
            if secrets.compare_digest(stored_clean, code_clean):
                remaining = stored_codes[:i] + stored_codes[i + 1:]
                return True, remaining
        return False, stored_codes

    @staticmethod
    def _generate_backup_codes(count: int = 10) -> list[str]:
        """10개 백업 코드 생성 (XXXXX-XXXXX 형식)"""
        codes = []
        for _ in range(count):
            part1 = secrets.token_hex(3).upper()
            part2 = secrets.token_hex(3).upper()
            codes.append(f"{part1}-{part2}")
        return codes


_mfa_handler: Optional[MFAHandler] = None

def get_mfa_handler() -> MFAHandler:
    global _mfa_handler
    if _mfa_handler is None:
        _mfa_handler = MFAHandler()
    return _mfa_handler
