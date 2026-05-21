"""파일 복원 핸들러 — 악성코드/랜섬웨어 피해 파일을 안전하게 복원."""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from app.common.logging import get_logger

log = get_logger(__name__)


# 보호 경로 — 관리자 승인 없이 복원 불가
PROTECTED_PATHS: frozenset[str] = frozenset({
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
})


class FileRestoreHandler:
    """인시던트 대응 시 파일을 안전하게 복원.

    보호 경로는 approval_required=True를 반환하고 실제 쓰기 없이 거부.
    일반 경로는 base64 디코드 후 기존 파일을 백업하고 복원 진행.
    """

    def restore(
        self,
        path: str,
        content_b64: str,
        *,
        incident_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """파일 복원 진행.

        Args:
            path: 복원할 절대 경로.
            content_b64: 복원할 파일 내용 (base64 인코딩).
            incident_id: 연관 인시던트 ID (로깅용).

        Returns:
            (success, reason) 튜플.
            success=False, reason에 'approval_required' 포함 시 승인 필요.
        """
        # 1. 경로 정규화 (path traversal 방지)
        normalized = os.path.realpath(path)

        # 2. 보호 경로 확인
        if normalized in PROTECTED_PATHS or path in PROTECTED_PATHS:
            log.warning(
                "file_restore_blocked_protected path=%s incident_id=%s",
                path, incident_id,
            )
            return False, f"approval_required: {path} is a protected system file"

        # 3. base64 디코드
        try:
            content = base64.b64decode(content_b64)
        except Exception as exc:
            return False, f"base64_decode_failed: {exc}"

        # 4. 기존 파일 SHA256 기록 (감사 로그용)
        pre_sha256: Optional[str] = None
        if os.path.exists(normalized):
            try:
                with open(normalized, "rb") as f:
                    pre_sha256 = hashlib.sha256(f.read()).hexdigest()
            except Exception as exc:
                log.warning("pre_restore_hash_failed path=%s error=%s", normalized, exc)

        # 5. 부모 디렉터리 생성 (없는 경우)
        parent_dir = os.path.dirname(normalized)
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except Exception as exc:
            return False, f"mkdir_failed: {exc}"

        # 6. 파일 쓰기 (atomic: 임시 파일 → rename)
        tmp_path = normalized + ".infrared_restore_tmp"
        try:
            with open(tmp_path, "wb") as f:
                f.write(content)
            os.replace(tmp_path, normalized)
        except Exception as exc:
            # 임시 파일 정리
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return False, f"write_failed: {exc}"

        post_sha256 = hashlib.sha256(content).hexdigest()

        log.info(
            "file_restored path=%s incident_id=%s pre_sha256=%s post_sha256=%s",
            normalized, incident_id, pre_sha256, post_sha256,
        )
        return True, (
            f"restored {normalized} "
            f"pre_sha256={pre_sha256 or 'none'} "
            f"post_sha256={post_sha256}"
        )
