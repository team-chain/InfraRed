"""재감염 방지 점검 모듈 — 인시던트 이후 시스템 보안 취약점 점검."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.common.logging import get_logger

log = get_logger(__name__)


# ── 데이터 모델 ────────────────────────────────────────────────────────────── #

@dataclass
class Risk:
    category: str       # ssh_config | suid_binary | empty_password | unpatched_package
    detail: str
    severity: str       # critical | high | medium | low


@dataclass
class ReinfectionReport:
    incident_id: str
    tenant_id: str
    checked_at: str
    risks: list[Risk]
    score: int          # 0–100 (높을수록 위험)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "tenant_id": self.tenant_id,
            "checked_at": self.checked_at,
            "risks": [
                {
                    "category": r.category,
                    "detail": r.detail,
                    "severity": r.severity,
                }
                for r in self.risks
            ],
            "score": self.score,
        }


# ── ReinfectionPrevention ─────────────────────────────────────────────────── #

class ReinfectionPrevention:
    """인시던트 이후 재감염 위험 요소를 점검하고 ReinfectionReport 반환."""

    def check_reinfection_risk(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> ReinfectionReport:
        """전체 재감염 위험 점검 실행.

        점검 항목:
        - SSH 설정 (PermitRootLogin, PasswordAuthentication)
        - SUID 바이너리 목록
        - 빈 패스워드 계정
        - 미패치 패키지 (apt 또는 yum)
        """
        checked_at = datetime.now(timezone.utc).isoformat()
        risks: list[Risk] = []

        risks.extend(self._check_ssh_config())
        risks.extend(self._check_suid_binaries())
        risks.extend(self._check_empty_passwords())
        risks.extend(self._check_unpatched_packages())

        score = self._calculate_score(risks)

        log.info(
            "reinfection_check_done incident_id=%s tenant_id=%s risks=%d score=%d",
            incident_id, tenant_id, len(risks), score,
        )

        return ReinfectionReport(
            incident_id=incident_id,
            tenant_id=tenant_id,
            checked_at=checked_at,
            risks=risks,
            score=score,
        )

    # ── SSH 설정 점검 ─────────────────────────────────────────────────────── #

    def _check_ssh_config(self) -> list[Risk]:
        risks: list[Risk] = []
        sshd_config_path = "/etc/ssh/sshd_config"
        try:
            with open(sshd_config_path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            log.debug("sshd_config not found at %s", sshd_config_path)
            return risks
        except PermissionError:
            risks.append(Risk(
                category="ssh_config",
                detail=f"permission denied reading {sshd_config_path}",
                severity="medium",
            ))
            return risks

        lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]

        # PermitRootLogin 확인
        permit_root = None
        for line in lines:
            if line.lower().startswith("permitrootlogin"):
                parts = line.split()
                if len(parts) >= 2:
                    permit_root = parts[1].lower()
                break

        if permit_root is None or permit_root in ("yes", "without-password", "prohibit-password"):
            risks.append(Risk(
                category="ssh_config",
                detail=f"PermitRootLogin is '{permit_root or 'not set (default allows)'}' — root SSH login may be possible",
                severity="critical" if permit_root == "yes" else "high",
            ))

        # PasswordAuthentication 확인
        password_auth = None
        for line in lines:
            if line.lower().startswith("passwordauthentication"):
                parts = line.split()
                if len(parts) >= 2:
                    password_auth = parts[1].lower()
                break

        if password_auth is None or password_auth == "yes":
            risks.append(Risk(
                category="ssh_config",
                detail=f"PasswordAuthentication is '{password_auth or 'yes (default)'}' — brute force possible",
                severity="high",
            ))

        return risks

    # ── SUID 바이너리 점검 ────────────────────────────────────────────────── #

    def _check_suid_binaries(self) -> list[Risk]:
        risks: list[Risk] = []
        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            binaries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            risks.append(Risk(
                category="suid_binary",
                detail="SUID scan timed out after 60s",
                severity="medium",
            ))
            return risks
        except Exception as exc:
            risks.append(Risk(
                category="suid_binary",
                detail=f"SUID scan failed: {exc}",
                severity="medium",
            ))
            return risks

        # 알려진 정상 SUID 바이너리 화이트리스트
        _KNOWN_SUID: frozenset[str] = frozenset({
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
            "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
            "/usr/bin/gpasswd", "/bin/ping", "/usr/bin/ping",
            "/bin/mount", "/bin/umount", "/usr/bin/pkexec",
        })

        suspicious = [b for b in binaries if b not in _KNOWN_SUID]
        if suspicious:
            risks.append(Risk(
                category="suid_binary",
                detail=f"Unexpected SUID binaries found: {', '.join(suspicious[:20])}",
                severity="high",
            ))

        return risks

    # ── 빈 패스워드 계정 점검 ────────────────────────────────────────────── #

    def _check_empty_passwords(self) -> list[Risk]:
        risks: list[Risk] = []
        try:
            result = subprocess.run(
                ["getent", "shadow"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return risks

            empty_users: list[str] = []
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty_users.append(parts[0])

            if empty_users:
                risks.append(Risk(
                    category="empty_password",
                    detail=f"Accounts with empty passwords: {', '.join(empty_users)}",
                    severity="critical",
                ))
        except subprocess.TimeoutExpired:
            risks.append(Risk(
                category="empty_password",
                detail="empty password check timed out",
                severity="low",
            ))
        except Exception as exc:
            log.debug("empty_password_check_failed: %s", exc)

        return risks

    # ── 미패치 패키지 점검 ───────────────────────────────────────────────── #

    def _check_unpatched_packages(self) -> list[Risk]:
        risks: list[Risk] = []

        # apt 시도
        upgradable = self._run_apt_check()
        if upgradable is not None:
            if upgradable:
                risks.append(Risk(
                    category="unpatched_package",
                    detail=f"{upgradable} package(s) have available updates (apt)",
                    severity="high" if upgradable >= 10 else "medium",
                ))
            return risks

        # apt 없으면 yum 시도
        upgradable_yum = self._run_yum_check()
        if upgradable_yum is not None and upgradable_yum > 0:
            risks.append(Risk(
                category="unpatched_package",
                detail=f"{upgradable_yum} package(s) have available updates (yum)",
                severity="high" if upgradable_yum >= 10 else "medium",
            ))

        return risks

    def _run_apt_check(self) -> Optional[int]:
        """apt list --upgradable 실행. apt 없으면 None 반환."""
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/bin:/bin"},
            )
            if result.returncode not in (0, 100):
                return None
            lines = [ln for ln in result.stdout.splitlines() if "/" in ln and "upgradable" not in ln.lower()]
            return len(lines)
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            log.debug("apt_check_timed_out")
            return None
        except Exception:
            return None

    def _run_yum_check(self) -> Optional[int]:
        """yum check-update 실행. yum 없으면 None 반환."""
        try:
            result = subprocess.run(
                ["yum", "check-update"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            # yum check-update returns 100 when updates available, 0 when none, non-zero on error
            if result.returncode not in (0, 100):
                return None
            lines = [
                ln for ln in result.stdout.splitlines()
                if ln.strip() and not ln.startswith(" ") and not ln.startswith("Last") and "." in ln
            ]
            return len(lines)
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            log.debug("yum_check_timed_out")
            return None
        except Exception:
            return None

    # ── 점수 계산 ─────────────────────────────────────────────────────────── #

    _SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

    def _calculate_score(self, risks: list[Risk]) -> int:
        """위험 점수 계산 (0–100). 심각도별 가중치 합산 후 100 상한."""
        total = sum(self._SEVERITY_WEIGHTS.get(r.severity, 0) for r in risks)
        return min(total, 100)
