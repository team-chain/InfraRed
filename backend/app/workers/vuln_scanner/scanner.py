"""취약점 스캐너 — 에이전트가 수집한 데이터를 기반으로 취약점을 탐지."""
from __future__ import annotations

import asyncio
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session

log = get_logger(__name__)


# ── 데이터 모델 ────────────────────────────────────────────────────────────── #

@dataclass
class Finding:
    check_id: str
    title: str
    description: str
    severity: str           # critical | high | medium | low | info
    resource: str           # 영향 대상 (파일 경로, 포트, 패키지명 등)
    remediation: str        # 조치 방법

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "resource": self.resource,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    tenant_id: str
    asset_id: str
    scanned_at: str
    findings: list[Finding]
    severity_counts: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "scanned_at": self.scanned_at,
            "findings": [f.to_dict() for f in self.findings],
            "severity_counts": self.severity_counts,
        }


# ── VulnerabilityScanner ──────────────────────────────────────────────────── #

class VulnerabilityScanner:
    """시스템 취약점 스캔 — SSH 설정, 파일 권한 이상 탐지."""

    async def scan(self, tenant_id: str, asset_id: str) -> ScanResult:
        """전체 취약점 스캔 실행.

        점검 항목:
        - SSH 설정 파일 취약 옵션
        - 민감한 파일 권한 이상
        - world-writable 디렉터리 (핵심 경로)
        - 결과를 DB에 저장 후 ScanResult 반환
        """
        scanned_at = datetime.now(timezone.utc).isoformat()
        findings: list[Finding] = []

        # 비동기 작업들을 병렬 실행
        ssh_findings, perm_findings = await asyncio.gather(
            asyncio.to_thread(self._check_ssh_config),
            asyncio.to_thread(self._check_file_permissions),
        )
        findings.extend(ssh_findings)
        findings.extend(perm_findings)

        severity_counts = self._count_by_severity(findings)

        result = ScanResult(
            tenant_id=tenant_id,
            asset_id=asset_id,
            scanned_at=scanned_at,
            findings=findings,
            severity_counts=severity_counts,
        )

        await self._save_to_db(result)

        log.info(
            "vuln_scan_done tenant=%s asset=%s findings=%d critical=%d high=%d",
            tenant_id, asset_id, len(findings),
            severity_counts.get("critical", 0),
            severity_counts.get("high", 0),
        )

        return result

    # ── SSH 설정 취약점 점검 ─────────────────────────────────────────────── #

    def _check_ssh_config(self) -> list[Finding]:
        findings: list[Finding] = []
        path = "/etc/ssh/sshd_config"

        try:
            with open(path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            return findings
        except PermissionError:
            findings.append(Finding(
                check_id="SSH-001",
                title="SSH config unreadable",
                description=f"Cannot read {path} — permission denied",
                severity="medium",
                resource=path,
                remediation="Run scan with appropriate privileges",
            ))
            return findings

        lines = {
            k.lower(): v.lower()
            for line in content.splitlines()
            if (stripped := line.strip()) and not stripped.startswith("#")
            for k, _, v in [stripped.partition(" ")]
            if v
        }

        # SSH-001: PermitRootLogin
        prl = lines.get("permitrootlogin", "yes")
        if prl not in ("no",):
            findings.append(Finding(
                check_id="SSH-001",
                title="PermitRootLogin not disabled",
                description=f"PermitRootLogin is set to '{prl}'. Direct root SSH login increases attack surface.",
                severity="critical" if prl == "yes" else "high",
                resource=path,
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
            ))

        # SSH-002: PasswordAuthentication
        pwa = lines.get("passwordauthentication", "yes")
        if pwa == "yes":
            findings.append(Finding(
                check_id="SSH-002",
                title="SSH password authentication enabled",
                description="Password-based SSH authentication is enabled, allowing brute force attacks.",
                severity="high",
                resource=path,
                remediation="Set 'PasswordAuthentication no' and use key-based authentication only",
            ))

        # SSH-003: Protocol version (legacy)
        protocol = lines.get("protocol", "2")
        if protocol != "2":
            findings.append(Finding(
                check_id="SSH-003",
                title="Legacy SSH protocol version configured",
                description=f"SSH Protocol is set to '{protocol}'. Protocol 1 has known vulnerabilities.",
                severity="critical",
                resource=path,
                remediation="Remove 'Protocol' directive or set 'Protocol 2'",
            ))

        # SSH-004: PermitEmptyPasswords
        pep = lines.get("permitemptypasswords", "no")
        if pep == "yes":
            findings.append(Finding(
                check_id="SSH-004",
                title="SSH empty passwords permitted",
                description="SSH allows logins with empty passwords.",
                severity="critical",
                resource=path,
                remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
            ))

        # SSH-005: MaxAuthTries
        try:
            max_auth = int(lines.get("maxauthtries", "6"))
            if max_auth > 4:
                findings.append(Finding(
                    check_id="SSH-005",
                    title="SSH MaxAuthTries too high",
                    description=f"MaxAuthTries is {max_auth} — allows excessive brute force attempts per connection.",
                    severity="medium",
                    resource=path,
                    remediation="Set 'MaxAuthTries 3' or lower in /etc/ssh/sshd_config",
                ))
        except ValueError:
            pass

        return findings

    # ── 파일 권한 이상 탐지 ──────────────────────────────────────────────── #

    def _check_file_permissions(self) -> list[Finding]:
        findings: list[Finding] = []

        # 민감 파일 권한 점검
        sensitive_files: list[tuple[str, int, str]] = [
            ("/etc/shadow",       0o640, "Shadow password file should not be world-readable"),
            ("/etc/passwd",       0o644, "passwd file permission check"),
            ("/etc/sudoers",      0o440, "sudoers should be read-only by root"),
            ("/etc/ssh/sshd_config", 0o600, "sshd_config should be owner-readable only"),
        ]

        for path, max_mode, desc in sensitive_files:
            finding = self._check_file_mode(path, max_mode, desc)
            if finding:
                findings.append(finding)

        # world-writable 핵심 디렉터리 점검
        critical_dirs: list[str] = [
            "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
            "/lib", "/lib64",
        ]
        for d in critical_dirs:
            finding = self._check_world_writable(d)
            if finding:
                findings.append(finding)

        # /tmp, /var/tmp sticky bit 확인
        for tmp_dir in ["/tmp", "/var/tmp"]:
            finding = self._check_sticky_bit(tmp_dir)
            if finding:
                findings.append(finding)

        return findings

    def _check_file_mode(self, path: str, max_mode: int, desc: str) -> Optional[Finding]:
        try:
            st = os.stat(path)
        except (FileNotFoundError, PermissionError):
            return None

        actual_mode = stat.S_IMODE(st.st_mode)
        # world-readable 비트만 체크 (others read = 0o004, write = 0o002)
        world_write = bool(actual_mode & 0o002)
        world_read_shadow = path == "/etc/shadow" and bool(actual_mode & 0o004)

        if world_write or world_read_shadow:
            return Finding(
                check_id="PERM-001",
                title=f"Insecure file permissions: {path}",
                description=f"{desc}. Current mode: {oct(actual_mode)}",
                severity="critical" if world_write else "high",
                resource=path,
                remediation=f"Run: chmod {oct(max_mode)[2:]} {path}",
            )
        return None

    def _check_world_writable(self, path: str) -> Optional[Finding]:
        try:
            st = os.stat(path)
        except (FileNotFoundError, PermissionError):
            return None

        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o002:  # world-writable
            return Finding(
                check_id="PERM-002",
                title=f"World-writable critical directory: {path}",
                description=f"Critical system directory {path} is world-writable (mode: {oct(mode)}). Allows privilege escalation.",
                severity="critical",
                resource=path,
                remediation=f"Run: chmod o-w {path}",
            )
        return None

    def _check_sticky_bit(self, path: str) -> Optional[Finding]:
        try:
            st = os.stat(path)
        except (FileNotFoundError, PermissionError):
            return None

        mode = st.st_mode
        if not (mode & stat.S_ISVTX):  # sticky bit 없음
            return Finding(
                check_id="PERM-003",
                title=f"Sticky bit missing on temp directory: {path}",
                description=f"{path} is missing the sticky bit. Users can delete other users' files.",
                severity="medium",
                resource=path,
                remediation=f"Run: chmod +t {path}",
            )
        return None

    # ── 유틸리티 ─────────────────────────────────────────────────────────── #

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    async def _save_to_db(self, result: ScanResult) -> None:
        """vuln_scan_results 테이블에 스캔 결과 INSERT."""
        import json
        try:
            async with get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO vuln_scan_results
                          (tenant_id, asset_id, scanned_at, findings, critical_count, high_count)
                        VALUES
                          (:tenant_id, :asset_id, :scanned_at, CAST(:findings AS JSONB), :critical_count, :high_count)
                    """),
                    {
                        "tenant_id": result.tenant_id,
                        "asset_id": result.asset_id,
                        "scanned_at": result.scanned_at,
                        "findings": json.dumps([f.to_dict() for f in result.findings]),
                        "critical_count": result.severity_counts.get("critical", 0),
                        "high_count": result.severity_counts.get("high", 0),
                    },
                )
                await session.commit()
            log.info("vuln_scan_saved tenant=%s asset=%s", result.tenant_id, result.asset_id)
        except Exception as exc:
            log.warning("vuln_scan_db_save_failed: %s", exc)
