"""Sensitive-data masking before transport.

Coverage (설계서 2.3):
  URL query string : token, api_key, password, session 파라미터
  HTTP 헤더        : Authorization (Bearer / Basic), Cookie
  개인정보 패턴    : 이메일 주소, 한국/국제 전화번호
"""
from __future__ import annotations

import re


PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # ── URL query string 파라미터 ─────────────────────────────────────
    (re.compile(r"(?i)(password=)[^\s&\"']+"), r"\1***"),
    (re.compile(r"(?i)(token=)[^\s&\"']+"), r"\1***"),
    (re.compile(r"(?i)(api_key=)[^\s&\"']+"), r"\1***"),
    (re.compile(r"(?i)(secret=)[^\s&\"']+"), r"\1***"),
    (re.compile(r"(?i)(session=)[^\s&\"']+"), r"\1***"),
    # ── HTTP 헤더 ──────────────────────────────────────────────────────
    # Authorization: Bearer <token>  /  Authorization: Basic <base64>
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s,\"']+"), r"\1***"),
    # Cookie: 헤더 전체 값 마스킹
    (re.compile(r"(?i)(cookie:\s*)\S.*"), r"\1***"),
    # ── 개인정보 패턴 ──────────────────────────────────────────────────
    # 이메일 주소
    (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "***@***.***",
    ),
    # 전화번호: 한국(010-xxxx-xxxx, 02-xxx-xxxx 등) + 국제(+82 포함)
    (
        re.compile(
            r"(?<!\d)"
            r"(\+?82[\s\-]?)?"          # 국가코드(선택)
            r"0\d{1,2}"                 # 지역/통신사 코드
            r"[\s\-]?"
            r"\d{3,4}"
            r"[\s\-]?"
            r"\d{4}"
            r"(?!\d)"
        ),
        "***-****-****",
    ),
)


def mask_line(line: str) -> str:
    masked = line.rstrip("\n")
    for pattern, replacement in PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked
