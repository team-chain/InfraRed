"""Sensitive-data masking before transport."""
from __future__ import annotations

import re


PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(password=)[^\s]+"), r"\1***"),
    (re.compile(r"(?i)(token=)[^\s]+"), r"\1***"),
    (re.compile(r"(?i)(secret=)[^\s]+"), r"\1***"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1***"),
)


def mask_line(line: str) -> str:
    masked = line.rstrip("\n")
    for pattern, replacement in PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked
