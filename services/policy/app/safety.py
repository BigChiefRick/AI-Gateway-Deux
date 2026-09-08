from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}\b", re.IGNORECASE),
    "openai_style_key": re.compile(r"\b(?:sk|m0)-[A-Za-z0-9_-]{16,}\b"),
    "github_token": re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "us_ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "email_address": re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
    ),
    "phone_number": re.compile(
        r"(?<!\d)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
    ),
}

_PAYMENT_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _passes_luhn(candidate: str) -> bool:
    digits = [int(character) for character in candidate if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def scan_text(value: str) -> set[str]:
    """Return violation labels only; never return the matched sensitive value."""
    violations = {label for label, pattern in _PATTERNS.items() if pattern.search(value)}
    if any(_passes_luhn(match.group(0)) for match in _PAYMENT_CARD_CANDIDATE.finditer(value)):
        violations.add("payment_card")
    return violations


def scan_value(value: Any) -> set[str]:
    if isinstance(value, str):
        return scan_text(value)
    if isinstance(value, Mapping):
        violations: set[str] = set()
        for item in value.values():
            violations.update(scan_value(item))
        return violations
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        violations = set()
        for item in value:
            violations.update(scan_value(item))
        return violations
    return set()
