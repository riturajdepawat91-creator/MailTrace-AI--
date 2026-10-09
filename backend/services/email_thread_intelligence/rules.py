from __future__ import annotations

import re
from typing import Any


MAX_MESSAGES = 100
MAX_TEXT_CHARS = 2 * 1024 * 1024
MAX_PARTICIPANTS = 500
MAX_REFERENCES = 200
MAX_ANOMALIES = 100
MAX_EVIDENCE = 100

EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b"
)

REPLY_PREFIX_RE = re.compile(
    r"(?i)^\s*(re|fw|fwd)\s*:\s*"
)

QUOTED_HEADER_RE = re.compile(
    r"(?im)^\s*(from|sent|to|cc|subject)\s*:"
)


def _bounded(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


def normalize_subject(subject: Any) -> str:
    value = _bounded(subject, 4096).strip()

    previous = None
    while value and value != previous:
        previous = value
        value = REPLY_PREFIX_RE.sub("", value).strip()

    return re.sub(r"\s+", " ", value).casefold()


def normalize_message_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().casefold()


def extract_email(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    match = EMAIL_RE.search(value)
    return match.group(0).casefold() if match else ""


def extract_emails(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []

    seen: set[str] = set()
    result: list[str] = []

    for email in EMAIL_RE.findall(value):
        normalized = email.casefold()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

        if len(result) >= MAX_PARTICIPANTS:
            break

    return result


def normalize_references(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []

    tokens = value.replace(",", " ").split()
    result: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        normalized = token.strip().casefold()
        if not normalized:
            continue

        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

        if len(result) >= MAX_REFERENCES:
            break

    return result


def detect_quoted_content(body: Any) -> dict[str, Any]:
    text = _bounded(body)

    lines = text.splitlines()
    quoted_line_count = 0
    quoted_header_hits = 0

    for line in lines[:20000]:
        stripped = line.lstrip()

        if stripped.startswith(">"):
            quoted_line_count += 1

        if QUOTED_HEADER_RE.search(line):
            quoted_header_hits += 1

    return {
        "quoted_line_count": quoted_line_count,
        "quoted_header_hits": quoted_header_hits,
        "quoted_content_detected": (
            quoted_line_count > 0 or quoted_header_hits > 0
        ),
    }
