"""Bounded RFC 5322/MIME parsing shared by analysis and forensic paths."""

from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Any


MAX_EMAIL_BYTES = 25 * 1024 * 1024
MAX_MIME_PARTS = 1000
MAX_MIME_DEPTH = 20
MAX_TOTAL_HEADERS = 1000


class EmailParseLimitError(ValueError):
    """The message exceeded a parser resource bound and was not analyzed."""


def parse_email_bytes(raw_email: bytes) -> tuple[Message, dict[str, Any]]:
    """Parse bytes and inspect structure iteratively before recursive consumers run."""
    if not isinstance(raw_email, bytes):
        raise TypeError("Email source must be bytes.")
    if len(raw_email) > MAX_EMAIL_BYTES:
        raise EmailParseLimitError("Email file exceeds the 25 MiB parser limit.")

    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    stack: list[tuple[Message, int, str]] = [(message, 0, "0")]
    part_count = 0
    max_depth_seen = 0
    header_count = 0
    defects: list[dict[str, str]] = []

    while stack:
        part, depth, part_path = stack.pop()
        if depth > MAX_MIME_DEPTH:
            raise EmailParseLimitError("Email MIME nesting exceeds the 20-level parser limit.")

        part_count += 1
        max_depth_seen = max(max_depth_seen, depth)
        if part_count > MAX_MIME_PARTS:
            raise EmailParseLimitError("Email MIME structure exceeds the 1000-part parser limit.")

        header_count += len(list(part.raw_items()))
        if header_count > MAX_TOTAL_HEADERS:
            raise EmailParseLimitError("Email headers exceed the 1000-field parser limit.")

        for defect in getattr(part, "defects", ()):
            defects.append({
                "part": part_path,
                "type": type(defect).__name__,
            })

        payload = part.get_payload()
        if isinstance(payload, list):
            for child_index in range(len(payload) - 1, -1, -1):
                child = payload[child_index]
                if isinstance(child, Message):
                    stack.append((child, depth + 1, f"{part_path}.{child_index}"))

    return message, {
        "status": "PARTIAL" if defects else "COMPLETE",
        "defects": defects,
        "mime_part_count": part_count,
        "mime_max_depth": max_depth_seen,
        "header_field_count": header_count,
        "limits": {
            "max_email_bytes": MAX_EMAIL_BYTES,
            "max_mime_parts": MAX_MIME_PARTS,
            "max_mime_depth": MAX_MIME_DEPTH,
            "max_total_headers": MAX_TOTAL_HEADERS,
        },
    }
