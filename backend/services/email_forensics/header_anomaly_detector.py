from __future__ import annotations

import re
from collections import Counter
from email.utils import parseaddr
from typing import Any


SENSITIVE_HEADERS = {
    "from",
    "reply-to",
    "return-path",
    "message-id",
    "sender",
    "date",
}


def _normalize_email(value: str | None) -> str:
    """
    Extract and normalize an email address.
    """

    if not value:
        return ""

    _, address = parseaddr(str(value))

    return address.strip().lower()


def _extract_domain(email_address: str) -> str:
    """
    Extract domain from an email address.
    """

    if not email_address or "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower()


def _extract_message_id_domain(message_id: str | None) -> str:
    """
    Extract domain portion from Message-ID.
    """

    if not message_id:
        return ""

    match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        str(message_id),
    )

    if not match:
        return ""

    return match.group(1).lower()


def _get_header_values(
    headers: dict[str, Any],
    header_name: str,
) -> list[str]:
    """
    Safely retrieve one or more values for a header.
    """

    value = headers.get(header_name)

    if value is None:
        value = headers.get(header_name.lower())

    if value is None:
        value = headers.get(header_name.title())

    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    if isinstance(value, str):
        return [value.strip()] if value.strip() else []

    return [str(value).strip()]


def _add_finding(
    findings: list[dict[str, Any]],
    *,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: dict[str, Any] | None = None,
    score: int = 0,
) -> None:
    """
    Add structured forensic finding.
    """

    findings.append(
        {
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "evidence": evidence or {},
            "score": score,
        }
    )


def detect_header_anomalies(
    parsed_headers: dict[str, Any],
) -> dict[str, Any]:
    """
    Advanced email header anomaly detection.

    This detector focuses on structural and identity-level
    inconsistencies that may indicate spoofing, manipulation,
    impersonation, or suspicious mail infrastructure.
    """

    findings: list[dict[str, Any]] = []

    raw_headers = parsed_headers.get("headers", parsed_headers)

    if not isinstance(raw_headers, dict):
        raw_headers = {}

    normalized_keys = [
        str(key).lower().strip()
        for key in raw_headers.keys()
    ]

    # --------------------------------------------------
    # 1. DUPLICATE SENSITIVE HEADERS
    # --------------------------------------------------

    header_counter = Counter(normalized_keys)

    for header_name, count in header_counter.items():

        if (
            header_name in SENSITIVE_HEADERS
            and count > 1
        ):

            _add_finding(
                findings,
                severity="medium",
                category="duplicate_header",
                title=f"Duplicate sensitive header: {header_name}",
                description=(
                    f"The header '{header_name}' appears "
                    f"{count} times. Duplicate identity-related "
                    "headers can indicate manipulation or "
                    "ambiguous sender information."
                ),
                evidence={
                    "header": header_name,
                    "count": count,
                },
                score=8,
            )

    # --------------------------------------------------
    # 2. EXTRACT IDENTITY HEADERS
    # --------------------------------------------------

    from_values = _get_header_values(
        raw_headers,
        "from",
    )

    reply_to_values = _get_header_values(
        raw_headers,
        "reply-to",
    )

    return_path_values = _get_header_values(
        raw_headers,
        "return-path",
    )

    sender_values = _get_header_values(
        raw_headers,
        "sender",
    )

    message_id_values = _get_header_values(
        raw_headers,
        "message-id",
    )

    from_email = (
        _normalize_email(from_values[0])
        if from_values
        else ""
    )

    reply_to_email = (
        _normalize_email(reply_to_values[0])
        if reply_to_values
        else ""
    )

    return_path_email = (
        _normalize_email(return_path_values[0])
        if return_path_values
        else ""
    )

    sender_email = (
        _normalize_email(sender_values[0])
        if sender_values
        else ""
    )

    # --------------------------------------------------
    # 3. FROM / REPLY-TO DOMAIN MISMATCH
    # --------------------------------------------------

    from_domain = _extract_domain(from_email)

    reply_to_domain = _extract_domain(
        reply_to_email
    )

    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    ):

        _add_finding(
            findings,
            severity="high",
            category="identity_mismatch",
            title="From and Reply-To domains differ",
            description=(
                "The visible sender domain differs from the "
                "Reply-To destination domain. This pattern is "
                "commonly associated with impersonation and "
                "credential-phishing attempts."
            ),
            evidence={
                "from_email": from_email,
                "from_domain": from_domain,
                "reply_to_email": reply_to_email,
                "reply_to_domain": reply_to_domain,
            },
            score=15,
        )

    # --------------------------------------------------
    # 4. FROM / RETURN-PATH MISMATCH
    # --------------------------------------------------

    return_path_domain = _extract_domain(
        return_path_email
    )

    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    ):

        _add_finding(
            findings,
            severity="medium",
            category="sender_alignment",
            title="From and Return-Path domains differ",
            description=(
                "The visible From domain does not match the "
                "Return-Path domain. This is not always malicious, "
                "but it is relevant forensic evidence when "
                "combined with other anomalies."
            ),
            evidence={
                "from_domain": from_domain,
                "return_path_domain": return_path_domain,
            },
            score=8,
        )

    # --------------------------------------------------
    # 5. FROM / SENDER MISMATCH
    # --------------------------------------------------

    sender_domain = _extract_domain(sender_email)

    if (
        from_domain
        and sender_domain
        and from_domain != sender_domain
    ):

        _add_finding(
            findings,
            severity="medium",
            category="identity_mismatch",
            title="From and Sender domains differ",
            description=(
                "The Sender header identifies infrastructure "
                "different from the visible From domain."
            ),
            evidence={
                "from_domain": from_domain,
                "sender_domain": sender_domain,
            },
            score=7,
        )

    # --------------------------------------------------
    # 6. MESSAGE-ID DOMAIN ANALYSIS
    # --------------------------------------------------

    if message_id_values:

        message_id_domain = (
            _extract_message_id_domain(
                message_id_values[0]
            )
        )

        if (
            message_id_domain
            and from_domain
            and message_id_domain != from_domain
        ):

            _add_finding(
                findings,
                severity="low",
                category="message_id",
                title="Message-ID domain differs from sender domain",
                description=(
                    "The domain embedded in Message-ID differs "
                    "from the visible sender domain. This may be "
                    "legitimate for mailing platforms but can also "
                    "provide infrastructure attribution evidence."
                ),
                evidence={
                    "message_id_domain": message_id_domain,
                    "from_domain": from_domain,
                    "message_id": message_id_values[0],
                },
                score=4,
            )

    else:

        _add_finding(
            findings,
            severity="medium",
            category="missing_header",
            title="Message-ID header missing",
            description=(
                "The email does not contain a Message-ID header. "
                "Missing Message-ID information can reduce "
                "traceability and may be suspicious depending "
                "on the sending infrastructure."
            ),
            evidence={},
            score=6,
        )

    # --------------------------------------------------
    # 7. DATE HEADER CHECK
    # --------------------------------------------------

    date_values = _get_header_values(
        raw_headers,
        "date",
    )

    if not date_values:

        _add_finding(
            findings,
            severity="medium",
            category="missing_header",
            title="Date header missing",
            description=(
                "The email does not contain a Date header."
            ),
            evidence={},
            score=5,
        )

    # --------------------------------------------------
    # 8. HEADER VALUE CONTROL CHARACTER CHECK
    # --------------------------------------------------

    suspicious_control_headers = []

    for key, value in raw_headers.items():

        values = (
            value
            if isinstance(value, list)
            else [value]
        )

        for item in values:

            text = str(item)

            if re.search(
                r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
                text,
            ):

                suspicious_control_headers.append(
                    {
                        "header": str(key),
                        "value": text[:200],
                    }
                )

    if suspicious_control_headers:

        _add_finding(
            findings,
            severity="high",
            category="header_structure",
            title="Suspicious control characters detected",
            description=(
                "One or more header values contain unexpected "
                "control characters."
            ),
            evidence={
                "affected_headers":
                    suspicious_control_headers,
            },
            score=15,
        )

    # --------------------------------------------------
    # 9. REQUIRED HEADER PRESENCE
    # --------------------------------------------------

    required_headers = [
        "from",
        "to",
        "subject",
    ]

    missing_required = []

    for header_name in required_headers:

        values = _get_header_values(
            raw_headers,
            header_name,
        )

        if not values:
            missing_required.append(header_name)

    if missing_required:

        _add_finding(
            findings,
            severity="medium",
            category="missing_header",
            title="Expected email headers missing",
            description=(
                "One or more commonly expected message headers "
                "are missing."
            ),
            evidence={
                "missing_headers": missing_required,
            },
            score=5 * len(missing_required),
        )

    # --------------------------------------------------
    # 10. SCORE CALCULATION
    # --------------------------------------------------

    anomaly_score = sum(
        item.get("score", 0)
        for item in findings
    )

    anomaly_score = min(anomaly_score, 100)

    high_count = sum(
        1
        for item in findings
        if item["severity"] == "high"
    )

    medium_count = sum(
        1
        for item in findings
        if item["severity"] == "medium"
    )

    low_count = sum(
        1
        for item in findings
        if item["severity"] == "low"
    )

    if anomaly_score >= 50:
        risk_level = "high"

    elif anomaly_score >= 25:
        risk_level = "medium"

    elif anomaly_score > 0:
        risk_level = "low"

    else:
        risk_level = "none"

    # --------------------------------------------------
    # RESULT
    # --------------------------------------------------

    return {
        "anomaly_score": anomaly_score,

        "risk_level": risk_level,

        "finding_count": len(findings),

        "severity_summary": {
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },

        "identity_snapshot": {
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_to_email": reply_to_email,
            "reply_to_domain": reply_to_domain,
            "return_path_email": return_path_email,
            "return_path_domain": return_path_domain,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
        },

        "findings": findings,
    }
