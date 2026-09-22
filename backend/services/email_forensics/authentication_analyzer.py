from __future__ import annotations

import re
from typing import Any


def _extract_result(
    text: str,
    key: str
) -> str:
    """
    Extract an authentication result such as:
    spf=pass, dkim=fail, dmarc=none
    """
    match = re.search(
        rf"\b{re.escape(key)}\s*=\s*([a-zA-Z]+)",
        text,
        re.IGNORECASE
    )

    if not match:
        return "NOT_FOUND"

    return match.group(1).upper()


def analyze_authentication(
    headers: dict[str, Any]
) -> dict[str, Any]:
    """
    Analyze SPF, DKIM and DMARC evidence from
    Authentication-Results and related headers.

    This module reports observed evidence only.
    It does not claim sender identity.
    """

    authentication = headers.get(
        "authentication",
        {}
    )

    authentication_results = authentication.get(
        "authentication_results",
        []
    )

    received_spf = authentication.get(
        "received_spf",
        []
    )

    dkim_signature = authentication.get(
        "dkim_signature",
        []
    )

    combined_results = " ".join(
        authentication_results
    )

    # -----------------------------------------------------
    # AUTHENTICATION RESULTS
    # -----------------------------------------------------

    spf = _extract_result(
        combined_results,
        "spf"
    )

    dkim = _extract_result(
        combined_results,
        "dkim"
    )

    dmarc = _extract_result(
        combined_results,
        "dmarc"
    )

    # -----------------------------------------------------
    # FALLBACK SPF
    # -----------------------------------------------------

    if spf == "NOT_FOUND" and received_spf:
        spf = _extract_result(
            " ".join(received_spf),
            "spf"
        )

    # -----------------------------------------------------
    # DKIM SIGNATURE PRESENCE
    # -----------------------------------------------------

    dkim_signature_present = bool(
        dkim_signature
    )

    # -----------------------------------------------------
    # SENDER ALIGNMENT
    # -----------------------------------------------------

    sender = headers.get("from")
    return_path = headers.get("return_path")

    alignment = "UNKNOWN"

    if sender and return_path:
        sender_domain = re.search(
            r"@([A-Za-z0-9.-]+)",
            sender
        )

        return_domain = re.search(
            r"@([A-Za-z0-9.-]+)",
            return_path
        )

        if sender_domain and return_domain:
            alignment = (
                "ALIGNED"
                if sender_domain.group(1).lower()
                == return_domain.group(1).lower()
                else "MISMATCH"
            )

    # -----------------------------------------------------
    # RISK ASSESSMENT
    # -----------------------------------------------------

    findings: list[dict[str, Any]] = []

    if spf == "FAIL":
        findings.append({
            "type": "spf",
            "severity": "HIGH",
            "title": "SPF validation failed",
            "description": (
                "The observed authentication "
                "results report an SPF failure."
            )
        })

    elif spf == "PASS":
        findings.append({
            "type": "spf",
            "severity": "INFO",
            "title": "SPF validation passed",
            "description": (
                "The observed authentication "
                "results report an SPF pass."
            )
        })

    if dkim == "FAIL":
        findings.append({
            "type": "dkim",
            "severity": "HIGH",
            "title": "DKIM validation failed",
            "description": (
                "The observed authentication "
                "results report a DKIM failure."
            )
        })

    elif dkim == "NONE" and not dkim_signature_present:
        findings.append({
            "type": "dkim",
            "severity": "MEDIUM",
            "title": "No DKIM signature observed",
            "description": (
                "No DKIM signature or successful "
                "DKIM authentication was observed."
            )
        })

    if dmarc == "FAIL":
        findings.append({
            "type": "dmarc",
            "severity": "CRITICAL",
            "title": "DMARC validation failed",
            "description": (
                "The observed authentication "
                "results report a DMARC failure."
            )
        })

    elif dmarc == "PASS":
        findings.append({
            "type": "dmarc",
            "severity": "INFO",
            "title": "DMARC validation passed",
            "description": (
                "The observed authentication "
                "results report a DMARC pass."
            )
        })

    if alignment == "MISMATCH":
        findings.append({
            "type": "alignment",
            "severity": "HIGH",
            "title": "Sender and Return-Path domains differ",
            "description": (
                "The visible sender domain and "
                "Return-Path domain do not match."
            )
        })

    # -----------------------------------------------------
    # OVERALL RISK
    # -----------------------------------------------------

    critical_count = sum(
        1
        for item in findings
        if item["severity"] == "CRITICAL"
    )

    high_count = sum(
        1
        for item in findings
        if item["severity"] == "HIGH"
    )

    medium_count = sum(
        1
        for item in findings
        if item["severity"] == "MEDIUM"
    )

    if critical_count > 0:
        risk = "HIGH"
    elif high_count >= 2:
        risk = "HIGH"
    elif high_count == 1 or medium_count > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "dkim_signature_present": dkim_signature_present,
        "sender_return_path_alignment": alignment,
        "risk": risk,
        "findings": findings,
        "finding_count": len(findings)
    }
