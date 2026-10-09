from __future__ import annotations

import re
from typing import Any


def validate_email_authentication(
    raw_email: bytes,
    sender: str | None,
    header_values: dict[str, Any],
    smtp_context: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate DKIM signatures and inspect DMARC DNS policy.

    Authentication-Results and Received-SPF inside an uploaded message are
    attacker-controlled evidence. SPF cannot be recomputed without trusted
    SMTP connection metadata, so it is explicitly left unverified here.
    """
    validation: dict[str, Any] = {
        "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
        "dkim": {"status": "NOT_PRESENT"},
        "dmarc": {"status": "UNKNOWN"},
        "reported_headers_trusted": False,
    }

    try:
        import dkim
        import dns.resolver
        from email.utils import parseaddr

        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 3.0

        if smtp_context:
            import ipaddress
            import spf

            client_ip = ipaddress.ip_address(smtp_context["client_ip"])
            if not client_ip.is_global:
                validation["spf"] = {
                    "status": "NOT_VERIFIABLE_NON_PUBLIC_CLIENT_IP",
                    "reason": "SPF checks require the public SMTP client IP.",
                }
            else:
                mail_from = smtp_context["mail_from"]
                if mail_from == "<>":
                    mail_from = f"postmaster@{smtp_context['helo']}"
                try:
                    spf_result, explanation = spf.check2(
                        i=str(client_ip),
                        s=mail_from,
                        h=smtp_context["helo"],
                        timeout=2,
                        querytime=6,
                    )
                    validation["spf"] = {
                        "status": spf_result.upper(),
                        "explanation": str(explanation)[:300],
                        "client_ip": str(client_ip),
                        "mail_from": smtp_context["mail_from"],
                        "helo": smtp_context["helo"],
                        "context_source": "hmac_authenticated_webhook",
                    }
                except Exception as error:
                    validation["spf"] = {
                        "status": "TEMPERROR",
                        "error": type(error).__name__,
                    }

        def dnsfunc(name: bytes, timeout: float = 5) -> bytes:
            query_name = name.decode("ascii", errors="ignore").rstrip(".")
            answers = resolver.resolve(query_name, "TXT", lifetime=3.0)
            return b"".join(
                b"".join(record.strings)
                for record in answers
            )

        signatures = header_values.get("dkim_signature", [])
        if signatures:
            verifier = dkim.DKIM(raw_email)
            outcomes = []
            for index in range(min(len(signatures), 2)):
                try:
                    outcomes.append(bool(verifier.verify(idx=index, dnsfunc=dnsfunc)))
                except Exception as error:
                    outcomes.append(None)
                    validation["dkim"]["error"] = type(error).__name__

            if any(outcomes):
                validation["dkim"] = {"status": "PASS"}
            elif all(outcome is False for outcome in outcomes):
                validation["dkim"] = {"status": "FAIL"}
            else:
                validation["dkim"]["status"] = "TEMPORARY_ERROR_OR_INVALID_KEY"

        address = parseaddr(sender or "")[1]
        domain = address.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        if not domain or "." not in domain:
            validation["dmarc"] = {"status": "NO_VALID_FROM_DOMAIN"}
        else:
            try:
                answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3.0)
                records = [
                    b"".join(record.strings).decode("utf-8", errors="replace")
                    for record in answers
                ]
                dmarc_record = next(
                    (record for record in records if record.lower().startswith("v=dmarc1")),
                    None,
                )
                validation["dmarc"] = (
                    {"status": "POLICY_FOUND", "record": dmarc_record, "domain": domain}
                    if dmarc_record
                    else {"status": "NO_POLICY", "domain": domain}
                )
            except dns.resolver.NXDOMAIN:
                validation["dmarc"] = {"status": "NO_POLICY", "domain": domain}
            except Exception as error:
                validation["dmarc"] = {
                    "status": "DNS_LOOKUP_ERROR",
                    "domain": domain,
                    "error": type(error).__name__,
                }
    except Exception as error:
        validation["validation_engine"] = "UNAVAILABLE"
        validation["error"] = type(error).__name__

    return validation


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
    headers: dict[str, Any],
    raw_email: bytes | None = None,
    smtp_context: dict[str, str] | None = None,
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

    result = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "reported_results": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
        },
        "authentication_results_trusted": False,
        "dkim_signature_present": dkim_signature_present,
        "sender_return_path_alignment": alignment,
        "risk": risk,
        "findings": findings,
        "finding_count": len(findings)
    }

    result["validation"] = (
        validate_email_authentication(raw_email, sender, authentication, smtp_context)
        if raw_email is not None
        else {
            "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
            "dkim": {"status": "NOT_VALIDATED"},
            "dmarc": {"status": "NOT_VALIDATED"},
            "reported_headers_trusted": False,
        }
    )
    return result
