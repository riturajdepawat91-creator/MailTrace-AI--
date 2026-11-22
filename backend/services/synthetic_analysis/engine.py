"""Offline threat analysis for attachment-free synthetic RFC 5322 messages.

This module intentionally has no Gmail, database, filesystem, or provider client.
Input bytes and decoded body text are used transiently and are not returned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.message import Message
from email.utils import parseaddr
import ipaddress
import re
import uuid
from urllib.parse import urlsplit

from services.email_parsing import (
    EmailParseLimitError,
    MAX_MIME_DEPTH,
    MAX_MIME_PARTS,
    MAX_TOTAL_HEADERS,
    parse_email_bytes,
)
from services.synthetic_analysis.authentication import analyze_authentication_evidence
from services.domain_alignment import normalized_host, organizational_domain
from services.link_deception_intelligence import analyze_link_deception
from services.threat_intelligence.ioc_normalizer import extract_iocs
from services.synthetic_analysis.scoring import (
    DEFAULT_POLICY,
    MANDATORY_CHECKS,
    score_findings,
)
from services.url_extraction import extract_url_evidence, normalize_url


ENGINE_VERSION = "synthetic-offline-1.0"
MAX_SYNTHETIC_MESSAGE_BYTES = 1 * 1024 * 1024
MAX_SYNTHETIC_BODY_CHARS = 256 * 1024
MAX_ANALYSIS_URLS = 100
MAX_ANALYSIS_IOCS = 200

_BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com"},
    "google": {"google.com", "google.com.au", "google.co.uk"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
}
_URGENCY_TERMS = (
    "immediately", "urgent", "within 24 hours", "account will be closed",
    "act now", "final warning", "suspended",
)
_CREDENTIAL_TERMS = (
    "enter your password", "verify your password", "confirm your password",
    "share your password", "login credentials", "verify your account",
    "one-time code", "one time code", "reset your password",
)
_PAYMENT_TERMS = (
    "change our bank details", "new bank account", "wire transfer",
    "send payment", "update payment details", "gift card",
)


class SyntheticInputError(ValueError):
    """Rejected synthetic input; message text is deliberately content-free."""


def _safe_url(value: str) -> tuple[str | None, str | None]:
    """Return an IOC-safe URL with path, userinfo, query and fragment removed."""
    normalized = normalize_url(value)
    if not normalized:
        return None, None
    try:
        parsed = urlsplit(normalized)
        host = parsed.hostname
        if not host:
            return None, None
        try:
            host = ipaddress.ip_address(host).compressed
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = normalized_host(host)
        if not host:
            return None, None
        port = parsed.port
        authority = f"{host}:{port}" if port and port not in (80, 443) else host
        return f"{parsed.scheme.lower()}://{authority}/[redacted]", host.strip("[]")
    except (ValueError, UnicodeError):
        return None, None


def _findings_for_body(body: str, sender_display: str, sender_domain: str) -> list[dict]:
    normalized = body.casefold()
    findings: list[dict] = []

    def add(code: str, category: str, severity: str, explanation: str, evidence_ref: str) -> None:
        findings.append({
            "id": f"MT-SYN-{code}",
            "category": category,
            "severity": severity,
            "explanation": explanation,
            "evidence_ref": evidence_ref,
            "method": "deterministic_local_heuristic",
            "confidence": "LIMITED_HEURISTIC",
        })

    lower_display = sender_display.casefold()
    sender_org = organizational_domain(sender_domain) if sender_domain else None
    for brand, domains in _BRANDS.items():
        if brand in lower_display and sender_org not in domains:
            add(
                "SENDER_DISPLAY_DOMAIN_MISMATCH", "sender_impersonation", "HIGH",
                "Display name contains a recognized brand cue while the sender domain is not an approved matching domain. This heuristic is not proof of impersonation.",
                "header.from.display_name",
            )
            break

    if any(term in normalized for term in _CREDENTIAL_TERMS):
        add("CREDENTIAL_REQUEST_LANGUAGE", "credential_theft", "HIGH",
            "Credential or account-verification language was detected; this indicator alone does not prove malicious intent.",
            "body.text.keyword_match")
    if any(term in normalized for term in _PAYMENT_TERMS):
        add("PAYMENT_MANIPULATION_LANGUAGE", "payment_manipulation", "HIGH",
            "Payment-change or transfer language was detected; this indicator alone does not prove fraud.",
            "body.text.keyword_match")
    if any(term in normalized for term in _URGENCY_TERMS):
        add("URGENCY_LANGUAGE", "social_engineering", "LOW",
            "Urgency language was detected; this indicator alone does not prove malicious intent.",
            "body.text.keyword_match")
    return findings


def _extract_body(message: Message) -> tuple[str, str]:
    if message.is_multipart():
        raise SyntheticInputError("Multipart messages are not accepted; use an attachment-free single-part synthetic fixture.")
    if message.get_content_disposition() == "attachment":
        raise SyntheticInputError("Attachment-bearing input is not accepted.")
    content_type = message.get_content_type().lower()
    if content_type not in {"text/plain", "text/html"}:
        raise SyntheticInputError("Only single-part text/plain or text/html synthetic EML is accepted.")
    try:
        body = message.get_content()
    except Exception as exc:
        raise SyntheticInputError("Synthetic message body encoding could not be decoded.") from exc
    if not isinstance(body, str):
        raise SyntheticInputError("Synthetic message body must decode as text.")
    if len(body) > MAX_SYNTHETIC_BODY_CHARS:
        raise SyntheticInputError("Synthetic message body exceeds the configured limit.")
    return body, content_type


def analyze_synthetic_email(
    raw_email: bytes, *, mock_authentication: dict | None = None,
    verification_results: dict | None = None,
) -> dict:
    """Analyze one attachment-free synthetic EML in memory and return a sanitized report.

    ``mock_authentication`` exists for unit tests only; the API never accepts it.
    """
    if not isinstance(raw_email, bytes):
        raise SyntheticInputError("Input must be EML bytes.")
    if not raw_email:
        raise SyntheticInputError("Synthetic EML is empty.")
    if len(raw_email) > MAX_SYNTHETIC_MESSAGE_BYTES:
        raise SyntheticInputError("Synthetic EML exceeds the 1 MiB prototype limit.")

    try:
        message, diagnostics = parse_email_bytes(raw_email)
    except (EmailParseLimitError, TypeError) as exc:
        raise SyntheticInputError("Synthetic EML exceeded parser safety limits.") from exc
    if diagnostics["mime_part_count"] > MAX_MIME_PARTS or diagnostics["mime_max_depth"] > MAX_MIME_DEPTH or diagnostics["header_field_count"] > MAX_TOTAL_HEADERS:
        raise SyntheticInputError("Synthetic EML exceeded parser safety limits.")

    body, body_type = _extract_body(message)
    from_value = str(message.get("From", ""))[:2048]
    sender_display, sender_address = parseaddr(from_value)
    sender_domain = sender_address.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in sender_address else ""
    sender_domain = normalized_host(sender_domain) or ""

    findings = _findings_for_body(body, sender_display[:128], sender_domain)
    link_analysis = analyze_link_deception(body if body_type == "text/html" else "")
    if link_analysis.severity in {"MEDIUM", "HIGH", "CRITICAL"}:
        findings.append({
            "id": "MT-SYN-DECEPTIVE_LINK",
            "category": "url_deception",
            "severity": str(link_analysis.severity),
            "explanation": "Static rendered-link analysis found a deceptive or high-risk link pattern; no URL was fetched.",
            "evidence_ref": "body.html.anchor_analysis",
            "method": "existing_local_link_deception_analyzer",
            "confidence": "STATIC_HEURISTIC",
        })

    url_evidence = extract_url_evidence([(0, body)], []) if body_type == "text/plain" else extract_url_evidence([], [(0, body)])
    urls = []
    for item in url_evidence[:MAX_ANALYSIS_URLS]:
        raw_url = str(item.get("original_url") or item.get("normalized_url", ""))
        safe_value, host = _safe_url(str(item.get("normalized_url", "")))
        if not safe_value or not host:
            continue
        urls.append({"value": safe_value, "host": host, "evidence_ref": "body.url", "validation": "NORMALIZED_LOCAL_ONLY"})
        try:
            parsed_url = urlsplit(raw_url)
            if parsed_url.username is not None or parsed_url.password is not None:
                findings.append({
                    "id": "MT-SYN-URL-USERINFO", "category": "suspicious_url", "severity": "HIGH",
                    "explanation": "URL contains a user-information component; the value is redacted from this report.",
                    "evidence_ref": "body.url.userinfo", "method": "local_url_structure", "confidence": "STATIC_HEURISTIC",
                })
        except ValueError:
            pass
        if re.search(r"%(?:25|2e|2f|5c|40|3a)", raw_url, re.I):
            findings.append({
                "id": "MT-SYN-URL-SUSPICIOUS-ENCODING", "category": "suspicious_url", "severity": "MEDIUM",
                "explanation": "URL contains selected percent-encoded delimiter patterns that can obscure its structure.",
                "evidence_ref": "body.url.encoding", "method": "local_url_structure", "confidence": "LIMITED_HEURISTIC",
            })
        try:
            ipaddress.ip_address(host)
            findings.append({
                "id": "MT-SYN-IP-LITERAL-URL", "category": "suspicious_url", "severity": "MEDIUM",
                "explanation": "URL uses an IP-literal host; this is a review indicator, not proof of maliciousness.",
                "evidence_ref": "body.url.host", "method": "local_url_structure", "confidence": "LIMITED_HEURISTIC",
            })
        except ValueError:
            pass

    # Existing normalizer is static. Remove its source fragments/original URL values
    # before returning anything so private paths/query values cannot escape.
    normalized_iocs = extract_iocs(body, url_evidence=url_evidence)[:MAX_ANALYSIS_IOCS]
    iocs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in normalized_iocs:
        kind = str(item.get("ioc_type") or item.get("indicator_type") or "").lower()
        raw_value = str(item.get("normalized_value") or item.get("value") or "")
        if kind == "url":
            safe_value, _ = _safe_url(raw_value)
            normalized = safe_value
        else:
            normalized = raw_value
        if not normalized or (kind, normalized) in seen:
            continue
        seen.add((kind, normalized))
        scope = None
        if kind == "ip":
            try:
                address = ipaddress.ip_address(normalized)
                scope = "private" if address.is_private else "public" if address.is_global else "non_public"
            except ValueError:
                continue
        safe_locations = []
        for location in item.get("source_locations", []):
            if not isinstance(location, dict):
                continue
            raw_offset = location.get("offset")
            offset = raw_offset if isinstance(raw_offset, int) and not isinstance(raw_offset, bool) and raw_offset >= 0 else None
            body_type = location.get("body_type")
            if body_type not in {"text/plain", "text/html"}:
                body_type = body_type if body_type in {"body.text", "additional_source"} else "body"
            sanitized_location = {"source": "body", "body_type": body_type}
            if offset is not None:
                sanitized_location["offset"] = offset
            if sanitized_location not in safe_locations:
                safe_locations.append(sanitized_location)
        if not safe_locations:
            safe_locations = [{"source": "body", "body_type": body_type}]
        evidence_refs = [
            f"body.ioc.{len(iocs) + 1}.occurrence.{index + 1}"
            for index, _ in enumerate(safe_locations)
        ]
        iocs.append({
            "type": kind,
            "value": normalized,
            "source_locations": safe_locations,
            "evidence_ref": evidence_refs[0],
            "evidence_refs": evidence_refs,
            "validation": "VALIDATED_LOCAL",
            **({"scope": scope} if scope else {}),
        })
        if len(iocs) >= MAX_ANALYSIS_IOCS:
            break

    authentication = analyze_authentication_evidence(
        message, sender_domain or None, mock_results=mock_authentication,
        verification_results=verification_results,
    )
    auth_failure_severity = {"spf": "HIGH", "dkim": "HIGH", "dmarc": "CRITICAL"}
    for check_name, severity in auth_failure_severity.items():
        if authentication["checks"][check_name]["state"] == "FAIL":
            findings.append({
                "id": f"MT-SYN-AUTH-{check_name.upper()}-FAIL",
                "category": "email_authentication",
                "severity": severity,
                "explanation": f"Independent {check_name.upper()} verification failed; this is authentication evidence, not proof of malicious intent.",
                "evidence_ref": f"authentication.{check_name}.verification",
                "method": "independent_authentication_verification",
                "confidence": "VERIFIED_TECHNICAL_RESULT",
            })
    mandatory_states = {
        "parser": "PASS" if diagnostics.get("status") == "COMPLETE" else "UNAVAILABLE",
        "sender_analysis": "PASS" if sender_address else "UNAVAILABLE",
        "sender_alignment": authentication["sender_domain_alignment"]["state"],
        "phishing_rules": "PASS",
        "url_extraction": "PASS",
        "ioc_extraction": "PASS",
        **{key: authentication["checks"][key]["state"] for key in ("spf", "dkim", "dmarc")},
    }
    scoring = score_findings(findings, mandatory_states, policy=DEFAULT_POLICY)
    findings = scoring["findings"]
    score = scoring["score"]
    score_breakdown = scoring["score_breakdown"]
    verdict = scoring["verdict"]
    verdict_explanation = scoring["explanation"]
    failed = sorted(name for name, state in mandatory_states.items() if state == "FAIL")
    unavailable = sorted(name for name, state in mandatory_states.items() if state in {"UNAVAILABLE", "NONE", "INVALID"})
    passed = sorted(name for name, state in mandatory_states.items() if state == "PASS")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "analysis_id": str(uuid.uuid4()),
        "synthetic_fixture_id": f"synthetic-{uuid.uuid4().hex[:12]}",
        "synthetic_test_analysis": True,
        "processing_status": "COMPLETED",
        "analysis_status": "COMPLETE" if all(mandatory_states.get(name) == "PASS" for name in MANDATORY_CHECKS) else "ANALYSIS_INCOMPLETE",
        "authentication": authentication,
        "sender_analysis": {
            "sender_domain": sender_domain or None,
            "display_name_present": bool(sender_display),
            "domain_format_valid": bool(sender_domain),
        },
        "findings": findings,
        "iocs": iocs,
        "risk": {
            "score": score,
            "score_is_probability": False,
            "verdict": verdict,
            "policy_version": scoring["policy_version"],
            "thresholds": scoring["thresholds"],
            "score_breakdown": score_breakdown,
            "explanation": verdict_explanation,
        },
        "evidence_references": sorted(
            {item["evidence_ref"] for item in findings}
            | {reference for item in iocs for reference in item.get("evidence_refs", [item["evidence_ref"]])}
        ),
        "checks_passed": passed,
        "checks_failed": failed,
        "checks_unavailable": unavailable,
        "check_states": mandatory_states,
        "parser_diagnostics": {
            "status": diagnostics.get("status"),
            "mime_part_count": diagnostics.get("mime_part_count"),
            "mime_max_depth": diagnostics.get("mime_max_depth"),
            "header_field_count": diagnostics.get("header_field_count"),
            "defect_count": len(diagnostics.get("defects", [])),
            "body_type": body_type,
        },
        "analysis_timestamp": now,
        "engine_version": ENGINE_VERSION,
    }
