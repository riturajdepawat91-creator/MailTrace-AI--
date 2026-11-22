"""Authentication evidence adapter with explicit trust states."""

from __future__ import annotations

from email.message import Message
from typing import Any

from services.domain_alignment import compare_domains
from services.email_parser import analyze_authentication as extract_reported_authentication


AUTH_CHECKS = ("spf", "dkim", "dmarc")
ALLOWED_STATES = {"PASS", "FAIL", "NONE", "UNAVAILABLE", "INVALID"}


def analyze_authentication_evidence(
    message: Message,
    sender_domain: str | None,
    *,
    mock_results: dict[str, Any] | None = None,
    verification_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Report untrusted claims; mock results are reserved for tests only."""
    extracted = extract_reported_authentication(message)
    claims = extracted.get("reported_results", {})
    reported = {
        name: str(claims.get(name) or "NOT_FOUND").upper()
        for name in AUTH_CHECKS
    }
    checks = {}
    for name in AUTH_CHECKS:
        verified = verification_results.get("checks", {}).get(name) if isinstance(verification_results, dict) else None
        injected = mock_results.get(name) if isinstance(mock_results, dict) else None
        if isinstance(verified, dict):
            state = str(verified.get("state") or "UNAVAILABLE").upper()
            checks[name] = {
                "state": state if state in ALLOWED_STATES else "INVALID",
                "source": str(verified.get("source") or "INDEPENDENT_VERIFICATION"),
                "reported_claim": reported[name],
                **({"policy_state": verified["policy_state"]} if name == "spf" and verified.get("policy_state") else {}),
            }
            continue
        if injected is None:
            checks[name] = {
                "state": "UNAVAILABLE",
                "source": "NO_LIVE_DNS_OR_CRYPTOGRAPHIC_VALIDATION_IN_PHASE_2B",
                "reported_claim": reported[name],
            }
            continue
        state = str(injected).upper()
        if state not in ALLOWED_STATES:
            state = "INVALID"
        checks[name] = {
            "state": state,
            "source": "MOCK_ONLY_NOT_LIVE_VERIFICATION",
            "reported_claim": reported[name],
        }
    mock_dmarc_domain = str(mock_results.get("dmarc_domain") or "") if isinstance(mock_results, dict) else ""
    verified_alignment = verification_results.get("sender_domain_alignment") if isinstance(verification_results, dict) else None
    if isinstance(verified_alignment, dict):
        state = str(verified_alignment.get("state") or "UNAVAILABLE").upper()
        alignment = {
            "state": state if state in ALLOWED_STATES else "INVALID",
            "reason": "Independent DKIM/SPF domain alignment evaluation.",
            "source": str(verified_alignment.get("source") or "INDEPENDENT_VERIFICATION"),
        }
    elif checks["dmarc"]["source"] == "MOCK_ONLY_NOT_LIVE_VERIFICATION" and checks["dmarc"]["state"] == "PASS" and sender_domain and mock_dmarc_domain:
        alignment_state = compare_domains(sender_domain, mock_dmarc_domain)
        alignment = {
            "state": "PASS" if alignment_state in {"EXACT_HOST", "ORGANIZATIONAL_ALIGNMENT"} else "FAIL" if alignment_state == "MISMATCH" else "INVALID",
            "reason": "Test-only mocked authentication domain compared using local organizational-domain alignment.",
            "source": "MOCK_ONLY_NOT_LIVE_VERIFICATION",
        }
    else:
        alignment = {
            "state": "UNAVAILABLE",
            "reason": "No trusted authentication result is available for alignment analysis.",
        }
    return {
        "checks": checks,
        "sender_domain_alignment": alignment,
        "reported_header_trusted": False,
        "independent_verification": bool(
            isinstance(verification_results, dict)
            and verification_results.get("independent_verification") is True
        ),
    }
