"""Shared status vocabulary for detector and enrichment outcomes.

Provider-specific values remain in ``provider_status``; this module never
changes risk scores or treats lack of coverage as a benign finding.
"""
from __future__ import annotations

from typing import Any

RESULT_STATES = {"PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE", "NOT_RUN"}


def check_result(status: str, *, provider_status: str | None = None,
                 message: str | None = None, outcome: str | None = None) -> dict[str, Any]:
    normalized = str(status or "UNKNOWN").strip().upper()
    if normalized not in RESULT_STATES:
        normalized = "UNKNOWN"
    result: dict[str, Any] = {"status": normalized}
    if provider_status:
        result["provider_status"] = str(provider_status)[:80]
    if message:
        result["message"] = str(message)[:240]
    if outcome:
        result["outcome"] = str(outcome)[:64]
    return result


def state_from_lookup(*, attempted: bool, success: bool | None,
                      matches: int | None = None, applicable: bool = True) -> str:
    if not applicable:
        return "NOT_APPLICABLE"
    if not attempted:
        return "NOT_RUN"
    if success is None:
        return "UNKNOWN"
    if success is False:
        return "ERROR"
    return "FAIL" if (matches or 0) > 0 else "PASS"


def build_analysis_statuses(result: dict[str, Any]) -> dict[str, Any]:
    """Build stable statuses for supported analysis components from final output."""
    parsed = result.get("parsing") if isinstance(result.get("parsing"), dict) else {}
    parse_raw = str(parsed.get("status") or "UNKNOWN").upper()
    parsing = "PASS" if parse_raw == "COMPLETE" else "UNKNOWN" if parse_raw in {"PARTIAL", "UNKNOWN"} else "ERROR"

    ai = result.get("email_ai") if isinstance(result.get("email_ai"), dict) else {}
    model_raw = str(ai.get("status") or "NOT_RUN").upper()
    model = "ERROR" if model_raw in {"ERROR", "FAILED"} else "NOT_RUN" if model_raw in {"SKIPPED", "NOT_RUN", "MODEL_NOT_READY", "UNAVAILABLE"} else "PASS"

    ti = result.get("threat_intelligence") if isinstance(result.get("threat_intelligence"), dict) else {}
    ti_raw = str(ti.get("status") or "UNKNOWN").lower()
    if ti_raw == "matched": ti_state = "FAIL"
    elif ti_raw == "no_matches" and str(ti.get("coverage_status", "")).upper() in {"FRESH", "COMPLETE", "FULL"}: ti_state = "PASS"
    elif ti_raw in {"error", "coverage_limited"}: ti_state = "ERROR" if ti_raw == "error" else "UNKNOWN"
    elif ti_raw in {"no_iocs", "not_configured", "disabled", "unavailable"}: ti_state = "NOT_RUN"
    else: ti_state = "UNKNOWN"

    fusion = result.get("intelligence_fusion") if isinstance(result.get("intelligence_fusion"), dict) else {}
    fusion_raw = str(fusion.get("status") or "UNKNOWN").upper()
    if fusion_raw == "ANALYZED": fusion_state = "PASS"
    elif fusion_raw in {"ERROR", "FAILED"}: fusion_state = "ERROR"
    elif fusion_raw in {"NOT_RUN", "SKIPPED"}: fusion_state = "NOT_RUN"
    else: fusion_state = "UNKNOWN"

    auth = (result.get("email_forensics") or {}).get("authentication_analysis", {}).get("validation", {})
    auth_states = {}
    for method in ("spf", "dkim", "dmarc"):
        item = auth.get(method) if isinstance(auth, dict) else None
        raw = str((item or {}).get("status") or "NOT_RUN").upper() if isinstance(item, dict) else "NOT_RUN"
        if raw in {"PASS", "POLICY_FOUND"}: state = "PASS"
        elif raw in {"FAIL", "SOFTFAIL", "PERMERROR", "NO_POLICY"}: state = "FAIL"
        elif raw in {"NOT_PRESENT", "NOT_VALIDATED", "NOT_VERIFIABLE_NON_PUBLIC_CLIENT_IP", "NO_VALID_FROM_DOMAIN"}: state = "NOT_APPLICABLE"
        elif raw in {"UNVERIFIED_NO_TRUSTED_SMTP_IP", "NOT_VALIDATED_MSG_CONVERSION"}: state = "NOT_RUN"
        elif raw in {"DNS_LOOKUP_ERROR", "TEMPERROR", "TEMPORARY_ERROR_OR_INVALID_KEY"}: state = "ERROR"
        elif raw == "NOT_RUN": state = "NOT_RUN"
        else: state = "UNKNOWN"
        auth_states[method] = check_result(state, provider_status=raw)

    ip_records = result.get("ip_intelligence") if isinstance(result.get("ip_intelligence"), dict) else {}
    geo_statuses = [((item.get("geolocation_status") or {}).get("status", "UNKNOWN"))
                    for item in ip_records.values() if isinstance(item, dict)]
    network_statuses = [((item.get("network_intelligence_status") or {}).get("status", "UNKNOWN"))
                        for item in ip_records.values() if isinstance(item, dict)]
    def aggregate_enrichment(values: list[str]) -> str:
        if not values: return "NOT_RUN"
        if any(value == "ERROR" for value in values): return "ERROR"
        if all(value == "NOT_APPLICABLE" for value in values): return "NOT_APPLICABLE"
        if any(value == "UNKNOWN" for value in values): return "UNKNOWN"
        return "PASS"

    return {
        "vocabulary": sorted(RESULT_STATES),
        "parsing": check_result(parsing, provider_status=parse_raw, message="Partial parsing requires analyst review." if parsing == "UNKNOWN" else None),
        "authentication": auth_states,
        "geolocation": check_result(aggregate_enrichment(geo_statuses), outcome=f"{len(geo_statuses)} IP record(s)"),
        "network_reputation": check_result(aggregate_enrichment(network_statuses), outcome=f"{len(network_statuses)} IP record(s)"),
        "model_inference": check_result(model, provider_status=model_raw, outcome="INFERENCE_COMPLETED" if model == "PASS" else "MODEL_UNAVAILABLE_OR_SKIPPED"),
        "threat_intelligence": check_result(
            ti_state,
            provider_status=ti_raw,
            message=("No extracted indicators; lookup was not performed." if ti_raw == "no_iocs" else
                     "Provider credentials are unavailable; lookup was not performed." if ti_raw == "not_configured" else None),
            outcome="ZERO_MATCHES" if ti_raw == "no_matches" else "MATCHES_FOUND" if ti_raw == "matched" else "NO_INDICATORS" if ti_raw == "no_iocs" else "MISSING_CREDENTIALS" if ti_raw == "not_configured" else None,
        ),
        "risk_fusion": check_result(fusion_state, provider_status=fusion_raw),
        "score": {"status": "PASS" if result.get("threat_analysis", {}).get("confidence_basis") == "intelligence_fusion" else "UNKNOWN",
                  "source": result.get("threat_analysis", {}).get("score_source"),
                  "confidence_status": "PASS" if result.get("threat_analysis", {}).get("confidence_value") is not None else "UNKNOWN"},
    }
