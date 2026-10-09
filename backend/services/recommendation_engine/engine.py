from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Dict, List, Optional


ENGINE_NAME = "soc95-recommendation-engine"
ENGINE_VERSION = "1.0"

VALID_PRIORITIES = {
    "P1": 100,
    "P2": 80,
    "P3": 60,
    "P4": 40,
    "P5": 20,
}

ACTION_PRIORITY = {
    "CONTAIN": "P1",
    "BLOCK_IOC": "P1",
    "ISOLATE_ENDPOINT": "P1",
    "RESET_CREDENTIAL": "P1",
    "DISABLE_ACCOUNT": "P1",
    "QUARANTINE_ATTACHMENT": "P2",
    "ERADICATE": "P2",
    "REMOVE_ARTIFACT": "P2",
    "COLLECT_EVIDENCE": "P3",
    "THREAT_HUNT": "P3",
    "VERIFY": "P4",
    "CLOSE": "P5",
}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _lower(value: Any) -> str:
    return _text(value).casefold()


def _clamp(value: Any, low: float = 0.0, high: float = 100.0) -> float:
    try:
        number = float(value)
    except Exception:
        number = 0.0

    return round(max(low, min(high, number)), 3)


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except Exception:
        number = 0.0

    if number > 1.0:
        number /= 100.0

    return round(max(0.0, min(1.0, number)), 4)


def _clean(values: Any) -> List[str]:
    if values is None:
        return []

    if isinstance(values, (list, tuple, set)):
        raw = values
    else:
        raw = [values]

    result: List[str] = []
    seen = set()

    for value in raw:
        text = _text(value)
        if not text:
            continue

        key = text.casefold()

        if key in seen:
            continue

        seen.add(key)
        result.append(text)

    return result


def _nested(context: Dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = context

        valid = True

        for part in path.split("."):
            if not isinstance(current, dict):
                valid = False
                break

            if part not in current:
                valid = False
                break

            current = current[part]

        if valid:
            return current

    return None


def _first_text(context: Dict[str, Any], *paths: str) -> str:
    for path in paths:
        value = _nested(context, path)

        text = _text(value)

        if text:
            return text

    return ""


def _severity(context: Dict[str, Any]) -> str:
    value = _first_text(
        context,
        "severity",
        "case_management.severity",
        "incident_management.severity",
        "investigation_management.severity",
    )

    normalized = value.upper()

    if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return normalized

    return "INFO"


def _priority(context: Dict[str, Any]) -> str:
    explicit = _first_text(
        context,
        "priority",
        "case_management.priority",
        "incident_management.priority",
    ).upper()

    if explicit in VALID_PRIORITIES:
        return explicit

    severity = _severity(context)

    mapping = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
        "INFO": "P5",
    }

    return mapping.get(severity, "P5")


def _score(context: Dict[str, Any]) -> float:
    for path in (
        "score",
        "risk_score",
        "case_management.score",
        "case_management.incident_score",
        "incident_management.score",
        "incident_management.risk_score",
        "investigation_management.incident_score",
    ):
        value = _nested(context, path)

        if value is None:
            continue

        try:
            number = float(value)

            if number <= 1.0:
                number *= 100.0

            return _clamp(number)
        except Exception:
            continue

    return {
        "CRITICAL": 95.0,
        "HIGH": 80.0,
        "MEDIUM": 60.0,
        "LOW": 30.0,
        "INFO": 10.0,
    }.get(_severity(context), 0.0)


def _confidence_from_context(context: Dict[str, Any]) -> float:
    for path in (
        "confidence",
        "case_management.confidence",
        "incident_management.confidence",
        "investigation_management.confidence",
    ):
        value = _nested(context, path)

        if value is not None:
            return _confidence(value)

    return 0.0


def _collect(context: Dict[str, Any], field: str) -> List[str]:
    values: List[str] = []

    paths = [
        field,
        f"case_management.{field}",
        f"incident_management.{field}",
        f"investigation_management.{field}",
    ]

    for path in paths:
        value = _nested(context, path)
        values.extend(_clean(value))

    result: List[str] = []
    seen = set()

    for value in values:
        key = value.casefold()

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def _hash_id(prefix: str, *parts: Any) -> str:
    payload = "|".join(_text(part) for part in parts)

    digest = sha256(payload.encode("utf-8")).hexdigest()[:16].upper()

    return f"{prefix}-{digest}"


def _recommendation(
    action_type: str,
    priority: str,
    confidence: float,
    rationale: str,
    evidence: List[str],
    targets: List[str],
    context_id: str,
) -> Dict[str, Any]:

    recommendation_id = _hash_id(
        "REC",
        action_type,
        priority,
        confidence,
        rationale,
        sorted(evidence),
        sorted(targets),
        context_id,
    )

    return {
        "recommendation_id": recommendation_id,
        "action_type": action_type,
        "priority": priority,
        "status": "RECOMMENDED",
        "approval_required": True,
        "execution_allowed": False,
        "execution_side_effect": False,
        "confidence": confidence,
        "rationale": rationale,
        "evidence": evidence,
        "targets": targets,
        "context_id": context_id,
    }


def _add_unique(
    recommendations: List[Dict[str, Any]],
    recommendation: Dict[str, Any],
) -> None:

    existing = {
        item.get("action_type")
        for item in recommendations
    }

    action_type = recommendation.get("action_type")

    if action_type not in existing:
        recommendations.append(recommendation)


def recommend_actions(context: Dict[str, Any]) -> Dict[str, Any]:
    source_snapshot = deepcopy(context)

    severity = _severity(context)
    priority = _priority(context)
    score = _score(context)
    confidence = _confidence_from_context(context)

    iocs = _collect(context, "iocs")
    campaigns = _collect(context, "campaigns")
    actors = _collect(context, "actors")
    malware = _collect(context, "malware")
    mitre = _collect(context, "mitre_techniques")
    alert_ids = _collect(context, "alert_ids")

    case_id = _first_text(
        context,
        "case_id",
        "case_management.case_id",
    )

    incident_id = _first_text(
        context,
        "incident_id",
        "case_management.incident_id",
        "incident_management.incident_id",
    )

    investigation_id = _first_text(
        context,
        "investigation_id",
        "case_management.investigation_id",
        "investigation_management.investigation_id",
    )

    context_id = (
        case_id
        or incident_id
        or investigation_id
        or _hash_id(
            "CTX",
            severity,
            priority,
            score,
            sorted(iocs),
            sorted(campaigns),
            sorted(actors),
            sorted(malware),
        )
    )

    recommendations: List[Dict[str, Any]] = []

    # --------------------------------------------------------
    # CRITICAL / HIGH CONTAINMENT
    # --------------------------------------------------------

    if severity in {"CRITICAL", "HIGH"} or score >= 80:
        evidence = [
            f"severity={severity}",
            f"score={score}",
        ]

        if incident_id:
            evidence.append(f"incident={incident_id}")

        _add_unique(
            recommendations,
            _recommendation(
                "CONTAIN",
                "P1",
                max(confidence, 0.75),
                "High-risk activity warrants immediate containment review.",
                evidence,
                [incident_id or case_id or "affected-asset"],
                context_id,
            ),
        )

    # --------------------------------------------------------
    # IOC BLOCKING
    # --------------------------------------------------------

    if iocs:
        _add_unique(
            recommendations,
            _recommendation(
                "BLOCK_IOC",
                "P1" if severity == "CRITICAL" else "P2",
                max(confidence, 0.70),
                "Observed IOCs should be evaluated for blocking across relevant controls.",
                [
                    f"ioc_count={len(iocs)}",
                    *iocs[:5],
                ],
                iocs,
                context_id,
            ),
        )

    # --------------------------------------------------------
    # MALWARE / ATTACHMENT
    # --------------------------------------------------------

    if malware:
        _add_unique(
            recommendations,
            _recommendation(
                "QUARANTINE_ATTACHMENT",
                "P2",
                max(confidence, 0.78),
                "Malware evidence supports quarantine of the associated artifact for analyst review.",
                [
                    f"malware_count={len(malware)}",
                    *malware[:5],
                ],
                malware,
                context_id,
            ),
        )

        _add_unique(
            recommendations,
            _recommendation(
                "ERADICATE",
                "P2",
                max(confidence, 0.72),
                "Malware evidence supports eradication planning after containment and approval.",
                [
                    f"malware_count={len(malware)}",
                    *malware[:5],
                ],
                malware,
                context_id,
            ),
        )

    # --------------------------------------------------------
    # CRITICAL ENDPOINT ISOLATION
    # --------------------------------------------------------

    if severity == "CRITICAL":
        _add_unique(
            recommendations,
            _recommendation(
                "ISOLATE_ENDPOINT",
                "P1",
                max(confidence, 0.80),
                "Critical severity supports endpoint isolation review to limit potential lateral movement.",
                [
                    "severity=CRITICAL",
                    f"score={score}",
                ],
                [case_id or incident_id or "affected-endpoint"],
                context_id,
            ),
        )

    # --------------------------------------------------------
    # ACTOR / CAMPAIGN HUNTING
    # --------------------------------------------------------

    if actors or campaigns:
        pivots = actors + campaigns

        _add_unique(
            recommendations,
            _recommendation(
                "THREAT_HUNT",
                "P2" if severity in {"CRITICAL", "HIGH"} else "P3",
                max(confidence, 0.65),
                "Actor/campaign context supports proactive threat hunting across related telemetry.",
                [
                    f"actor_count={len(actors)}",
                    f"campaign_count={len(campaigns)}",
                    *pivots[:8],
                ],
                pivots,
                context_id,
            ),
        )

    # --------------------------------------------------------
    # MITRE / EVIDENCE COLLECTION
    # --------------------------------------------------------

    if mitre or alert_ids or incident_id or investigation_id:
        evidence = [
            f"alert_count={len(alert_ids)}",
            f"mitre_count={len(mitre)}",
        ]

        if incident_id:
            evidence.append(f"incident={incident_id}")

        if investigation_id:
            evidence.append(f"investigation={investigation_id}")

        _add_unique(
            recommendations,
            _recommendation(
                "COLLECT_EVIDENCE",
                "P3",
                max(confidence, 0.60),
                "Investigation context supports structured evidence collection before final disposition.",
                evidence,
                alert_ids + mitre,
                context_id,
            ),
        )

    # --------------------------------------------------------
    # ALWAYS VERIFY AFTER RESPONSE PLANNING
    # --------------------------------------------------------

    _add_unique(
        recommendations,
        _recommendation(
            "VERIFY",
            "P4",
            max(confidence, 0.50),
            "Post-response verification is recommended to confirm containment and residual-risk status.",
            [
                "verification_required=True",
            ],
            [case_id or incident_id or "response"],
            context_id,
        ),
    )

    # --------------------------------------------------------
    # CLOSE ONLY WHEN LOW RISK / CLEAN STATE
    # --------------------------------------------------------

    verification_status = _lower(
        _first_text(
            context,
            "verification_status",
            "response_verification.verification_status",
        )
    )

    close_recommended = (
        verification_status == "verified"
        and score <= 25
        and not iocs
        and severity in {"INFO", "LOW"}
    )

    if close_recommended:
        _add_unique(
            recommendations,
            _recommendation(
                "CLOSE",
                "P5",
                max(confidence, 0.65),
                "Verified low-risk state with no residual IOC evidence supports case closure review.",
                [
                    "verification_status=verified",
                    f"score={score}",
                    "residual_iocs=0",
                ],
                [case_id or incident_id or "case"],
                context_id,
            ),
        )

    recommendations = sorted(
        recommendations,
        key=lambda item: (
            VALID_PRIORITIES.get(item["priority"], 0) * -1,
            item["action_type"],
            item["recommendation_id"],
        ),
    )

    status = "NO_RECOMMENDATIONS"

    if recommendations:
        status = "RECOMMENDATIONS_READY"

    elif close_recommended:
        status = "CLOSE_READY"

    recommendation_score = 0.0

    if recommendations:
        weighted = [
            VALID_PRIORITIES.get(item["priority"], 0)
            for item in recommendations
        ]

        recommendation_score = _clamp(
            (sum(weighted) / len(weighted))
            + min(10.0, len(recommendations) * 1.5)
        )

    recommendation_confidence = 0.0

    if recommendations:
        recommendation_confidence = round(
            sum(
                float(item.get("confidence") or 0.0)
                for item in recommendations
            )
            / len(recommendations),
            4,
        )

    recommendation_id = _hash_id(
        "RECM",
        context_id,
        [
            (
                item["recommendation_id"],
                item["action_type"],
                item["priority"],
            )
            for item in recommendations
        ],
    )

    result = {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "recommendation_id": recommendation_id,
        "context_id": context_id,
        "status": status,
        "severity": severity,
        "priority": priority,
        "score": _clamp(recommendation_score),
        "confidence": _confidence(recommendation_confidence),
        "case_id": case_id,
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "alert_ids": alert_ids,
        "iocs": iocs,
        "campaigns": campaigns,
        "actors": actors,
        "malware": malware,
        "mitre_techniques": mitre,
        "recommendation_count": len(recommendations),
        "recommendations": recommendations,
        "close_recommended": close_recommended,
        "capabilities": {
            "containment_recommendation": any(
                item["action_type"] == "CONTAIN"
                for item in recommendations
            ),
            "ioc_block_recommendation": any(
                item["action_type"] == "BLOCK_IOC"
                for item in recommendations
            ),
            "malware_remediation_recommendation": any(
                item["action_type"] == "ERADICATE"
                for item in recommendations
            ),
            "evidence_collection_recommendation": any(
                item["action_type"] == "COLLECT_EVIDENCE"
                for item in recommendations
            ),
            "threat_hunting_recommendation": any(
                item["action_type"] == "THREAT_HUNT"
                for item in recommendations
            ),
            "verification_recommendation": any(
                item["action_type"] == "VERIFY"
                for item in recommendations
            ),
            "close_recommendation": close_recommended,
            "approval_tracking": True,
            "read_only": True,
            "persistence": False,
            "execution_side_effect": False,
            "simulation": True,
        },
        "input_immutable": source_snapshot == context,
    }

    return result


def recommend(context: Dict[str, Any]) -> Dict[str, Any]:
    return recommend_actions(context)


def build_recommendations(context: Dict[str, Any]) -> Dict[str, Any]:
    return recommend_actions(context)
