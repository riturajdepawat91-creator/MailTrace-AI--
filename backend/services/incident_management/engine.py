"""SOC Incident Management V1.

Converts Detection Correlation incident candidates into
deterministic, bounded, analyst-oriented incident objects.

This module is intentionally side-effect free:
- no database writes
- no alert mutation
- no Detection Correlation mutation
- no modification of existing Threat Intelligence calculations
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


ENGINE_NAME = "soc95-incident-management"
ENGINE_VERSION = "1.0"

MAX_INCIDENTS = 1000
MAX_ALERTS_PER_INCIDENT = 5000
MAX_IOCS_PER_INCIDENT = 5000
MAX_MITRE_PER_INCIDENT = 1000


_STATUS_NEW = "NEW"
_STATUS_TRIAGED = "TRIAGED"
_STATUS_INVESTIGATING = "INVESTIGATING"
_STATUS_CONTAINMENT = "CONTAINMENT"
_STATUS_RESOLVED = "RESOLVED"
_STATUS_CLOSED = "CLOSED"

_VALID_STATUSES = {
    _STATUS_NEW,
    _STATUS_TRIAGED,
    _STATUS_INVESTIGATING,
    _STATUS_CONTAINMENT,
    _STATUS_RESOLVED,
    _STATUS_CLOSED,
}

_SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_PRIORITY_RANK = {
    "P5": 0,
    "P4": 1,
    "P3": 2,
    "P2": 3,
    "P1": 4,
}


def _clamp(
    value: Any,
    low: float = 0.0,
    high: float = 100.0,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = low

    if number != number:
        number = low

    return max(low, min(high, number))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return list(value)

    return [value]


def _clean_strings(
    value: Any,
    *,
    limit: int = 5000,
) -> List[str]:
    output = set()

    for item in _as_list(value):
        if item is None:
            continue

        if isinstance(item, Mapping):
            candidates = [
                item.get("ioc"),
                item.get("value"),
                item.get("indicator"),
                item.get("id"),
                item.get("technique"),
                item.get("technique_id"),
                item.get("mitre_id"),
            ]
        else:
            candidates = [item]

        for candidate in candidates:
            if isinstance(candidate, str):
                text = candidate.strip()
                if text:
                    output.add(text)

        if len(output) >= limit:
            break

    return sorted(output)[:limit]


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        dt = value

    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        except (OverflowError, OSError, ValueError):
            return None

    elif isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        normalized = text.replace("Z", "+00:00")

        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None

    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().upper()

    if severity in _SEVERITY_RANK:
        return severity

    if severity in {"SEV-1", "S1"}:
        return "CRITICAL"

    if severity in {"SEV-2", "S2"}:
        return "HIGH"

    if severity in {"SEV-3", "S3"}:
        return "MEDIUM"

    if severity in {"SEV-4", "S4"}:
        return "LOW"

    return "INFO"


def _highest_severity(values: Iterable[Any]) -> str:
    normalized = [
        _normalize_severity(value)
        for value in values
    ]

    if not normalized:
        return "INFO"

    return max(
        normalized,
        key=lambda item: _SEVERITY_RANK.get(item, 0),
    )


def _priority_for(
    severity: str,
    incident_score: float,
    confidence: float,
    alert_count: int,
) -> str:
    severity = _normalize_severity(severity)
    score = _clamp(incident_score)
    confidence = _clamp(
        confidence,
        0.0,
        1.0,
    )

    points = 0.0

    points += {
        "INFO": 0.0,
        "LOW": 10.0,
        "MEDIUM": 25.0,
        "HIGH": 40.0,
        "CRITICAL": 55.0,
    }.get(severity, 0.0)

    points += score * 0.30
    points += confidence * 10.0
    points += min(
        max(alert_count - 1, 0),
        10,
    ) * 1.5

    if points >= 85:
        return "P1"

    if points >= 65:
        return "P2"

    if points >= 40:
        return "P3"

    if points >= 20:
        return "P4"

    return "P5"


def _status_for(
    severity: str,
    score: float,
    confidence: float,
) -> str:
    severity = _normalize_severity(severity)
    score = _clamp(score)
    confidence = _clamp(
        confidence,
        0.0,
        1.0,
    )

    if severity == "CRITICAL" or score >= 90.0:
        return _STATUS_TRIAGED

    if severity == "HIGH" or score >= 70.0:
        return _STATUS_TRIAGED

    if confidence >= 0.70 and score >= 45.0:
        return _STATUS_TRIAGED

    return _STATUS_NEW


def _deterministic_incident_id(
    source_incident_id: Any,
    alert_ids: Sequence[str],
    iocs: Sequence[str],
) -> str:
    seed_parts = [
        str(source_incident_id or "").strip(),
        *sorted(
            set(
                str(item).strip()
                for item in alert_ids
                if str(item).strip()
            )
        ),
        *sorted(
            set(
                str(item).strip()
                for item in iocs
                if str(item).strip()
            )
        ),
    ]

    digest = hashlib.sha256(
        "|".join(seed_parts).encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"INC-{digest}"


def _relationship_count(
    candidate: Mapping[str, Any],
) -> int:
    try:
        return max(
            0,
            int(
                candidate.get(
                    "relationship_count",
                    0,
                )
            ),
        )
    except (TypeError, ValueError):
        return 0


def _extract_alert_ids(
    candidate: Mapping[str, Any],
) -> List[str]:
    values = []

    for key in (
        "alert_ids",
        "correlated_alert_ids",
        "alerts",
        "alert_id",
    ):
        values.extend(
            _clean_strings(
                candidate.get(key),
                limit=MAX_ALERTS_PER_INCIDENT,
            )
        )

    return sorted(
        set(values)
    )[:MAX_ALERTS_PER_INCIDENT]


def _extract_iocs(
    candidate: Mapping[str, Any],
    alert_lookup: Mapping[str, Mapping[str, Any]],
) -> List[str]:
    values = []

    for key in (
        "iocs",
        "ioc_values",
        "indicators",
        "indicator_values",
        "shared_iocs",
        "correlated_iocs",
        "relationship_iocs",
    ):
        values.extend(
            _clean_strings(
                candidate.get(key),
                limit=MAX_IOCS_PER_INCIDENT,
            )
        )

    relationships = candidate.get(
        "relationships",
        [],
    )

    if isinstance(relationships, list):
        for relationship in relationships:
            if not isinstance(relationship, Mapping):
                continue

            for key in (
                "iocs",
                "shared_iocs",
                "ioc_values",
                "indicators",
            ):
                values.extend(
                    _clean_strings(
                        relationship.get(key),
                        limit=MAX_IOCS_PER_INCIDENT,
                    )
                )

    for alert_id in _extract_alert_ids(candidate):
        alert = alert_lookup.get(
            alert_id,
            {},
        )

        if not isinstance(alert, Mapping):
            continue

        for key in (
            "iocs",
            "ioc_values",
            "indicators",
            "indicator_values",
        ):
            values.extend(
                _clean_strings(
                    alert.get(key),
                    limit=MAX_IOCS_PER_INCIDENT,
                )
            )

    return sorted(
        set(values)
    )[:MAX_IOCS_PER_INCIDENT]


def _extract_mitre(
    candidate: Mapping[str, Any],
    alert_lookup: Mapping[str, Mapping[str, Any]],
) -> List[str]:
    values = []

    for key in (
        "mitre",
        "mitre_attack",
        "mitre_ids",
        "techniques",
        "technique_ids",
    ):
        values.extend(
            _clean_strings(
                candidate.get(key),
                limit=MAX_MITRE_PER_INCIDENT,
            )
        )

    for alert_id in _extract_alert_ids(candidate):
        alert = alert_lookup.get(
            alert_id,
            {},
        )

        if not isinstance(alert, Mapping):
            continue

        for key in (
            "mitre",
            "mitre_attack",
            "mitre_ids",
            "techniques",
            "technique_ids",
        ):
            values.extend(
                _clean_strings(
                    alert.get(key),
                    limit=MAX_MITRE_PER_INCIDENT,
                )
            )

    return sorted(
        set(values)
    )[:MAX_MITRE_PER_INCIDENT]


def _extract_campaigns(
    candidate: Mapping[str, Any],
    alert_lookup: Mapping[str, Mapping[str, Any]],
) -> List[str]:
    values = []

    for key in (
        "campaigns",
        "campaign",
        "campaign_id",
        "shared_campaigns",
        "correlated_campaigns",
    ):
        values.extend(
            _clean_strings(
                candidate.get(key),
                limit=500,
            )
        )

    relationships = candidate.get(
        "relationships",
        [],
    )

    if isinstance(relationships, list):
        for relationship in relationships:
            if not isinstance(relationship, Mapping):
                continue

            for key in (
                "campaigns",
                "shared_campaigns",
                "campaign_ids",
            ):
                values.extend(
                    _clean_strings(
                        relationship.get(key),
                        limit=500,
                    )
                )

    for alert_id in _extract_alert_ids(candidate):
        alert = alert_lookup.get(
            alert_id,
            {},
        )

        if not isinstance(alert, Mapping):
            continue

        for key in (
            "campaigns",
            "campaign",
            "campaign_id",
        ):
            values.extend(
                _clean_strings(
                    alert.get(key),
                    limit=500,
                )
            )

    return sorted(
        set(values)
    )[:500]


def _extract_actors(
    candidate: Mapping[str, Any],
    alert_lookup: Mapping[str, Mapping[str, Any]],
) -> List[str]:
    values = []

    for key in (
        "actors",
        "actor",
        "threat_actor",
        "threat_actors",
    ):
        values.extend(
            _clean_strings(
                candidate.get(key),
                limit=500,
            )
        )

    for alert_id in _extract_alert_ids(candidate):
        alert = alert_lookup.get(
            alert_id,
            {},
        )

        if not isinstance(alert, Mapping):
            continue

        for key in (
            "actors",
            "actor",
            "threat_actor",
            "threat_actors",
        ):
            values.extend(
                _clean_strings(
                    alert.get(key),
                    limit=500,
                )
            )

    return sorted(set(values))[:500]


def _extract_time_window(
    candidate: Mapping[str, Any],
    alert_lookup: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Optional[str]]:
    timestamps = []

    candidate_times = [
        candidate.get("first_seen"),
        candidate.get("last_seen"),
        candidate.get("timestamp"),
        candidate.get("created_at"),
        candidate.get("updated_at"),
    ]

    for value in candidate_times:
        parsed = _parse_timestamp(value)

        if parsed:
            timestamps.append(parsed)

    for alert_id in _extract_alert_ids(candidate):
        alert = alert_lookup.get(
            alert_id,
            {},
        )

        if not isinstance(alert, Mapping):
            continue

        for key in (
            "timestamp",
            "created_at",
            "updated_at",
            "first_seen",
            "last_seen",
        ):
            parsed = _parse_timestamp(
                alert.get(key)
            )

            if parsed:
                timestamps.append(parsed)

    if not timestamps:
        return {
            "first_seen": None,
            "last_seen": None,
        }

    timestamps.sort()

    return {
        "first_seen": timestamps[0].isoformat(),
        "last_seen": timestamps[-1].isoformat(),
    }


def _soc95_manage_incidents_base(
    detection_correlation: Optional[Mapping[str, Any]] = None,
    *,
    alert_intelligence: Optional[Mapping[str, Any]] = None,
    existing_status: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build analyst-ready incident management intelligence."""

    detection_correlation = (
        detection_correlation
        if isinstance(
            detection_correlation,
            Mapping,
        )
        else {}
    )

    alert_intelligence = (
        alert_intelligence
        if isinstance(
            alert_intelligence,
            Mapping,
        )
        else {}
    )

    existing_status = (
        existing_status
        if isinstance(
            existing_status,
            Mapping,
        )
        else {}
    )

    raw_candidates = detection_correlation.get(
        "incident_candidates",
        [],
    )

    if not isinstance(raw_candidates, list):
        raw_candidates = []

    raw_alerts = []

    for alert_key in (
        "detections",
        "alerts",
        "alert_list",
        "items",
        "records",
    ):
        candidate_alerts = alert_intelligence.get(
            alert_key,
            [],
        )

        if isinstance(
            candidate_alerts,
            list,
        ):
            raw_alerts.extend(
                candidate_alerts
            )

    if isinstance(
        alert_intelligence,
        Mapping,
    ):
        nested = alert_intelligence.get(
            "alert_intelligence",
            {},
        )

        if isinstance(
            nested,
            Mapping,
        ):
            nested_alerts = nested.get(
                "detections",
                [],
            )

            if isinstance(
                nested_alerts,
                list,
            ):
                raw_alerts.extend(
                    nested_alerts
                )

    alert_lookup: Dict[
        str,
        Mapping[str, Any],
    ] = {}

    for alert in raw_alerts:
        if not isinstance(alert, Mapping):
            continue

        alert_id = str(
            alert.get("alert_id")
            or alert.get("id")
            or ""
        ).strip()

        if alert_id:
            alert_lookup[alert_id] = alert

    incidents: List[Dict[str, Any]] = []
    seen_fingerprints = set()
    suppressed_duplicates = 0

    for raw_candidate in raw_candidates[:MAX_INCIDENTS]:
        if not isinstance(raw_candidate, Mapping):
            continue

        alert_ids = _extract_alert_ids(
            raw_candidate
        )

        iocs = _extract_iocs(
            raw_candidate,
            alert_lookup,
        )

        mitre = _extract_mitre(
            raw_candidate,
            alert_lookup,
        )

        campaigns = [item.upper() for item in _extract_campaigns(raw_candidate, alert_lookup)]

        actors = _extract_actors(
            raw_candidate,
            alert_lookup,
        )

        source_incident_id = str(
            raw_candidate.get("incident_id")
            or raw_candidate.get("id")
            or ""
        ).strip()

        severity = _normalize_severity(
            raw_candidate.get("severity")
            or raw_candidate.get("incident_severity")
        )

        incident_score = _clamp(
            raw_candidate.get(
                "incident_score",
                raw_candidate.get(
                    "score",
                    0.0,
                ),
            )
        )

        confidence = _clamp(
            raw_candidate.get(
                "confidence",
                0.0,
            ),
            0.0,
            1.0,
        )

        fingerprint = (
            tuple(sorted(alert_ids)),
            tuple(sorted(iocs)),
            tuple(sorted(campaigns)),
            tuple(sorted(actors)),
        )

        if fingerprint in seen_fingerprints:
            suppressed_duplicates += 1
            continue

        seen_fingerprints.add(
            fingerprint
        )

        relation_count = _relationship_count(
            raw_candidate
        )

        priority = _priority_for(
            severity,
            incident_score,
            confidence,
            len(alert_ids),
        )

        status = _status_for(
            severity,
            incident_score,
            confidence,
        )

        if (
            source_incident_id
            and source_incident_id in existing_status
        ):
            requested_status = str(
                existing_status[source_incident_id]
            ).strip().upper()

            if requested_status in _VALID_STATUSES:
                status = requested_status

        incident_id = _deterministic_incident_id(
            source_incident_id,
            alert_ids,
            iocs,
        )

        reasons = _clean_strings(
            raw_candidate.get(
                "correlation_reasons"
            ),
            limit=100,
        )

        if not reasons:
            reasons = _clean_strings(
                raw_candidate.get(
                    "reasons"
                ),
                limit=100,
            )

        time_window = _extract_time_window(
            raw_candidate,
            alert_lookup,
        )

        analyst_state = {
            "assigned_to": None,
            "decision": "UNDECIDED",
            "disposition": "OPEN",
            "notes_required": False,
        }

        incidents.append(
            {
                "incident_id": incident_id,
                "source_incident_id": (
                    source_incident_id
                    or None
                ),
                "status": status,
                "priority": priority,
                "severity": severity,
                "incident_score": round(
                    incident_score,
                    3,
                ),
                "confidence": round(
                    confidence,
                    4,
                ),
                "alert_count": len(alert_ids),
                "relationship_count": relation_count,
                "alert_ids": alert_ids,
                "iocs": iocs,
                "campaigns": campaigns,
                "actors": actors,
                "mitre_techniques": mitre,
                "correlation_reasons": reasons,
                "time_window": time_window,
                "analyst_state": analyst_state,
                "lifecycle": {
                    "current": status,
                    "reopen_supported": True,
                    "terminal_statuses": [
                        _STATUS_RESOLVED,
                        _STATUS_CLOSED,
                    ],
                },
            }
        )

    incidents.sort(
        key=lambda item: (
            -_PRIORITY_RANK.get(
                item["priority"],
                0,
            ),
            -_SEVERITY_RANK.get(
                item["severity"],
                0,
            ),
            -float(
                item["incident_score"]
            ),
            item["incident_id"],
        )
    )

    incidents = incidents[:MAX_INCIDENTS]

    correlated_alert_ids = sorted({
        alert_id
        for incident in incidents
        for alert_id in incident.get(
            "alert_ids",
            [],
        )
    })

    priority_distribution = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0,
        "P5": 0,
    }

    severity_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    status_distribution = {
        status: 0
        for status in sorted(
            _VALID_STATUSES
        )
    }

    for incident in incidents:
        priority_distribution[
            incident["priority"]
        ] += 1

        severity_distribution[
            incident["severity"]
        ] += 1

        status_distribution[
            incident["status"]
        ] += 1

    avg_score = (
        sum(
            item["incident_score"]
            for item in incidents
        )
        / len(incidents)
        if incidents
        else 0.0
    )

    avg_confidence = (
        sum(
            item["confidence"]
            for item in incidents
        )
        / len(incidents)
        if incidents
        else 0.0
    )

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "status": (
            "INCIDENTS_CREATED"
            if incidents
            else "NO_INCIDENTS"
        ),
        "source_detection_engine": str(
            detection_correlation.get(
                "engine",
                "",
            )
        ),
        "source_detection_version": str(
            detection_correlation.get(
                "version",
                "",
            )
        ),
        "input_candidate_count": len(
            raw_candidates
        ),
        "incident_count": len(
            incidents
        ),
        "duplicate_incident_count": (
            suppressed_duplicates
        ),
        "correlated_alert_count": len(
            correlated_alert_ids
        ),
        "priority_distribution": (
            priority_distribution
        ),
        "severity_distribution": (
            severity_distribution
        ),
        "status_distribution": (
            status_distribution
        ),
        "average_incident_score": round(
            _clamp(avg_score),
            3,
        ),
        "average_confidence": round(
            _clamp(
                avg_confidence,
                0.0,
                1.0,
            ),
            4,
        ),
        "incident_ids": [
            incident["incident_id"]
            for incident in incidents
        ],
        "incidents": incidents,
        "management_capabilities": {
            "deduplication": True,
            "lifecycle": True,
            "priority": True,
            "severity_aggregation": True,
            "risk_aggregation": True,
            "confidence_aggregation": True,
            "alert_mapping": True,
            "ioc_mapping": True,
            "campaign_mapping": True,
            "actor_mapping": True,
            "mitre_mapping": True,
            "reopen_support": True,
            "analyst_decision_state": True,
            "persistence": False,
        },
    }

def _soc95_normalize_context_values(value):
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        output = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                output.append(text)
        return sorted(set(output))

    if isinstance(value, dict):
        output = []
        for item in value.values():
            if item is None:
                continue
            if isinstance(item, (list, tuple, set)):
                output.extend(
                    str(x).strip()
                    for x in item
                    if x is not None and str(x).strip()
                )
            else:
                text = str(item).strip()
                if text:
                    output.append(text)
        return sorted(set(output))

    text = str(value).strip()

    if not text:
        return []

    return [text]


def _soc95_enrich_incident_context(
    incident_result,
    detection_correlation,
):
    if not isinstance(incident_result, dict):
        return incident_result

    candidates = []

    if isinstance(detection_correlation, dict):
        raw_candidates = detection_correlation.get(
            "incident_candidates",
            [],
        )

        if isinstance(raw_candidates, list):
            candidates = [
                item
                for item in raw_candidates
                if isinstance(item, dict)
            ]

    candidate_map = {}

    for candidate in candidates:

        source_id = candidate.get(
            "incident_id"
        )

        if source_id is None:
            continue

        candidate_map[
            str(source_id).strip().lower()
        ] = candidate

    incidents = incident_result.get(
        "incidents",
        [],
    )

    if not isinstance(incidents, list):
        return incident_result

    for incident in incidents:

        if not isinstance(incident, dict):
            continue

        source_id = incident.get(
            "source_incident_id"
        )

        candidate = candidate_map.get(
            str(source_id).strip().lower()
        ) if source_id is not None else None

        if candidate is None:
            continue

        mappings = {
            "iocs": candidate.get(
                "iocs",
                [],
            ),
            "campaigns": candidate.get(
                "campaigns",
                [],
            ),
            "actors": candidate.get(
                "actors",
                [],
            ),
            "malware": candidate.get(
                "malware",
                [],
            ),
            "mitre_techniques": candidate.get(
                "mitre_techniques",
                [],
            ),
        }

        for field, candidate_value in mappings.items():

            normalized_candidate = (
                _soc95_normalize_context_values(
                    candidate_value
                )
            )

            if not normalized_candidate:
                continue

            current_value = _soc95_normalize_context_values(
                incident.get(field)
            )

            if not current_value:
                incident[field] = (
                    normalized_candidate
                )

    return incident_result


_soc95_manage_incidents_wrapped = True


def manage_incidents(
    detection_correlation,
    alert_intelligence=None,
    existing_status=None,
):
    result = _soc95_manage_incidents_base(
        detection_correlation=detection_correlation,
        alert_intelligence=alert_intelligence,
        existing_status=existing_status,
    )

    return _soc95_enrich_incident_context(
        result,
        detection_correlation,
    )
