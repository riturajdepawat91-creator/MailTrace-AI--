from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


ENGINE_NAME = "soc95-investigation-management"
ENGINE_VERSION = "1.0"

INVESTIGATION_STATUSES = (
    "NEW",
    "ACTIVE",
    "EVIDENCE_REVIEW",
    "ANALYSIS",
    "CONCLUSION",
    "CLOSED",
)

TERMINAL_STATUSES = (
    "CLOSED",
)

PRIORITY_ORDER = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
    "P5": 5,
}

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = minimum

    return max(
        minimum,
        min(
            maximum,
            number,
        ),
    )


def _confidence(
    value: Any,
) -> float:
    return _clamp(
        value,
        0.0,
        1.0,
    )


def _clean_values(
    value: Any,
) -> List[str]:

    if value is None:
        return []

    if isinstance(
        value,
        dict,
    ):
        values: List[str] = []

        for item in value.values():
            values.extend(
                _clean_values(item)
            )

        return sorted(
            set(
                item
                for item in values
                if item
            )
        )

    if isinstance(
        value,
        (list, tuple, set),
    ):
        values = []

        for item in value:
            text = _text(item)

            if text:
                values.append(text)

        return sorted(
            set(values)
        )

    text = _text(value)

    return [text] if text else []


def _parse_time(
    value: Any,
) -> Optional[datetime]:

    text = _text(value)

    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00",
            )
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def _iso(
    value: Optional[datetime],
) -> Optional[str]:

    if value is None:
        return None

    return value.isoformat()


def _now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _deterministic_id(
    prefix: str,
    source: str,
) -> str:

    digest = hashlib.sha256(
        _text(source).encode(
            "utf-8"
        )
    ).hexdigest()[:16].upper()

    return (
        f"{prefix}-{digest}"
    )


def _severity(
    incident: Dict[str, Any],
) -> str:

    value = _text(
        incident.get(
            "severity"
        )
    ).upper()

    if value in SEVERITY_ORDER:
        return value

    return "INFO"


def _priority(
    incident: Dict[str, Any],
) -> str:

    value = _text(
        incident.get(
            "priority"
        )
    ).upper()

    if value in PRIORITY_ORDER:
        return value

    severity = _severity(
        incident
    )

    mapping = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
        "INFO": "P5",
    }

    return mapping[
        severity
    ]


def _incident_list(
    incidents: Any,
) -> List[Dict[str, Any]]:

    if isinstance(
        incidents,
        dict,
    ):
        incidents = incidents.get(
            "incidents",
            [],
        )

    if not isinstance(
        incidents,
        list,
    ):
        return []

    return [
        item
        for item in incidents
        if isinstance(
            item,
            dict,
        )
    ]


def _candidate_map(
    candidates: Any,
) -> Dict[str, Dict[str, Any]]:

    output: Dict[str, Dict[str, Any]] = {}

    if not isinstance(
        candidates,
        list,
    ):
        return output

    for candidate in candidates:

        if not isinstance(
            candidate,
            dict,
        ):
            continue

        incident_id = _text(
            candidate.get(
                "incident_id"
            )
        )

        if not incident_id:
            continue

        output[
            incident_id.lower()
        ] = candidate

    return output


def _build_timeline(
    incident: Dict[str, Any],
    candidate: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    events: List[Dict[str, Any]] = []

    incident_id = _text(
        incident.get(
            "incident_id"
        )
    )

    # SOC95 deterministic investigation timeline anchor
    _soc95_investigation_open_event = {
        "event_id": _deterministic_id(
            "EVT",
            f"{incident_id}:investigation_opened",
        ),
        "event_type": "INVESTIGATION_OPENED",
        "timestamp": None,
        "source": "investigation_management",
        "incident_id": incident_id,
        "confidence": _confidence(
            incident.get(
                "confidence",
                0.0,
            )
        ),
        "timestamp_status": "UNKNOWN",
    }

    events.append(
        _soc95_investigation_open_event
    )

    first_seen = (
        incident.get(
            "time_window",
            {}
        )
        if isinstance(
            incident.get(
                "time_window"
            ),
            dict,
        )
        else {}
    )

    first_dt = _parse_time(
        first_seen.get(
            "first_seen"
        )
    )

    last_dt = _parse_time(
        first_seen.get(
            "last_seen"
        )
    )

    if first_dt is not None:

        events.append(
            {
                "event_id": _deterministic_id(
                    "EVT",
                    f"{incident_id}:first:{first_dt.isoformat()}",
                ),
                "event_type": "INCIDENT_FIRST_SEEN",
                "timestamp": _iso(first_dt),
                "source": "incident_management",
                "incident_id": incident_id,
                "confidence": _confidence(
                    incident.get(
                        "confidence",
                        0.0,
                    )
                ),
            }
        )

    if last_dt is not None:

        events.append(
            {
                "event_id": _deterministic_id(
                    "EVT",
                    f"{incident_id}:last:{last_dt.isoformat()}",
                ),
                "event_type": "INCIDENT_LAST_SEEN",
                "timestamp": _iso(last_dt),
                "source": "incident_management",
                "incident_id": incident_id,
                "confidence": _confidence(
                    incident.get(
                        "confidence",
                        0.0,
                    )
                ),
            }
        )

    if candidate:

        reasons = _clean_values(
            candidate.get(
                "correlation_reasons"
            )
        )

        for position, reason in enumerate(
            reasons,
            start=1,
        ):

            event_time = (
                first_dt
                if position == 1
                else last_dt
            )

            events.append(
                {
                    "event_id": _deterministic_id(
                        "EVT",
                        f"{incident_id}:correlation:{reason}",
                    ),
                    "event_type": "CORRELATION_SIGNAL",
                    "timestamp": _iso(
                        event_time
                    ),
                    "source": "detection_correlation",
                    "incident_id": incident_id,
                    "signal": reason,
                    "confidence": _confidence(
                        candidate.get(
                            "confidence",
                            incident.get(
                                "confidence",
                                0.0,
                            ),
                        )
                    ),
                }
            )

    events.sort(
        key=lambda item: (
            item.get(
                "timestamp"
            ) is None,
            item.get(
                "timestamp"
            ) or "",
            item.get(
                "event_id"
            ),
        )
    )

    return events


def _build_evidence(
    incident: Dict[str, Any],
    candidate: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    incident_id = _text(
        incident.get(
            "incident_id"
        )
    )

    evidence: List[Dict[str, Any]] = []

    fields = [
        (
            "IOC",
            "iocs",
            "IOC_EVIDENCE",
        ),
        (
            "CAMPAIGN",
            "campaigns",
            "CAMPAIGN_EVIDENCE",
        ),
        (
            "ACTOR",
            "actors",
            "ACTOR_EVIDENCE",
        ),
        (
            "MALWARE",
            "malware",
            "MALWARE_EVIDENCE",
        ),
        (
            "MITRE",
            "mitre_techniques",
            "MITRE_EVIDENCE",
        ),
    ]

    for evidence_type, field, event_type in fields:

        values = _clean_values(
            incident.get(
                field
            )
        )

        if (
            not values
            and candidate
        ):
            values = _clean_values(
                candidate.get(
                    field
                )
            )

        for value in values:

            evidence.append(
                {
                    "evidence_id": _deterministic_id(
                        "EVD",
                        f"{incident_id}:{evidence_type}:{value}",
                    ),
                    "type": evidence_type,
                    "value": value,
                    "source": "incident_management",
                    "incident_id": incident_id,
                    "confidence": _confidence(
                        incident.get(
                            "confidence",
                            0.0,
                        )
                    ),
                    "status": "UNREVIEWED",
                    "pivot_available": True,
                }
            )

    evidence.sort(
        key=lambda item: (
            item.get(
                "type",
                ""
            ),
            item.get(
                "value",
                ""
            ),
        )
    )

    return evidence


def _build_findings(
    incident: Dict[str, Any],
    candidate: Optional[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    findings: List[Dict[str, Any]] = []

    severity = _severity(
        incident
    )

    priority = _priority(
        incident
    )

    reasons = []

    if candidate:
        reasons = _clean_values(
            candidate.get(
                "correlation_reasons"
            )
        )

    if reasons:

        findings.append(
            {
                "finding_id": _deterministic_id(
                    "FND",
                    f"{incident.get('incident_id')}:" +
                    ":".join(reasons),
                ),
                "type": "CORRELATION",
                "title": "Correlated multi-signal activity",
                "status": "OPEN",
                "confidence": _confidence(
                    incident.get(
                        "confidence",
                        0.0,
                    )
                ),
                "evidence_count": len(
                    evidence
                ),
                "summary": (
                    "The incident is supported by "
                    + ", ".join(
                        reasons
                    )
                    + "."
                ),
            }
        )

    findings.append(
        {
            "finding_id": _deterministic_id(
                "FND",
                f"{incident.get('incident_id')}:severity:{severity}:priority:{priority}",
            ),
            "type": "RISK",
            "title": f"{severity} severity {priority} priority assessment",
            "status": "OPEN",
            "confidence": _confidence(
                incident.get(
                    "confidence",
                    0.0,
                )
            ),
            "evidence_count": len(
                evidence
            ),
            "summary": (
                f"Incident risk is classified as "
                f"{severity} with {priority} priority."
            ),
        }
    )

    return findings


def _build_pivots(
    incident: Dict[str, Any],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    pivots: List[Dict[str, Any]] = []

    for item in evidence:

        value = item.get(
            "value"
        )

        evidence_type = item.get(
            "type"
        )

        if not value:
            continue

        pivot_kind = {
            "IOC": "IOC",
            "CAMPAIGN": "CAMPAIGN",
            "ACTOR": "ACTOR",
            "MALWARE": "MALWARE",
            "MITRE": "MITRE",
        }.get(
            evidence_type,
            evidence_type,
        )

        pivots.append(
            {
                "pivot_id": _deterministic_id(
                    "PIV",
                    f"{incident.get('incident_id')}:{pivot_kind}:{value}",
                ),
                "pivot_type": pivot_kind,
                "value": value,
                "state": "AVAILABLE",
                "source_evidence_id": item.get(
                    "evidence_id"
                ),
            }
        )

    return pivots


def _investigation_id(
    incident: Dict[str, Any],
) -> str:

    source = (
        _text(
            incident.get(
                "incident_id"
            )
        )
        or (
            _text(
                incident.get(
                    "source_incident_id"
                )
            )
        )
    )

    return _deterministic_id(
        "INV",
        source,
    )


def investigate_incidents(
    incident_management: Any,
    detection_correlation: Optional[Dict[str, Any]] = None,
    existing_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build deterministic, side-effect-free investigations from Incident
    Management output.

    No persistence is performed by this layer.
    """

    incidents = _incident_list(
        incident_management
    )

    candidates = {}

    if isinstance(
        detection_correlation,
        dict,
    ):
        candidates = _candidate_map(
            detection_correlation.get(
                "incident_candidates",
                [],
            )
        )

    investigations: List[Dict[str, Any]] = []

    existing = (
        existing_status
        if isinstance(
            existing_status,
            dict,
        )
        else {}
    )

    existing_map = (
        existing.get(
            "investigations",
            {}
        )
        if isinstance(
            existing.get(
                "investigations",
                {}
            ),
            dict,
        )
        else {}
    )

    for incident in incidents:

        incident_id = _text(
            incident.get(
                "incident_id"
            )
        )

        if not incident_id:
            continue

        candidate = candidates.get(
            incident_id.lower()
        )

        evidence = _build_evidence(
            incident,
            candidate,
        )

        timeline = _build_timeline(
            incident,
            candidate,
        )

        pivots = _build_pivots(
            incident,
            evidence,
        )

        findings = _build_findings(
            incident,
            candidate,
            evidence,
        )

        source_state = existing_map.get(
            incident_id,
            {}
        )

        if not isinstance(
            source_state,
            dict,
        ):
            source_state = {}

        status = _text(
            source_state.get(
                "status",
                "NEW",
            )
        ).upper()

        if status not in INVESTIGATION_STATUSES:
            status = "NEW"

        investigation = {
            "investigation_id":
                _investigation_id(
                    incident
                ),
            "incident_id":
                incident_id,
            "status":
                status,
            "priority":
                _priority(
                    incident
                ),
            "severity":
                _severity(
                    incident
                ),
            "incident_score":
                _clamp(
                    incident.get(
                        "incident_score",
                        0.0,
                    )
                ),
            "confidence":
                _confidence(
                    incident.get(
                        "confidence",
                        0.0,
                    )
                ),
            "alert_ids":
                _clean_values(
                    incident.get(
                        "alert_ids"
                    )
                ),
            "evidence":
                evidence,
            "evidence_count":
                len(evidence),
            "pivots":
                pivots,
            "pivot_count":
                len(pivots),
            "timeline":
                timeline,
            "timeline_event_count":
                len(timeline),
            "findings":
                findings,
            "finding_count":
                len(findings),
            "analyst_state": {
                "assigned_to":
                    source_state.get(
                        "assigned_to",
                        incident.get(
                            "analyst_state",
                            {}
                        ).get(
                            "assigned_to"
                        )
                        if isinstance(
                            incident.get(
                                "analyst_state"
                            ),
                            dict,
                        )
                        else None,
                    ),
                "decision":
                    source_state.get(
                        "decision",
                        "UNDECIDED",
                    ),
                "notes_required":
                    bool(
                        source_state.get(
                            "notes_required",
                            False,
                        )
                    ),
            },
            "lifecycle": {
                "current":
                    status,
                "reopen_supported":
                    True,
                "terminal_statuses":
                    list(
                        TERMINAL_STATUSES
                    ),
            },
            "capabilities": {
                "evidence_review":
                    True,
                "ioc_pivot":
                    any(
                        item.get(
                            "pivot_type"
                        ) == "IOC"
                        for item in pivots
                    ),
                "campaign_pivot":
                    any(
                        item.get(
                            "pivot_type"
                        ) == "CAMPAIGN"
                        for item in pivots
                    ),
                "actor_pivot":
                    any(
                        item.get(
                            "pivot_type"
                        ) == "ACTOR"
                        for item in pivots
                    ),
                "malware_pivot":
                    any(
                        item.get(
                            "pivot_type"
                        ) == "MALWARE"
                        for item in pivots
                    ),
                "mitre_pivot":
                    any(
                        item.get(
                            "pivot_type"
                        ) == "MITRE"
                        for item in pivots
                    ),
                "timeline_analysis":
                    bool(
                        timeline
                    ),
                "finding_management":
                    True,
                "persistence":
                    False,
            },
        }

        investigations.append(
            investigation
        )

    investigations.sort(
        key=lambda item: (
            PRIORITY_ORDER.get(
                item.get(
                    "priority"
                ),
                99,
            ),
            -float(
                item.get(
                    "incident_score",
                    0.0,
                )
            ),
            item.get(
                "investigation_id",
                "",
            ),
        )
    )

    status = (
        "INVESTIGATIONS_CREATED"
        if investigations
        else "NO_INVESTIGATIONS"
    )

    severity_distribution: Dict[str, int] = {}

    for investigation in investigations:

        key = investigation.get(
            "severity",
            "INFO",
        )

        severity_distribution[key] = (
            severity_distribution.get(
                key,
                0,
            )
            + 1
        )

    return {
        "engine":
            ENGINE_NAME,
        "version":
            ENGINE_VERSION,
        "status":
            status,
        "incident_count":
            len(incidents),
        "investigation_count":
            len(investigations),
        "investigation_ids": [
            item.get(
                "investigation_id"
            )
            for item in investigations
        ],
        "severity_distribution":
            dict(
                sorted(
                    severity_distribution.items()
                )
            ),
        "investigations":
            investigations,
        "deterministic":
            True,
        "persistence":
            False,
    }


def manage_investigations(
    incident_management: Any,
    detection_correlation: Optional[Dict[str, Any]] = None,
    existing_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    return investigate_incidents(
        incident_management=incident_management,
        detection_correlation=detection_correlation,
        existing_status=existing_status,
    )


__all__ = [
    "investigate_incidents",
    "manage_investigations",
]