"""
SOC 9.5 Case Management V1

Side-effect-free case workflow layer.

Pipeline:

Detection Correlation
    ->
Incident Management
    ->
Investigation Management
    ->
Case Management
    ->
Analyst Decision
    ->
Response / Audit

Persistence is intentionally disabled in V1.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional


ENGINE_NAME = "soc95-case-management"
ENGINE_VERSION = "1.0"

STATUS_NEW = "NEW"
STATUS_TRIAGED = "TRIAGED"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_PENDING_DECISION = "PENDING_DECISION"
STATUS_RESPONSE = "RESPONSE"
STATUS_RESOLVED = "RESOLVED"
STATUS_CLOSED = "CLOSED"

TERMINAL_STATUSES = {
    STATUS_CLOSED,
}

PRIORITY_ORDER = {
    "P1": 5,
    "P2": 4,
    "P3": 3,
    "P4": 2,
    "P5": 1,
}

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


def _text(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _clamp(
    value: Any,
    low: float,
    high: float,
) -> float:

    try:
        numeric = float(value)
    except (
        TypeError,
        ValueError,
    ):
        numeric = low

    return max(
        low,
        min(
            high,
            numeric,
        ),
    )


def _clean_values(
    values: Any,
) -> List[str]:

    if values is None:
        return []

    if isinstance(
        values,
        (
            str,
            int,
            float,
        ),
    ):
        values = [values]

    if not isinstance(
        values,
        (list, tuple, set),
    ):
        return []

    cleaned = []

    for value in values:
        text = _text(value)

        if not text:
            continue

        if text not in cleaned:
            cleaned.append(text)

    return sorted(
        cleaned,
        key=lambda item: item.lower(),
    )


def _safe_dict(
    value: Any,
) -> Dict[str, Any]:

    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def _now_iso() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


def _deterministic_id(
    prefix: str,
    value: Any,
) -> str:

    if isinstance(
        value,
        (
            dict,
            list,
        ),
    ):
        canonical = json.dumps(
            value,
            sort_keys=True,
            default=str,
        )
    else:
        canonical = _text(value)

    digest = hashlib.sha256(
        canonical.encode(
            "utf-8"
        )
    ).hexdigest()[:16].upper()

    return (
        f"{prefix}-{digest}"
    )


def _severity(
    value: Any,
) -> str:

    normalized = _lower(
        value
    ).upper()

    if normalized in SEVERITY_ORDER:
        return normalized

    return "UNKNOWN"


def _priority(
    value: Any,
) -> str:

    normalized = _lower(
        value
    ).upper()

    if normalized in PRIORITY_ORDER:
        return normalized

    return "P5"


def _highest_severity(
    values: Iterable[Any],
) -> str:

    candidates = [
        _severity(value)
        for value in values
    ]

    if not candidates:
        return "UNKNOWN"

    return max(
        candidates,
        key=lambda item:
            SEVERITY_ORDER.get(
                item,
                0,
            ),
    )


def _highest_priority(
    values: Iterable[Any],
) -> str:

    candidates = [
        _priority(value)
        for value in values
    ]

    if not candidates:
        return "P5"

    return max(
        candidates,
        key=lambda item:
            PRIORITY_ORDER.get(
                item,
                1,
            ),
    )


def _incident_list(
    incident_management: Any,
) -> List[Dict[str, Any]]:

    payload = _safe_dict(
        incident_management
    )

    incidents = payload.get(
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


def _investigation_list(
    investigation_management: Any,
) -> List[Dict[str, Any]]:

    payload = _safe_dict(
        investigation_management
    )

    investigations = payload.get(
        "investigations",
        [],
    )

    if not isinstance(
        investigations,
        list,
    ):
        return []

    return [
        item
        for item in investigations
        if isinstance(
            item,
            dict,
        )
    ]


def _candidate_case_pairs(
    incident_management: Any,
    investigation_management: Any,
) -> List[Dict[str, Any]]:

    incidents = _incident_list(
        incident_management
    )

    investigations = _investigation_list(
        investigation_management
    )

    investigation_by_incident = {}

    for investigation in investigations:

        incident_id = _text(
            investigation.get(
                "incident_id"
            )
        )

        if not incident_id:
            continue

        investigation_by_incident[
            incident_id
        ] = investigation

    pairs = []

    for incident in incidents:

        incident_id = _text(
            incident.get(
                "incident_id"
            )
        )

        if not incident_id:
            continue

        investigation = (
            investigation_by_incident.get(
                incident_id
            )
        )

        pairs.append(
            {
                "incident": incident,
                "investigation":
                    investigation or {},
            }
        )

    return pairs


def _analyst_state(
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
) -> Dict[str, Any]:

    incident_state = _safe_dict(
        incident.get(
            "analyst_state"
        )
    )

    investigation_state = _safe_dict(
        investigation.get(
            "analyst_state"
        )
    )

    assigned_to = (
        _text(
            incident_state.get(
                "assigned_to"
            )
        )
        or _text(
            investigation_state.get(
                "assigned_to"
            )
        )
    )

    decision = (
        _text(
            investigation_state.get(
                "decision"
            )
        )
        or _text(
            incident_state.get(
                "decision"
            )
        )
    )

    disposition = (
        _text(
            investigation_state.get(
                "disposition"
            )
        )
        or _text(
            incident_state.get(
                "disposition"
            )
        )
    )

    notes_required = bool(
        investigation_state.get(
            "notes_required",
            False,
        )
        or incident_state.get(
            "notes_required",
            False,
        )
    )

    return {
        "assigned_to": assigned_to,
        "decision": decision,
        "disposition": disposition,
        "notes_required": notes_required,
        "case_decision": "",
        "case_disposition": "",
        "case_notes": "",
    }


def _collect_context(
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
) -> Dict[str, List[str]]:

    result = {
        "alert_ids": [],
        "iocs": [],
        "campaigns": [],
        "actors": [],
        "malware": [],
        "mitre_techniques": [],
    }

    sources = [
        incident,
        investigation,
    ]

    field_aliases = {
        "alert_ids": [
            "alert_ids",
        ],
        "iocs": [
            "iocs",
        ],
        "campaigns": [
            "campaigns",
        ],
        "actors": [
            "actors",
        ],
        "malware": [
            "malware",
        ],
        "mitre_techniques": [
            "mitre_techniques",
        ],
    }

    for output_key, aliases in field_aliases.items():

        values = []

        for source in sources:

            for alias in aliases:

                values.extend(
                    _clean_values(
                        source.get(
                            alias
                        )
                    )
                )

        result[output_key] = _clean_values(
            values
        )

    return result


def _collect_nested_context(
    investigation: Dict[str, Any],
    context: Dict[str, List[str]],
) -> Dict[str, List[str]]:

    evidence = investigation.get(
        "evidence",
        [],
    )

    pivots = investigation.get(
        "pivots",
        [],
    )

    for collection in [
        evidence,
        pivots,
    ]:

        if not isinstance(
            collection,
            list,
        ):
            continue

        for item in collection:

            if not isinstance(
                item,
                dict,
            ):
                continue

            item_type = _lower(
                item.get(
                    "type"
                )
            )

            value = _text(
                item.get(
                    "value"
                )
            )

            if not value:
                continue

            if item_type == "ioc":
                context["iocs"].append(
                    value
                )

            elif item_type == "campaign":
                context["campaigns"].append(
                    value
                )

            elif item_type == "actor":
                context["actors"].append(
                    value
                )

            elif item_type == "malware":
                context["malware"].append(
                    value
                )

            elif item_type == "mitre":
                context[
                    "mitre_techniques"
                ].append(
                    value
                )

    for key in list(
        context.keys()
    ):
        context[key] = _clean_values(
            context[key]
        )

    return context


def _build_timeline_summary(
    investigation: Dict[str, Any],
) -> Dict[str, Any]:

    timeline = investigation.get(
        "timeline",
        [],
    )

    if not isinstance(
        timeline,
        list,
    ):
        timeline = []

    known = 0
    unknown = 0

    for event in timeline:

        if not isinstance(
            event,
            dict,
        ):
            continue

        if event.get(
            "timestamp"
        ) is None:

            unknown += 1

        else:
            known += 1

    return {
        "event_count": len(
            timeline
        ),
        "known_timestamp_events":
            known,
        "unknown_timestamp_events":
            unknown,
    }


def _build_case_findings(
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
    context: Dict[str, List[str]],
) -> List[Dict[str, Any]]:

    findings = []

    existing = investigation.get(
        "findings",
        [],
    )

    if isinstance(
        existing,
        list,
    ):

        for item in existing:

            if isinstance(
                item,
                dict,
            ):
                findings.append(
                    dict(item)
                )

    if not findings:

        severity = _severity(
            incident.get(
                "severity"
            )
        )

        if severity in {
            "CRITICAL",
            "HIGH",
        }:

            findings.append(
                {
                    "finding_id":
                        _deterministic_id(
                            "FND",
                            (
                                incident.get(
                                    "incident_id"
                                ),
                                severity,
                                context,
                            ),
                        ),
                    "type":
                        "THREAT_ASSESSMENT",
                    "severity":
                        severity,
                    "statement":
                        "Correlated threat activity "
                        "requires analyst disposition.",
                    "confidence":
                        _clamp(
                            investigation.get(
                                "confidence",
                                incident.get(
                                    "confidence",
                                    0.0,
                                ),
                            ),
                            0.0,
                            1.0,
                        ),
                }
            )

    return findings


def _build_audit(
    case_id: str,
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
) -> List[Dict[str, Any]]:

    audit = []

    audit.append(
        {
            "event_id":
                _deterministic_id(
                    "AUD",
                    f"{case_id}:created",
                ),
            "event_type":
                "CASE_CREATED",
            "case_id":
                case_id,
            "timestamp":
                None,
            "timestamp_status":
                "UNKNOWN",
            "source":
                "case_management",
        }
    )

    incident_id = _text(
        incident.get(
            "incident_id"
        )
    )

    investigation_id = _text(
        investigation.get(
            "investigation_id"
        )
    )

    if incident_id:
        audit.append(
            {
                "event_id":
                    _deterministic_id(
                        "AUD",
                        (
                            f"{case_id}:"
                            f"incident:{incident_id}"
                        ),
                    ),
                "event_type":
                    "INCIDENT_LINKED",
                "case_id":
                    case_id,
                "incident_id":
                    incident_id,
                "timestamp":
                    None,
                "timestamp_status":
                    "UNKNOWN",
                "source":
                    "case_management",
            }
        )

    if investigation_id:
        audit.append(
            {
                "event_id":
                    _deterministic_id(
                        "AUD",
                        (
                            f"{case_id}:"
                            f"investigation:{investigation_id}"
                        ),
                    ),
                "event_type":
                    "INVESTIGATION_LINKED",
                "case_id":
                    case_id,
                "investigation_id":
                    investigation_id,
                "timestamp":
                    None,
                "timestamp_status":
                    "UNKNOWN",
                "source":
                    "case_management",
            }
        )

    return audit


def _build_lifecycle(
    case_id: str,
) -> Dict[str, Any]:

    return {
        "state": STATUS_NEW,
        "previous_state": None,
        "reopen_supported": True,
        "terminal": False,
        "transitions": [
            {
                "transition_id":
                    _deterministic_id(
                        "TRN",
                        f"{case_id}:created",
                    ),
                "from": None,
                "to": STATUS_NEW,
                "timestamp": None,
                "timestamp_status": "UNKNOWN",
            }
        ],
    }


def _build_case(
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
) -> Dict[str, Any]:

    incident_id = _text(
        incident.get(
            "incident_id"
        )
    )

    investigation_id = _text(
        investigation.get(
            "investigation_id"
        )
    )

    case_id = _deterministic_id(
        "CASE",
        (
            incident_id,
            investigation_id,
        ),
    )

    context = _collect_context(
        incident,
        investigation,
    )

    context = _collect_nested_context(
        investigation,
        context,
    )

    incident_severity = _severity(
        incident.get(
            "severity"
        )
    )

    investigation_severity = _severity(
        investigation.get(
            "severity"
        )
    )

    severity = _highest_severity(
        [
            incident_severity,
            investigation_severity,
        ]
    )

    priority = _highest_priority(
        [
            incident.get(
                "priority"
            ),
            investigation.get(
                "priority"
            ),
        ]
    )

    incident_score = _clamp(
        investigation.get(
            "incident_score",
            incident.get(
                "incident_score",
                incident.get(
                    "score",
                    0.0,
                ),
            ),
        ),
        0.0,
        100.0,
    )

    confidence = _clamp(
        investigation.get(
            "confidence",
            incident.get(
                "confidence",
                0.0,
            ),
        ),
        0.0,
        1.0,
    )

    findings = _build_case_findings(
        incident,
        investigation,
        context,
    )

    timeline_summary = (
        _build_timeline_summary(
            investigation
        )
    )

    analyst_state = _analyst_state(
        incident,
        investigation,
    )

    lifecycle = _build_lifecycle(
        case_id
    )

    audit = _build_audit(
        case_id,
        incident,
        investigation,
    )

    initial_status = STATUS_NEW

    if priority in {
        "P1",
        "P2",
    }:
        initial_status = STATUS_TRIAGED

    return {
        "case_id":
            case_id,

        "incident_id":
            incident_id,

        "investigation_id":
            investigation_id,

        "status":
            initial_status,

        "priority":
            priority,

        "severity":
            severity,

        "incident_score":
            incident_score,

        "confidence":
            confidence,

        "alert_ids":
            context["alert_ids"],

        "iocs":
            context["iocs"],

        "campaigns":
            context["campaigns"],

        "actors":
            context["actors"],

        "malware":
            context["malware"],

        "mitre_techniques":
            context["mitre_techniques"],

        "evidence":
            list(
                investigation.get(
                    "evidence",
                    [],
                )
                if isinstance(
                    investigation.get(
                        "evidence",
                        [],
                    ),
                    list,
                )
                else []
            ),

        "pivots":
            list(
                investigation.get(
                    "pivots",
                    [],
                )
                if isinstance(
                    investigation.get(
                        "pivots",
                        [],
                    ),
                    list,
                )
                else []
            ),

        "findings":
            findings,

        "finding_count":
            len(findings),

        "timeline":
            list(
                investigation.get(
                    "timeline",
                    [],
                )
                if isinstance(
                    investigation.get(
                        "timeline",
                        [],
                    ),
                    list,
                )
                else []
            ),

        "timeline_summary":
            timeline_summary,

        "analyst_state":
            analyst_state,

        "lifecycle":
            lifecycle,

        "audit":
            audit,

        "response_state":
            {
                "status":
                    "NOT_STARTED",
                "actions":
                    [],
                "containment":
                    "NOT_STARTED",
                "eradication":
                    "NOT_STARTED",
                "recovery":
                    "NOT_STARTED",
            },

        "capabilities":
            {
                "analyst_decision":
                    True,
                "response_tracking":
                    True,
                "audit_trail":
                    True,
                "reopen":
                    True,
                "persistence":
                    False,
            },
    }


def create_cases(
    incident_management: Any,
    investigation_management: Any,
    existing_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create deterministic cases from Incident + Investigation outputs.

    No DB writes.
    No source-object mutation.
    """

    pairs = _candidate_case_pairs(
        incident_management,
        investigation_management,
    )

    existing_status = (
        existing_status
        if isinstance(
            existing_status,
            dict,
        )
        else {}
    )

    cases = []

    for pair in pairs:

        incident = pair[
            "incident"
        ]

        investigation = pair[
            "investigation"
        ]

        cases.append(
            _build_case(
                incident,
                investigation,
            )
        )

    cases.sort(
        key=lambda item:
            item.get(
                "case_id",
                "",
            )
    )

    case_ids = [
        item.get(
            "case_id"
        )
        for item in cases
    ]

    status = (
        "CASES_CREATED"
        if cases
        else "NO_CASES"
    )

    severity_distribution = {}

    for case in cases:

        severity = case.get(
            "severity",
            "UNKNOWN",
        )

        severity_distribution[
            severity
        ] = (
            severity_distribution.get(
                severity,
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

        "case_count":
            len(cases),

        "case_ids":
            case_ids,

        "severity_distribution":
            dict(
                sorted(
                    severity_distribution.items()
                )
            ),

        "cases":
            cases,

        "deterministic":
            True,

        "persistence":
            False,

        "existing_status_used":
            bool(existing_status),
    }


def manage_cases(
    incident_management: Any,
    investigation_management: Any,
    existing_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Alias for create_cases().
    """

    return create_cases(
        incident_management=incident_management,
        investigation_management=investigation_management,
        existing_status=existing_status,
    )