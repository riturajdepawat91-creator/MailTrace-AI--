from __future__ import annotations

from typing import Any, Dict, List, Optional
import hashlib


ENGINE_NAME = "soc95-response-management"
ENGINE_VERSION = "1.0"


STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_PLANNED = "PLANNED"
STATUS_PENDING_APPROVAL = "PENDING_APPROVAL"
STATUS_APPROVED = "APPROVED"
STATUS_EXECUTING = "EXECUTING"
STATUS_CONTAINED = "CONTAINED"
STATUS_REMEDIATED = "REMEDIATED"
STATUS_RECOVERY = "RECOVERY"
STATUS_VERIFIED = "VERIFIED"
STATUS_CLOSED = "CLOSED"


SEVERITY_ORDER = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


PRIORITY_ORDER = {
    "P5": 1,
    "P4": 2,
    "P3": 3,
    "P2": 4,
    "P1": 5,
}


RESPONSE_ACTIONS = {
    "CONTAIN",
    "BLOCK_IOC",
    "QUARANTINE_ATTACHMENT",
    "DISABLE_ACCOUNT",
    "RESET_CREDENTIAL",
    "ISOLATE_ENDPOINT",
    "REMOVE_ARTIFACT",
    "ERADICATE",
    "RECOVER",
    "VERIFY",
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
        number = float(value)
    except (TypeError, ValueError):
        number = low

    return max(
        low,
        min(
            high,
            number,
        ),
    )


def _safe_dict(
    value: Any,
) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _clean_values(
    value: Any,
) -> List[str]:

    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set),
    ):
        values = value
    else:
        values = [value]

    result = set()

    for item in values:

        if isinstance(item, dict):
            item = (
                item.get("value")
                or item.get("id")
                or item.get("name")
            )

        normalized = _lower(item)

        if normalized:
            result.add(normalized)

    return sorted(result)


def _cases(
    case_management: Any,
) -> List[Dict[str, Any]]:

    data = _safe_dict(
        case_management
    )

    values = data.get(
        "cases",
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return []

    return [
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ]


def _incidents(
    incident_management: Any,
) -> List[Dict[str, Any]]:

    data = _safe_dict(
        incident_management
    )

    values = data.get(
        "incidents",
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return []

    return [
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ]


def _investigations(
    investigation_management: Any,
) -> List[Dict[str, Any]]:

    data = _safe_dict(
        investigation_management
    )

    values = data.get(
        "investigations",
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return []

    return [
        item
        for item in values
        if isinstance(
            item,
            dict,
        )
    ]


def _severity(
    value: Any,
) -> str:

    value = _text(
        value
    ).upper()

    if value not in SEVERITY_ORDER:
        return "INFO"

    return value


def _priority(
    value: Any,
) -> str:

    value = _text(
        value
    ).upper()

    if value not in PRIORITY_ORDER:
        return "P5"

    return value


def _highest_severity(
    values: List[Any],
) -> str:

    normalized = [
        _severity(value)
        for value in values
    ]

    return max(
        normalized,
        key=lambda item:
            SEVERITY_ORDER[item],
        default="INFO",
    )


def _highest_priority(
    values: List[Any],
) -> str:

    normalized = [
        _priority(value)
        for value in values
    ]

    return max(
        normalized,
        key=lambda item:
            PRIORITY_ORDER[item],
        default="P5",
    )


def _deterministic_id(
    prefix: str,
    *parts: Any,
) -> str:

    material = "|".join(
        _text(part)
        for part in parts
    )

    digest = hashlib.sha256(
        material.encode(
            "utf-8"
        )
    ).hexdigest()[:16].upper()

    return f"{prefix}-{digest}"


def _action_risk(
    action_type: str,
) -> str:

    if action_type in {
        "ISOLATE_ENDPOINT",
        "DISABLE_ACCOUNT",
        "RESET_CREDENTIAL",
    }:
        return "CRITICAL"

    if action_type in {
        "QUARANTINE_ATTACHMENT",
        "REMOVE_ARTIFACT",
        "ERADICATE",
    }:
        return "HIGH"

    if action_type in {
        "BLOCK_IOC",
        "CONTAIN",
        "RECOVER",
    }:
        return "MEDIUM"

    return "LOW"


def _recommended_action_types(
    case: Dict[str, Any],
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
) -> List[str]:

    severity = _highest_severity(
        [
            case.get("severity"),
            incident.get("severity"),
            investigation.get("severity"),
        ]
    )

    iocs = _clean_values(
        case.get(
            "iocs",
            incident.get(
                "iocs",
                [],
            ),
        )
    )

    malware = _clean_values(
        case.get(
            "malware",
            incident.get(
                "malware",
                [],
            ),
        )
    )

    actions = set()

    if severity in {
        "HIGH",
        "CRITICAL",
    }:
        actions.add(
            "CONTAIN"
        )

    if iocs:
        actions.add(
            "BLOCK_IOC"
        )

    if malware:
        actions.add(
            "QUARANTINE_ATTACHMENT"
        )

    if severity == "CRITICAL":
        actions.add(
            "ISOLATE_ENDPOINT"
        )

    if malware:
        actions.add(
            "ERADICATE"
        )

    actions.add(
        "VERIFY"
    )

    return sorted(
        action
        for action in actions
        if action in RESPONSE_ACTIONS
    )


def _build_action(
    action_type: str,
    response_id: str,
    case: Dict[str, Any],
    incident: Dict[str, Any],
    confidence: float,
) -> Dict[str, Any]:

    action_id = _deterministic_id(
        "ACT",
        response_id,
        action_type,
    )

    return {
        "action_id": action_id,
        "action_type": action_type,
        "status": "RECOMMENDED",
        "approval_status": "PENDING",
        "execution_status": "NOT_EXECUTED",
        "risk": _action_risk(
            action_type
        ),
        "confidence": _clamp(
            confidence,
            0.0,
            1.0,
        ),
        "case_id": _text(
            case.get("case_id")
        ),
        "incident_id": _text(
            incident.get("incident_id")
        ),
        "reversible": action_type not in {
            "ERADICATE",
            "DISABLE_ACCOUNT",
            "REMOVE_ARTIFACT",
        },
        "execution_side_effect": False,
    }


def _build_response(
    case: Dict[str, Any],
    incident: Dict[str, Any],
    investigation: Dict[str, Any],
    existing_status: Optional[Dict[str, Any]],
) -> Dict[str, Any]:

    case_id = _text(
        case.get("case_id")
    )

    incident_id = _text(
        incident.get("incident_id")
    )

    investigation_id = _text(
        investigation.get("investigation_id")
    )

    severity = _highest_severity(
        [
            case.get("severity"),
            incident.get("severity"),
            investigation.get("severity"),
        ]
    )

    priority = _highest_priority(
        [
            case.get("priority"),
            incident.get("priority"),
            investigation.get("priority"),
        ]
    )

    score = _clamp(
        investigation.get(
            "incident_score",
            incident.get(
                "incident_score",
                case.get(
                    "incident_score",
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
                case.get(
                    "confidence",
                    0.0,
                ),
            ),
        ),
        0.0,
        1.0,
    )

    response_id = _deterministic_id(
        "RSP",
        case_id,
        incident_id,
        investigation_id,
    )

    action_types = _recommended_action_types(
        case,
        incident,
        investigation,
    )

    actions = [
        _build_action(
            action_type,
            response_id,
            case,
            incident,
            confidence,
        )
        for action_type in action_types
    ]

    existing = _safe_dict(
        existing_status
    )

    status = _text(
        existing.get("status")
    ).upper()

    valid_statuses = {
        STATUS_NOT_STARTED,
        STATUS_PLANNED,
        STATUS_PENDING_APPROVAL,
        STATUS_APPROVED,
        STATUS_EXECUTING,
        STATUS_CONTAINED,
        STATUS_REMEDIATED,
        STATUS_RECOVERY,
        STATUS_VERIFIED,
        STATUS_CLOSED,
    }

    if status not in valid_statuses:
        status = (
            STATUS_PLANNED
            if actions
            else STATUS_NOT_STARTED
        )

    approval_state = _text(
        existing.get(
            "approval_state"
        )
    ).upper()

    if approval_state not in {
        "NOT_REQUIRED",
        "PENDING",
        "APPROVED",
        "REJECTED",
    }:
        approval_state = (
            "PENDING"
            if actions
            else "NOT_REQUIRED"
        )

    return {
        "response_id": response_id,
        "case_id": case_id,
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "status": status,
        "severity": severity,
        "priority": priority,
        "incident_score": score,
        "confidence": confidence,
        "alert_ids": _clean_values(
            case.get(
                "alert_ids",
                incident.get(
                    "alert_ids",
                    [],
                ),
            )
        ),
        "iocs": _clean_values(
            case.get(
                "iocs",
                incident.get(
                    "iocs",
                    [],
                ),
            )
        ),
        "campaigns": _clean_values(
            case.get(
                "campaigns",
                incident.get(
                    "campaigns",
                    [],
                ),
            )
        ),
        "actors": _clean_values(
            case.get(
                "actors",
                incident.get(
                    "actors",
                    [],
                ),
            )
        ),
        "malware": _clean_values(
            case.get(
                "malware",
                incident.get(
                    "malware",
                    [],
                ),
            )
        ),
        "mitre_techniques": _clean_values(
            case.get(
                "mitre_techniques",
                incident.get(
                    "mitre_techniques",
                    [],
                ),
            )
        ),
        "recommended_actions": actions,
        "response_state": {
            "status": status,
            "approval_state": approval_state,
            "containment": "NOT_STARTED",
            "eradication": "NOT_STARTED",
            "recovery": "NOT_STARTED",
            "verification": "NOT_STARTED",
        },
        "analyst_state": {
            "decision": "UNDECIDED",
            "approval_required": bool(
                actions
            ),
            "approved_by": "",
            "rejected_by": "",
            "notes_required": False,
        },
        "lifecycle": [
            {
                "transition_id": _deterministic_id(
                    "TRN",
                    response_id,
                    "created",
                ),
                "from": None,
                "to": status,
                "timestamp": None,
                "timestamp_status": "UNKNOWN",
            }
        ],
        "audit": [
            {
                "event_id": _deterministic_id(
                    "AUD",
                    response_id,
                    "created",
                ),
                "event_type": "RESPONSE_CREATED",
                "response_id": response_id,
                "case_id": case_id,
                "incident_id": incident_id,
                "timestamp": None,
                "timestamp_status": "UNKNOWN",
                "source": "response_management",
            },
            {
                "event_id": _deterministic_id(
                    "AUD",
                    response_id,
                    "planned",
                ),
                "event_type": "RESPONSE_PLAN_CREATED",
                "response_id": response_id,
                "action_count": len(actions),
                "timestamp": None,
                "timestamp_status": "UNKNOWN",
                "source": "response_management",
            },
        ],
        "capabilities": {
            "plan_actions": True,
            "approval_tracking": True,
            "execution_tracking": True,
            "containment_tracking": True,
            "eradication_tracking": True,
            "recovery_tracking": True,
            "verification_tracking": True,
            "rollback_tracking": True,
            "persistence": False,
            "execution_side_effect": False,
        },
        "persistence": False,
    }


def manage_response(
    case_management: Any,
    incident_management: Any = None,
    investigation_management: Any = None,
    existing_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    cases = _cases(
        case_management
    )

    incidents = _incidents(
        incident_management
    )

    investigations = _investigations(
        investigation_management
    )

    if not cases:
        return {
            "engine": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "status": "NO_CASES",
            "response_count": 0,
            "response_ids": [],
            "responses": [],
            "deterministic": True,
            "persistence": False,
        }

    incident_map = {
        _lower(
            item.get("incident_id")
        ): item
        for item in incidents
    }

    investigation_map = {
        _lower(
            item.get("investigation_id")
        ): item
        for item in investigations
    }

    responses = []

    for case in cases:

        incident = incident_map.get(
            _lower(
                case.get("incident_id")
            ),
            {},
        )

        investigation = investigation_map.get(
            _lower(
                case.get("investigation_id")
            ),
            {},
        )

        responses.append(
            _build_response(
                case,
                incident,
                investigation,
                existing_status,
            )
        )

    responses.sort(
        key=lambda item: (
            -PRIORITY_ORDER.get(
                item["priority"],
                1,
            ),
            -SEVERITY_ORDER.get(
                item["severity"],
                1,
            ),
            item["response_id"],
        )
    )

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "status": (
            "RESPONSES_CREATED"
            if responses
            else "NO_RESPONSES"
        ),
        "response_count": len(
            responses
        ),
        "response_ids": [
            item["response_id"]
            for item in responses
        ],
        "responses": responses,
        "deterministic": True,
        "persistence": False,
    }