
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Iterable, List, Tuple


ENGINE_NAME = "soc95-detection-correlation"
ENGINE_VERSION = "v1"

MAX_RELATIONSHIPS = 5000
MAX_INCIDENTS = 1000

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_BY_RANK = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clamp(
    value: float,
    low: float,
    high: float,
) -> float:
    return round(
        max(
            low,
            min(
                high,
                value,
            )
        ),
        3,
    )


def _normalize_token(value: Any) -> str:
    return re.sub(
        r"\s+",
        " ",
        _safe_str(value).casefold(),
    ).strip()


def _normalize_ioc(value: Any) -> str:
    return _normalize_token(value).rstrip(".")



def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set)
    ):
        return list(value)

    return [value]


def _parse_timestamp(value: Any):
    if value is None:
        return None

    raw = _safe_str(value)

    if not raw:
        return None

    candidates = [
        raw,
        raw.replace(
            "Z",
            "+00:00"
        ),
    ]

    for candidate in candidates:

        try:
            parsed = datetime.fromisoformat(
                candidate
            )
        except Exception:
            continue

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    return None


def _alert_key(alert: Dict[str, Any]) -> str:
    raw = (
        alert.get("alert_id")
        or alert.get("id")
        or alert.get("detection_id")
        or alert.get("indicator")
        or alert.get("ioc")
        or alert.get("value")
        or ""
    )

    return _normalize_token(
        raw
    )


def _extract_iocs(alert: Dict[str, Any]) -> List[str]:
    values = []

    for key in (
        "ioc",
        "indicator",
        "value",
        "url",
        "domain",
        "ip",
        "hash",
    ):
        value = alert.get(key)

        if value:
            values.append(
                _normalize_ioc(value)
            )

    for key in (
        "iocs",
        "indicators",
    ):
        for value in _as_list(
            alert.get(key)
        ):
            normalized = _normalize_ioc(
                value
            )

            if normalized:
                values.append(
                    normalized
                )

    return sorted(
        set(
            item
            for item in values
            if item
        )
    )


def _extract_set(
    alert: Dict[str, Any],
    keys: Iterable[str],
) -> List[str]:

    result = set()

    for key in keys:

        for value in _as_list(
            alert.get(key)
        ):

            normalized = _normalize_token(value)

            if normalized:
                result.add(
                    normalized
                )

    return sorted(
        result
    )


def _normalize_alert(
    alert: Dict[str, Any],
    index: int,
) -> Dict[str, Any]:

    if not isinstance(
        alert,
        dict
    ):
        alert = {}

    alert_id = _alert_key(
        alert
    )

    if not alert_id:

        alert_id = (
            f"anonymous-{index:05d}"
        )

    severity = _normalize_token(
        alert.get(
            "severity",
            "INFO"
        )
    ).upper()

    if severity not in SEVERITY_RANK:
        severity = "INFO"

    score = _safe_float(
        alert.get(
            "alert_score",
            alert.get(
                "risk_score",
                alert.get(
                    "threat_score",
                    0
                )
            )
        )
    )

    confidence = _clamp(
        _safe_float(
            alert.get(
                "confidence",
                0
            )
        ),
        0.0,
        1.0,
    )

    return {
        "alert_id": alert_id,
        "severity": severity,
        "severity_rank": SEVERITY_RANK[
            severity
        ],
        "alert_score": _clamp(
            score,
            0.0,
            100.0,
        ),
        "confidence": confidence,
        "iocs": _extract_iocs(
            alert
        ),
        "campaigns": _extract_set(
            alert,
            (
                "campaign",
                "campaign_id",
                "campaigns",
            )
        ),
        "actors": _extract_set(
            alert,
            (
                "actor",
                "threat_actor",
                "actors",
            )
        ),
        "malware": _extract_set(
            alert,
            (
                "malware",
                "malware_family",
                "malware_families",
            )
        ),
        "mitre": _extract_set(
            alert,
            (
                "mitre_attack",
                "mitre",
                "techniques",
                "mitre_techniques",
            )
        ),
        "timestamp": _parse_timestamp(
            alert.get(
                "timestamp",
                alert.get(
                    "created_at",
                    alert.get(
                        "detected_at"
                    )
                )
            )
        ),
        "source": _normalize_token(
            alert.get(
                "source"
            )
        ),
    }


def _relationship_score(
    left: Dict[str, Any],
    right: Dict[str, Any],
) -> Tuple[float, List[str], List[str], int]:

    reasons = []
    relationship_types = []
    points = 0

    left_iocs = set(
        left["iocs"]
    )

    right_iocs = set(
        right["iocs"]
    )

    shared_iocs = sorted(
        left_iocs.intersection(
            right_iocs
        )
    )

    if shared_iocs:

        points += 45

        relationship_types.append(
            "shared_ioc"
        )

        reasons.append(
            "shared_ioc"
        )

    shared_campaigns = sorted(
        set(left["campaigns"]).intersection(
            right["campaigns"]
        )
    )

    if shared_campaigns:

        points += 30

        relationship_types.append(
            "shared_campaign"
        )

        reasons.append(
            "shared_campaign"
        )

    shared_actors = sorted(
        set(left["actors"]).intersection(
            right["actors"]
        )
    )

    if shared_actors:

        points += 25

        relationship_types.append(
            "shared_actor"
        )

        reasons.append(
            "shared_actor"
        )

    shared_malware = sorted(
        set(left["malware"]).intersection(
            right["malware"]
        )
    )

    if shared_malware:

        points += 20

        relationship_types.append(
            "shared_malware"
        )

        reasons.append(
            "shared_malware"
        )

    shared_mitre = sorted(
        set(left["mitre"]).intersection(
            right["mitre"]
        )
    )

    if shared_mitre:

        points += min(
            20,
            5 * len(shared_mitre)
        )

        relationship_types.append(
            "shared_mitre"
        )

        reasons.append(
            "shared_mitre"
        )

    temporal_gap_seconds = None

    if (
        left["timestamp"] is not None
        and
        right["timestamp"] is not None
    ):

        temporal_gap_seconds = abs(
            (
                left["timestamp"]
                -
                right["timestamp"]
            ).total_seconds()
        )

        if temporal_gap_seconds <= 900:

            points += 18

            relationship_types.append(
                "temporal_proximity_15m"
            )

            reasons.append(
                "temporal_proximity"
            )

        elif temporal_gap_seconds <= 3600:

            points += 12

            relationship_types.append(
                "temporal_proximity_1h"
            )

            reasons.append(
                "temporal_proximity"
            )

        elif temporal_gap_seconds <= 21600:

            points += 6

            relationship_types.append(
                "temporal_proximity_6h"
            )

            reasons.append(
                "temporal_proximity"
            )

    if (
        left["source"]
        and
        right["source"]
        and
        left["source"]
        == right["source"]
    ):

        points += 4

        relationship_types.append(
            "shared_source"
        )

        reasons.append(
            "shared_source"
        )

    # Clamp the relationship score.
    score = _clamp(
        points,
        0.0,
        100.0,
    )

    return (
        score,
        sorted(
            set(reasons)
        ),
        sorted(
            set(relationship_types)
        ),
        temporal_gap_seconds,
    )


def _relationship_confidence(
    score: float,
    left: Dict[str, Any],
    right: Dict[str, Any],
) -> float:

    base = score / 100.0

    evidence_quality = (
        (
            left["confidence"]
            +
            right["confidence"]
        )
        / 2.0
    )

    severity_support = (
        (
            left["severity_rank"]
            +
            right["severity_rank"]
        )
        /
        (
            2.0
            * max(
                SEVERITY_RANK.values()
            )
        )
    )

    confidence = (
        base * 0.65
        +
        evidence_quality * 0.25
        +
        severity_support * 0.10
    )

    return _clamp(
        confidence,
        0.0,
        1.0,
    )


def _severity_for_incident(
    alerts: List[Dict[str, Any]]
) -> str:

    if not alerts:
        return "INFO"

    rank = max(
        item["severity_rank"]
        for item in alerts
    )

    return SEVERITY_BY_RANK[
        rank
    ]


def _incident_id(
    alert_ids: Iterable[str],
) -> str:

    normalized = sorted(
        set(
            _normalize_token(
                item
            )
            for item in alert_ids
            if _normalize_token(item)
        )
    )

    digest = hashlib.sha256(
        "|".join(
            normalized
        ).encode(
            "utf-8"
        )
    ).hexdigest()[:12].upper()

    return (
        "INC-CORR-"
        + digest
    )


def _correlation_id(
    left_id: str,
    right_id: str,
) -> str:

    pair = sorted(
        [
            _normalize_token(
                left_id
            ),
            _normalize_token(
                right_id
            )
        ]
    )

    digest = hashlib.sha256(
        "|".join(
            pair
        ).encode(
            "utf-8"
        )
    ).hexdigest()[:12].upper()

    return (
        "REL-"
        + digest
    )


def correlate_detections(
    alerts: Any,
    *,
    min_relationship_score: float = 35.0,
) -> Dict[str, Any]:
    """
    Correlate normalized SOC detections into relationship
    clusters and incident candidates.

    Conservative rule:
    isolated alerts do not become correlated incidents.
    """

    raw_alerts = (
        list(alerts)
        if isinstance(
            alerts,
            (list, tuple)
        )
        else []
    )

    normalized = [
        _normalize_alert(
            alert,
            index
        )
        for index, alert
        in enumerate(
            raw_alerts
        )
    ]

    # -------------------------------------------------
    # Deterministic deduplication
    # -------------------------------------------------

    unique = {}
    duplicate_count = 0

    for item in normalized:

        key = item["alert_id"]

        if key in unique:
            duplicate_count += 1

            existing = unique[key]

            # Keep the stronger representation.
            if (
                item["alert_score"],
                item["severity_rank"],
                item["confidence"],
            ) > (
                existing["alert_score"],
                existing["severity_rank"],
                existing["confidence"],
            ):
                unique[key] = item

        else:
            unique[key] = item

    alerts_unique = [
        unique[key]
        for key in sorted(
            unique
        )
    ]

    # -------------------------------------------------
    # Pairwise correlation
    # -------------------------------------------------

    relationships = []

    adjacency = defaultdict(
        set
    )

    for index, left in enumerate(
        alerts_unique
    ):

        for right in alerts_unique[
            index + 1:
        ]:

            score, reasons, relationship_types, gap = (
                _relationship_score(
                    left,
                    right
                )
            )

            if score < min_relationship_score:
                continue

            confidence = _relationship_confidence(
                score,
                left,
                right
            )

            relation = {
                "correlation_id": _correlation_id(
                    left["alert_id"],
                    right["alert_id"],
                ),
                "source_alert": left[
                    "alert_id"
                ],
                "target_alert": right[
                    "alert_id"
                ],
                "score": score,
                "confidence": confidence,
                "reasons": reasons,
                "relationship_types": relationship_types,
                "temporal_gap_seconds": gap,
                "shared_iocs": sorted(
                    set(left["iocs"]).intersection(
                        right["iocs"]
                    )
                ),
                "shared_campaigns": sorted(
                    set(left["campaigns"]).intersection(
                        right["campaigns"]
                    )
                ),
                "shared_actors": sorted(
                    set(left["actors"]).intersection(
                        right["actors"]
                    )
                ),
                "shared_malware": sorted(
                    set(left["malware"]).intersection(
                        right["malware"]
                    )
                ),
                "shared_mitre": sorted(
                    set(left["mitre"]).intersection(
                        right["mitre"]
                    )
                ),
            }

            relationships.append(
                relation
            )

            adjacency[
                left["alert_id"]
            ].add(
                right["alert_id"]
            )

            adjacency[
                right["alert_id"]
            ].add(
                left["alert_id"]
            )

            if len(relationships) >= MAX_RELATIONSHIPS:
                break

        if len(relationships) >= MAX_RELATIONSHIPS:
            break

    relationships.sort(
        key=lambda item: (
            -float(
                item["score"]
            ),
            item["correlation_id"],
        )
    )

    # -------------------------------------------------
    # Connected components -> incident candidates
    # -------------------------------------------------

    visited = set()
    incidents = []

    for alert in alerts_unique:

        alert_id = alert[
            "alert_id"
        ]

        if alert_id in visited:
            continue

        if not adjacency.get(
            alert_id
        ):
            visited.add(
                alert_id
            )
            continue

        queue = deque(
            [alert_id]
        )

        component = []

        while queue:

            current = queue.popleft()

            if current in visited:
                continue

            visited.add(
                current
            )

            component.append(
                current
            )

            for neighbour in sorted(
                adjacency.get(
                    current,
                    set()
                )
            ):

                if neighbour not in visited:
                    queue.append(
                        neighbour
                    )

        if len(component) < 2:
            continue

        component_alerts = [
            unique[item]
            for item in sorted(
                component
            )
        ]

        component_relations = [
            relation
            for relation in relationships
            if (
                relation[
                    "source_alert"
                ] in component
                and
                relation[
                    "target_alert"
                ] in component
            )
        ]

        relation_confidence = (
            sum(
                relation[
                    "confidence"
                ]
                for relation
                in component_relations
            )
            /
            max(
                1,
                len(
                    component_relations
                )
            )
        )

        strongest_score = max(
            (
                relation[
                    "score"
                ]
                for relation
                in component_relations
            ),
            default=0.0
        )

        multi_relation_bonus = min(
            20.0,
            max(
                0,
                len(
                    component_relations
                ) - 1
            ) * 4.0
        )

        incident_confidence = _clamp(
            relation_confidence * 0.70
            +
            min(
                1.0,
                strongest_score / 100.0
            ) * 0.20
            +
            min(
                1.0,
                len(component_relations) / 5.0
            ) * 0.10,
            0.0,
            1.0,
        )

        incident_score = _clamp(
            strongest_score
            +
            multi_relation_bonus,
            0.0,
            100.0,
        )

        # SOC95 incident context propagation
        _incident_shared_iocs = set()
        _incident_shared_campaigns = set()
        _incident_shared_actors = set()
        _incident_shared_malware = set()

        _incident_shared_mitre = set()

        # -------------------------------------------------
        # MITRE incident context propagation
        #
        # Relationship-level shared_mitre represents
        # pairwise overlap only.
        #
        # Incident-level MITRE context must contain the
        # union of techniques observed across all alerts
        # participating in the connected incident component.
        # -------------------------------------------------

        for _incident_alert in component_alerts:

            if not isinstance(
                _incident_alert,
                dict,
            ):
                continue

            _incident_shared_mitre.update(
                _incident_alert.get(
                    "mitre",
                    [],
                )
                or []
            )

        for _incident_relation in component_relations:

            if not isinstance(
                _incident_relation,
                dict,
            ):
                continue

            _incident_shared_iocs.update(
                _incident_relation.get(
                    "shared_iocs",
                    [],
                )
                or []
            )

            _incident_shared_campaigns.update(
                _incident_relation.get(
                    "shared_campaigns",
                    [],
                )
                or []
            )

            _incident_shared_actors.update(
                _incident_relation.get(
                    "shared_actors",
                    [],
                )
                or []
            )

            _incident_shared_malware.update(
                _incident_relation.get(
                    "shared_malware",
                    [],
                )
                or []
            )

            # Preserve pairwise MITRE overlap as
            # supplemental relationship context.
            _incident_shared_mitre.update(
                _incident_relation.get(
                    "shared_mitre",
                    [],
                )
                or []
            )

        incident = {
            "incident_id": _incident_id(
                component
            ),
            "alert_ids": sorted(
                component
            ),
            "alert_count": len(
                component
            ),
            "relationship_count": len(
                component_relations
            ),
            "severity": _severity_for_incident(
                component_alerts
            ),
            "incident_score": incident_score,
            "confidence": incident_confidence,
            "status": "OPEN",
            "iocs": sorted(
                _incident_shared_iocs
            ),
            "campaigns": sorted(
                _incident_shared_campaigns
            ),
            "actors": sorted(
                _incident_shared_actors
            ),
            "malware": sorted(
                _incident_shared_malware
            ),
            "mitre_techniques": sorted(
                _incident_shared_mitre
            ),
            "correlation_reasons": sorted(
                set(
                    reason
                    for relation
                    in component_relations
                    for reason
                    in relation[
                        "reasons"
                    ]
                )
            ),
            "relationship_types": sorted(
                set(
                    relation_type
                    for relation
                    in component_relations
                    for relation_type
                    in relation[
                        "relationship_types"
                    ]
                )
            ),
        }

        incidents.append(
            incident
        )

        if len(incidents) >= MAX_INCIDENTS:
            break

    incidents.sort(
        key=lambda item: (
            -float(
                item["incident_score"]
            ),
            item["incident_id"],
        )
    )

    # -------------------------------------------------
    # Summary
    # -------------------------------------------------

    correlated_alert_ids = sorted(
        {
            alert_id
            for incident
            in incidents
            for alert_id
            in incident[
                "alert_ids"
            ]
        }
    )

    isolated_alert_ids = sorted(
        set(
            alert[
                "alert_id"
            ]
            for alert
            in alerts_unique
        )
        -
        set(
            correlated_alert_ids
        )
    )

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "status": (
            "CORRELATED"
            if incidents
            else "NO_CORRELATION"
        ),
        "input_count": len(
            raw_alerts
        ),
        "unique_alert_count": len(
            alerts_unique
        ),
        "duplicate_alert_count": (
            duplicate_count
        ),
        "relationship_count": len(
            relationships
        ),
        "incident_candidate_count": len(
            incidents
        ),
        "correlated_alert_count": len(
            correlated_alert_ids
        ),
        "isolated_alert_count": len(
            isolated_alert_ids
        ),
        "relationships": relationships,
        "incident_candidates": incidents,
        "isolated_alert_ids": isolated_alert_ids,
        "deterministic": True,
    }
