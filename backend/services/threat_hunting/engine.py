from __future__ import annotations

from typing import Any, Dict, List, Iterable
import copy
import hashlib
import json


ENGINE_NAME = "soc95-threat-hunting"
ENGINE_VERSION = "1.0"

HUNT_STATUSES = {
    "NO_MATCH",
    "MATCHED",
    "HIGH_CONFIDENCE",
    "CRITICAL_FINDING",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _clamp(
    value: Any,
    low: float = 0.0,
    high: float = 100.0,
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


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0

    return max(
        0.0,
        min(
            1.0,
            number,
        ),
    )


def _clean_values(value: Any) -> List[str]:

    if isinstance(value, str):
        value = [value]

    if not isinstance(
        value,
        (list, tuple, set),
    ):
        return []

    result = []

    for item in value:

        text = _text(item)

        if text and text not in result:
            result.append(text)

    return sorted(
        result,
        key=lambda item: item.lower(),
    )


def _deterministic_id(
    prefix: str,
    *parts: Any,
) -> str:

    normalized = []

    for part in parts:

        if isinstance(
            part,
            (dict, list, tuple, set),
        ):

            if isinstance(
                part,
                set,
            ):
                part = sorted(
                    _clean_values(part)
                )

            normalized.append(
                json.dumps(
                    part,
                    sort_keys=True,
                    default=str,
                )
            )

        else:
            normalized.append(
                _text(part)
            )

    material = "|".join(
        normalized
    )

    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"{prefix}-{digest}"


def _records_from_context(
    context: Dict[str, Any],
) -> List[Dict[str, Any]]:

    candidates = []

    for key in (
        "alerts",
        "detections",
        "incidents",
        "investigations",
        "cases",
        "records",
        "events",
    ):

        value = context.get(
            key,
            [],
        )

        if isinstance(
            value,
            list,
        ):

            candidates.extend(
                item
                for item in value
                if isinstance(
                    item,
                    dict,
                )
            )

        elif isinstance(
            value,
            dict,
        ):

            candidates.append(
                value
            )

    return copy.deepcopy(
        candidates
    )


def _iter_values(
    record: Dict[str, Any],
    keys: Iterable[str],
) -> List[str]:

    values = []

    for key in keys:

        raw = record.get(
            key,
            [],
        )

        values.extend(
            _clean_values(raw)
        )

    return sorted(
        set(values),
        key=lambda item: item.lower(),
    )


def _record_id(
    record: Dict[str, Any],
    index: int,
) -> str:

    for key in (
        "alert_id",
        "detection_id",
        "incident_id",
        "investigation_id",
        "case_id",
        "event_id",
        "id",
    ):

        value = _text(
            record.get(key)
        )

        if value:
            return value

    return _deterministic_id(
        "REC",
        index,
        record,
    )


def _match_case_insensitive(
    query_values: List[str],
    record_values: List[str],
) -> List[str]:

    lookup = {
        item.lower(): item
        for item in record_values
    }

    matches = []

    for query in query_values:

        value = lookup.get(
            query.lower()
        )

        if value:
            matches.append(value)

    return sorted(
        set(matches),
        key=lambda item: item.lower(),
    )


def _build_match(
    record: Dict[str, Any],
    index: int,
    query: Dict[str, Any],
) -> Dict[str, Any]:

    record_id = _record_id(
        record,
        index,
    )

    iocs = _iter_values(
        record,
        (
            "iocs",
            "ioc",
            "indicators",
        ),
    )

    campaigns = _iter_values(
        record,
        (
            "campaigns",
            "campaign",
        ),
    )

    actors = _iter_values(
        record,
        (
            "actors",
            "actor",
            "threat_actors",
        ),
    )

    malware = _iter_values(
        record,
        (
            "malware",
            "malware_families",
        ),
    )

    mitre = _iter_values(
        record,
        (
            "mitre",
            "mitre_techniques",
            "techniques",
        ),
    )

    domains = _iter_values(
        record,
        (
            "domains",
            "domain",
        ),
    )

    ips = _iter_values(
        record,
        (
            "ips",
            "ip_addresses",
            "ip",
        ),
    )

    hashes = _iter_values(
        record,
        (
            "hashes",
            "hash",
            "file_hashes",
        ),
    )

    query_iocs = _clean_values(
        query.get(
            "iocs",
            [],
        )
    )

    query_campaigns = _clean_values(
        query.get(
            "campaigns",
            [],
        )
    )

    query_actors = _clean_values(
        query.get(
            "actors",
            [],
        )
    )

    query_malware = _clean_values(
        query.get(
            "malware",
            [],
        )
    )

    query_mitre = _clean_values(
        query.get(
            "mitre_techniques",
            query.get(
                "mitre",
                [],
            ),
        )
    )

    query_domains = _clean_values(
        query.get(
            "domains",
            [],
        )
    )

    query_ips = _clean_values(
        query.get(
            "ips",
            [],
        )
    )

    query_hashes = _clean_values(
        query.get(
            "hashes",
            [],
        )
    )

    matched_iocs = _match_case_insensitive(
        query_iocs,
        iocs,
    )

    matched_campaigns = _match_case_insensitive(
        query_campaigns,
        campaigns,
    )

    matched_actors = _match_case_insensitive(
        query_actors,
        actors,
    )

    matched_malware = _match_case_insensitive(
        query_malware,
        malware,
    )

    matched_mitre = _match_case_insensitive(
        query_mitre,
        mitre,
    )

    matched_domains = _match_case_insensitive(
        query_domains,
        domains,
    )

    matched_ips = _match_case_insensitive(
        query_ips,
        ips,
    )

    matched_hashes = _match_case_insensitive(
        query_hashes,
        hashes,
    )

    signals = []

    if matched_iocs:
        signals.append("IOC")
    if matched_campaigns:
        signals.append("CAMPAIGN")
    if matched_actors:
        signals.append("ACTOR")
    if matched_malware:
        signals.append("MALWARE")
    if matched_mitre:
        signals.append("MITRE")
    if matched_domains:
        signals.append("DOMAIN")
    if matched_ips:
        signals.append("IP")
    if matched_hashes:
        signals.append("HASH")

    match_count = len(signals)

    score = _clamp(
        (
            len(matched_iocs) * 32.0
            + len(matched_campaigns) * 20.0
            + len(matched_actors) * 18.0
            + len(matched_malware) * 15.0
            + len(matched_mitre) * 10.0
            + len(matched_domains) * 12.0
            + len(matched_ips) * 12.0
            + len(matched_hashes) * 18.0
        )
    )

    score = max(
        score,
        20.0 if match_count else 0.0,
    )

    record_confidence = _confidence(
        record.get(
            "confidence",
            record.get(
                "score_confidence",
                0.0,
            ),
        )
    )

    if match_count >= 3:
        confidence = _confidence(
            max(
                record_confidence,
                0.75,
            )
            + 0.05
        )
    elif match_count == 2:
        confidence = _confidence(
            max(
                record_confidence,
                0.65,
            )
        )
    elif match_count == 1:
        confidence = _confidence(
            max(
                record_confidence,
                0.55,
            )
        )
    else:
        confidence = record_confidence

    severity = _upper(
        record.get(
            "severity"
        )
    )

    if (
        severity == "CRITICAL"
        or score >= 85.0
    ):
        finding_severity = "CRITICAL"

    elif (
        severity == "HIGH"
        or score >= 60.0
    ):
        finding_severity = "HIGH"

    elif (
        severity == "MEDIUM"
        or score >= 35.0
    ):
        finding_severity = "MEDIUM"

    else:
        finding_severity = (
            "LOW"
            if match_count
            else "INFO"
        )

    return {
        "record_id": record_id,
        "source_record": copy.deepcopy(
            record
        ),
        "matched": bool(signals),
        "match_signals": signals,
        "matched_iocs": matched_iocs,
        "matched_campaigns": matched_campaigns,
        "matched_actors": matched_actors,
        "matched_malware": matched_malware,
        "matched_mitre": matched_mitre,
        "matched_domains": matched_domains,
        "matched_ips": matched_ips,
        "matched_hashes": matched_hashes,
        "score": round(
            score,
            4,
        ),
        "confidence": round(
            confidence,
            6,
        ),
        "severity": finding_severity,
    }


def _build_hunt_summary(
    matches: List[Dict[str, Any]],
) -> Dict[str, Any]:

    matched = [
        item
        for item in matches
        if item.get("matched")
    ]

    severities = {
        severity: sum(
            1
            for item in matched
            if _upper(
                item.get(
                    "severity"
                )
            )
            == severity
        )
        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        )
    }

    iocs = sorted(
        {
            value
            for item in matched
            for value in item.get(
                "matched_iocs",
                [],
            )
        },
        key=lambda item: item.lower(),
    )

    campaigns = sorted(
        {
            value
            for item in matched
            for value in item.get(
                "matched_campaigns",
                [],
            )
        },
        key=lambda item: item.lower(),
    )

    actors = sorted(
        {
            value
            for item in matched
            for value in item.get(
                "matched_actors",
                [],
            )
        },
        key=lambda item: item.lower(),
    )

    malware = sorted(
        {
            value
            for item in matched
            for value in item.get(
                "matched_malware",
                [],
            )
        },
        key=lambda item: item.lower(),
    )

    mitre = sorted(
        {
            value
            for item in matched
            for value in item.get(
                "matched_mitre",
                [],
            )
        },
        key=lambda item: item.lower(),
    )

    score = 0.0
    confidence = 0.0

    if matched:

        score = max(
            item.get(
                "score",
                0.0,
            )
            for item in matched
        )

        confidence = sum(
            item.get(
                "confidence",
                0.0,
            )
            for item in matched
        ) / len(matched)

    if any(
        _upper(
            item.get(
                "severity"
            )
        )
        == "CRITICAL"
        for item in matched
    ):

        status = "CRITICAL_FINDING"

    elif (
        matched
        and confidence >= 0.75
    ):

        status = "HIGH_CONFIDENCE"

    elif matched:

        status = "MATCHED"

    else:

        status = "NO_MATCH"

    return {
        "status": status,
        "matched_record_count": len(
            matched
        ),
        "severity_distribution": severities,
        "max_score": round(
            _clamp(score),
            4,
        ),
        "average_confidence": round(
            _confidence(confidence),
            6,
        ),
        "matched_iocs": iocs,
        "matched_campaigns": campaigns,
        "matched_actors": actors,
        "matched_malware": malware,
        "matched_mitre_techniques": mitre,
    }


def hunt_threats(
    context: Any,
    query: Any = None,
) -> Dict[str, Any]:

    if not isinstance(
        context,
        dict,
    ):

        return {
            "engine": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "success": False,
            "error": "Hunt context must be an object.",
            "hunt_status": "NO_MATCH",
            "simulated": True,
            "persistence": False,
        }

    query = (
        copy.deepcopy(query)
        if isinstance(
            query,
            dict,
        )
        else {}
    )

    source_context = copy.deepcopy(
        context
    )

    records = _records_from_context(
        source_context
    )

    matches = []

    for index, record in enumerate(
        records
    ):

        item = _build_match(
            record,
            index,
            query,
        )

        if item.get(
            "matched"
        ):
            matches.append(item)

    summary = _build_hunt_summary(
        matches
    )

    hunt_id = _deterministic_id(
        "HUNT",
        query,
        records,
    )

    time_window = {
        "start": _text(
            query.get(
                "start_time"
            )
            or query.get(
                "from"
            )
        ),
        "end": _text(
            query.get(
                "end_time"
            )
            or query.get(
                "to"
            )
        ),
    }

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "success": True,
        "hunt_id": hunt_id,
        "hunt_status": summary[
            "status"
        ],
        "query": query,
        "time_window": time_window,
        "searched_record_count": len(
            records
        ),
        "matched_record_count": summary[
            "matched_record_count"
        ],
        "matches": matches,
        "summary": summary,
        "pivots": {
            "iocs": summary[
                "matched_iocs"
            ],
            "campaigns": summary[
                "matched_campaigns"
            ],
            "actors": summary[
                "matched_actors"
            ],
            "malware": summary[
                "matched_malware"
            ],
            "mitre_techniques": summary[
                "matched_mitre_techniques"
            ],
        },
        "capabilities": {
            "ioc_hunting": True,
            "campaign_hunting": True,
            "actor_hunting": True,
            "malware_hunting": True,
            "mitre_hunting": True,
            "domain_hunting": True,
            "ip_hunting": True,
            "hash_hunting": True,
            "time_window_hunting": True,
            "cross_record_correlation": True,
            "deterministic_ids": True,
            "read_only": True,
            "real_world_execution": False,
            "persistence": False,
        },
        "simulated": True,
        "persistence": False,
        "execution_side_effect": False,
    }