from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional


ENGINE_NAME = "soc95-ioc-timeline"
ENGINE_VERSION = "1.0"

IOC_FIELDS = (
    "ioc",
    "indicator",
    "value",
    "ip",
    "domain",
    "url",
    "hash",
    "sha256",
    "sha1",
    "md5",
)

TIMESTAMP_FIELDS = (
    "timestamp",
    "time",
    "created_at",
    "updated_at",
    "first_seen",
    "last_seen",
    "detected_at",
    "occurred_at",
)

SOURCE_FIELDS = (
    "source",
    "engine",
    "module",
    "source_type",
)

EVENT_FIELDS = (
    "event_type",
    "type",
    "action",
    "status",
    "verdict",
    "decision",
    "result",
)

IOC_CONTAINER_FIELDS = (
    "iocs",
    "indicators",
    "ioc",
    "artifacts",
    "observables",
)

RELATION_FIELDS = (
    "alert_ids",
    "alerts",
    "incident_id",
    "incident_ids",
    "investigation_id",
    "investigation_ids",
    "case_id",
    "case_ids",
    "campaigns",
    "actors",
    "malware",
    "mitre_techniques",
)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _lower(value: Any) -> str:
    return _text(value).lower()


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
    if number <= 1.0:
        return round(max(0.0, min(1.0, number)), 4)
    return round(max(0.0, min(1.0, number / 100.0)), 4)


def _clean_values(values: Any) -> List[str]:
    if values is None:
        return []

    if isinstance(values, (list, tuple, set)):
        raw = values
    else:
        raw = [values]

    result: List[str] = []
    seen = set()

    for item in raw:
        value = _text(item)
        if not value:
            continue

        key = value.casefold()
        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def _parse_time(value: Any) -> Optional[datetime]:
    text = _text(value)

    if not text:
        return None

    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _deterministic_id(prefix: str, *parts: Any) -> str:
    payload = "|".join(_text(part) for part in parts)
    digest = sha256(payload.encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _iter_records(context: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(context, dict):
        for key, value in context.items():
            if isinstance(value, dict):
                record = deepcopy(value)
                record.setdefault("_container", key)
                yield record
                continue

            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        record = deepcopy(item)
                        record.setdefault("_container", key)
                        yield record

    elif isinstance(context, list):
        for item in context:
            if isinstance(item, dict):
                yield deepcopy(item)


def _extract_iocs(record: Dict[str, Any]) -> List[str]:
    values: List[str] = []

    for field in IOC_FIELDS:
        if field in record:
            values.extend(_clean_values(record.get(field)))

    for field in IOC_CONTAINER_FIELDS:
        container = record.get(field)

        if isinstance(container, dict):
            for nested_key, nested_value in container.items():
                if nested_key.casefold() in IOC_FIELDS:
                    values.extend(_clean_values(nested_value))

        elif isinstance(container, list):
            for item in container:
                if isinstance(item, dict):
                    for nested_key in IOC_FIELDS:
                        if nested_key in item:
                            values.extend(_clean_values(item.get(nested_key)))
                else:
                    values.extend(_clean_values(item))

        else:
            values.extend(_clean_values(container))

    unique: List[str] = []
    seen = set()

    for value in values:
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)

    return unique


def _extract_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    candidates: List[datetime] = []

    for field in TIMESTAMP_FIELDS:
        if field not in record:
            continue

        raw = record.get(field)

        if isinstance(raw, list):
            for item in raw:
                parsed = _parse_time(item)
                if parsed:
                    candidates.append(parsed)
        else:
            parsed = _parse_time(raw)
            if parsed:
                candidates.append(parsed)

    if not candidates:
        return None

    return min(candidates)


def _extract_source(record: Dict[str, Any]) -> str:
    for field in SOURCE_FIELDS:
        value = _text(record.get(field))
        if value:
            return value

    container = _text(record.get("_container"))
    return container or "unknown"


def _extract_event_type(record: Dict[str, Any]) -> str:
    for field in EVENT_FIELDS:
        value = _text(record.get(field))
        if value:
            return value

    container = _text(record.get("_container"))
    return container or "OBSERVED"


def _extract_relations(record: Dict[str, Any]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}

    for field in RELATION_FIELDS:
        value = record.get(field)

        cleaned = _clean_values(value)

        if cleaned:
            result[field] = cleaned

    return result


def _record_score(record: Dict[str, Any]) -> float:
    for field in ("risk_score", "score", "threat_score", "incident_score"):
        if field in record:
            try:
                number = float(record.get(field))
                if number <= 1.0:
                    number *= 100.0
                return _clamp(number)
            except Exception:
                pass

    severity = _lower(record.get("severity"))

    mapping = {
        "critical": 95.0,
        "high": 80.0,
        "medium": 60.0,
        "low": 30.0,
        "info": 10.0,
    }

    return mapping.get(severity, 0.0)


def _record_confidence(record: Dict[str, Any]) -> float:
    for field in ("confidence", "confidence_score"):
        if field in record:
            return _confidence(record.get(field))

    return 0.0


def _build_event(ioc: str, record: Dict[str, Any], ordinal: int) -> Dict[str, Any]:
    timestamp = _extract_timestamp(record)
    relations = _extract_relations(record)

    event_id = _deterministic_id(
        "IOCEVT",
        ioc.casefold(),
        _extract_source(record),
        _extract_event_type(record),
        _iso(timestamp),
        ordinal,
        sorted(relations.items()),
    )

    return {
        "event_id": event_id,
        "ioc": ioc,
        "event_type": _extract_event_type(record),
        "timestamp": _iso(timestamp),
        "timestamp_status": "KNOWN" if timestamp else "UNKNOWN",
        "source": _extract_source(record),
        "score": _record_score(record),
        "confidence": _record_confidence(record),
        "relations": relations,
    }


def _deduplicate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen = set()

    for event in events:
        fingerprint = (
            _lower(event.get("ioc")),
            _lower(event.get("event_type")),
            _lower(event.get("source")),
            _lower(event.get("timestamp")),
            tuple(sorted(
                (
                    key,
                    tuple(sorted(_clean_values(value))),
                )
                for key, value in (event.get("relations") or {}).items()
            )),
        )

        if fingerprint in seen:
            continue

        seen.add(fingerprint)
        result.append(event)

    return result


def _sort_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        events,
        key=lambda item: (
            item.get("timestamp") is None,
            item.get("timestamp") or "",
            item.get("event_id") or "",
        ),
    )


def _build_ioc_timeline(ioc: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = _sort_events(events)

    known_times = [
        _parse_time(event.get("timestamp"))
        for event in ordered
        if event.get("timestamp")
    ]

    known_times = [value for value in known_times if value is not None]

    first_seen = min(known_times) if known_times else None
    last_seen = max(known_times) if known_times else None

    scores = [
        float(event.get("score") or 0.0)
        for event in ordered
    ]

    confidences = [
        float(event.get("confidence") or 0.0)
        for event in ordered
        if event.get("confidence") is not None
    ]

    sources = sorted({
        _text(event.get("source"))
        for event in ordered
        if _text(event.get("source"))
    })

    event_types = sorted({
        _text(event.get("event_type"))
        for event in ordered
        if _text(event.get("event_type"))
    })

    relation_values: Dict[str, List[str]] = {}

    for event in ordered:
        for key, values in (event.get("relations") or {}).items():
            bucket = relation_values.setdefault(key, [])

            for value in _clean_values(values):
                if value.casefold() not in {
                    existing.casefold()
                    for existing in bucket
                }:
                    bucket.append(value)

    timeline_id = _deterministic_id(
        "IOCT",
        ioc.casefold(),
        [event.get("event_id") for event in ordered],
    )

    if not ordered:
        status = "NO_EVENTS"
    elif not known_times:
        status = "TIMELINE_UNKNOWN"
    elif len(known_times) == 1:
        status = "SINGLE_EVENT"
    else:
        status = "TIMELINE_BUILT"

    timeline_confidence = 0.0

    if ordered:
        source_factor = min(1.0, len(sources) / 3.0)
        timestamp_factor = len(known_times) / max(1, len(ordered))
        evidence_factor = min(1.0, len(ordered) / 5.0)

        timeline_confidence = round(
            min(
                1.0,
                (
                    source_factor * 0.25
                    + timestamp_factor * 0.45
                    + evidence_factor * 0.30
                ),
            ),
            4,
        )

    max_score = max(scores) if scores else 0.0
    avg_confidence = (
        sum(confidences) / len(confidences)
        if confidences
        else 0.0
    )

    return {
        "timeline_id": timeline_id,
        "ioc": ioc,
        "status": status,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
        "event_count": len(ordered),
        "known_timestamp_count": len(known_times),
        "unknown_timestamp_count": len(ordered) - len(known_times),
        "sources": sources,
        "event_types": event_types,
        "max_score": _clamp(max_score),
        "confidence": round(min(1.0, max(avg_confidence, timeline_confidence)), 4),
        "relations": relation_values,
        "events": ordered,
    }


def build_ioc_timeline(context: Any) -> Dict[str, Any]:
    records = list(_iter_records(context))

    timeline_events: Dict[str, List[Dict[str, Any]]] = {}
    event_counter = 0

    for record in records:
        iocs = _extract_iocs(record)

        if not iocs:
            continue

        for ioc in iocs:
            event_counter += 1
            event = _build_event(ioc, record, event_counter)
            timeline_events.setdefault(ioc, []).append(event)

    timelines = []

    for ioc in sorted(
        timeline_events.keys(),
        key=lambda value: (value.casefold(), value),
    ):
        events = _deduplicate_events(timeline_events[ioc])
        timelines.append(_build_ioc_timeline(ioc, events))

    all_events = [
        event
        for timeline in timelines
        for event in timeline["events"]
    ]

    known_times = [
        _parse_time(event.get("timestamp"))
        for event in all_events
        if event.get("timestamp")
    ]
    known_times = [value for value in known_times if value is not None]

    start_time = min(known_times) if known_times else None
    end_time = max(known_times) if known_times else None

    if not timelines:
        status = "NO_EVENTS"
    elif not known_times:
        status = "TIMELINE_UNKNOWN"
    else:
        status = "TIMELINES_BUILT"

    score = 0.0

    if timelines:
        score = max(
            float(item.get("max_score") or 0.0)
            for item in timelines
        )

        if len(timelines) > 1:
            score = _clamp(score + min(10.0, len(timelines) * 1.5))

    confidence_values = [
        float(item.get("confidence") or 0.0)
        for item in timelines
    ]

    confidence = (
        round(sum(confidence_values) / len(confidence_values), 4)
        if confidence_values
        else 0.0
    )

    timeline_id = _deterministic_id(
        "IOCTM",
        [
            item.get("timeline_id")
            for item in timelines
        ],
    )

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "timeline_id": timeline_id,
        "status": status,
        "score": _clamp(score),
        "confidence": _confidence(confidence),
        "ioc_count": len(timelines),
        "event_count": len(all_events),
        "known_timestamp_count": len(known_times),
        "unknown_timestamp_count": len(all_events) - len(known_times),
        "start_time": _iso(start_time),
        "end_time": _iso(end_time),
        "timelines": timelines,
        "capabilities": {
            "ioc_first_seen": True,
            "ioc_last_seen": True,
            "event_correlation": True,
            "relation_mapping": True,
            "deterministic_ids": True,
            "read_only": True,
            "persistence": False,
            "execution_side_effect": False,
            "simulation": True,
        },
    }


def build_timeline(context: Any) -> Dict[str, Any]:
    return build_ioc_timeline(context)


def analyze_ioc_timeline(context: Any) -> Dict[str, Any]:
    return build_ioc_timeline(context)
