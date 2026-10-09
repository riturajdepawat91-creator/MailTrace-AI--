from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any


def _safe(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    if isinstance(value, Enum):
        return _safe(value.value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            str(k): _safe(v)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe(v) for v in value]

    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _safe(value.to_dict())

    if hasattr(value, "__dict__"):
        return {
            str(k): _safe(v)
            for k, v in vars(value).items()
            if not str(k).startswith("__")
        }

    if isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(
        f"Unsupported canonical value type: {type(value).__name__}"
    )


def canonical_json(value: Any) -> str:
    safe = _safe(value)

    return json.dumps(
        safe,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_hex(value: Any) -> str:
    payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def execution_fingerprint(manifest_dict: dict[str, Any]) -> str:
    material = {
        "schema": "mailtrace.analysis_execution.v1",
        "manifest": manifest_dict,
    }

    return sha256_hex(material)


def record_hash(
    *,
    record_without_hash: dict[str, Any],
    previous_record_hash: str | None,
) -> str:
    material = {
        "schema": "mailtrace.provenance_record.v1",
        "previous_record_hash": previous_record_hash,
        "record": record_without_hash,
    }

    return sha256_hex(material)


def artifact_fingerprint(
    *,
    artifact_type: str,
    artifact_payload: dict[str, Any],
) -> str:
    material = {
        "schema": "mailtrace.artifact.v1",
        "artifact_type": artifact_type,
        "payload": artifact_payload,
    }

    return sha256_hex(material)
