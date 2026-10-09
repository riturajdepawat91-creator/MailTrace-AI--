"""Canonical commitment construction for integrity anchoring."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def canonical_commitment_payload(
    *,
    evidence_id: str,
    evidence_sha256: str,
    terminal_event_hash: str,
    chain_anchor_digest: str,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "mailtrace.integrity_anchor.v1",
        "evidence_id": evidence_id,
        "commitment_algorithm": "sha256",
        "evidence_sha256": evidence_sha256,
        "terminal_event_hash": terminal_event_hash,
        "chain_anchor_digest": chain_anchor_digest,
    }

    if manifest_sha256 is not None:
        payload["manifest_sha256"] = manifest_sha256

    return payload


def commitment_sha256(payload: dict[str, Any]) -> str:
    canonical = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
