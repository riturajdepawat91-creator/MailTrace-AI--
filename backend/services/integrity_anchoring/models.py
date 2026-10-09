from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AnchorRequest:
    anchor_id: str
    evidence_id: str
    commitment_algorithm: str
    commitment_sha256: str
    commitment_payload: dict[str, Any]
    requested_at_utc: str
    provider: str
    nonce: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnchorReceipt:
    anchor_id: str
    evidence_id: str
    provider: str
    status: str
    trust_level: str
    commitment_algorithm: str
    commitment_sha256: str
    anchored_at_utc: str | None
    external_reference: str | None
    proof: bytes | None
    verification_state: str
    verification_issues: tuple[str, ...] = field(default_factory=tuple)
    nonce: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnchorVerification:
    anchor_id: str
    evidence_id: str
    valid: bool
    commitment_match: bool
    provider_verified: bool
    timestamp_present: bool
    trust_level: str
    issues: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AnchorExport:
    analysis: dict[str, Any]
    request: dict[str, Any]
    receipt: dict[str, Any]
    verification: dict[str, Any]
    export_integrity: dict[str, str]
