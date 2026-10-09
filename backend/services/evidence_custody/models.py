from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceHashSet:
    sha256: str
    sha512: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class CustodyEvent:
    event_id: str
    evidence_id: str
    sequence: int
    event_type: str
    timestamp_utc: str
    actor: str
    purpose: str
    source: str | None
    destination: str | None
    reason: str | None

    previous_event_hash: str | None
    event_hash: str

    resulting_state: str
    evidence_sha256: str

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceRecord:
    evidence_id: str
    case_id: str | None
    investigation_id: str | None

    artifact_type: str
    original_filename: str | None
    media_type: str | None
    source: str

    acquisition_timestamp_utc: str
    collector: str
    acquisition_method: str

    size_bytes: int
    hashes: EvidenceHashSet

    preservation_path: str | None = None
    preservation_verified: bool = False

    state: str = "ACQUIRED"
    sealed: bool = False
    seal_hash: str | None = None

    created_timestamp_utc: str = ""
    updated_timestamp_utc: str = ""

    custody_event_ids: list[str] = field(default_factory=list)

    core_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["hashes"] = self.hashes.to_dict()
        return data


@dataclass
class VerificationResult:
    evidence_id: str
    verified: bool
    evidence_hash_match: bool
    seal_hash_match: bool
    custody_chain_valid: bool
    preservation_copy_match: bool

    calculated_sha256: str | None
    calculated_sha512: str | None

    expected_sha256: str | None
    expected_sha512: str | None

    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceManifest:
    manifest_version: str
    generated_timestamp_utc: str
    evidence_count: int
    evidences: list[dict[str, Any]]
    manifest_sha256: str
    manifest_sha512: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
