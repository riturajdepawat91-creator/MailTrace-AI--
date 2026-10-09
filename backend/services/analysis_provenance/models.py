from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DependencySnapshot:
    dependency_id: str
    dependency_type: str
    provider: str | None
    observed_at_utc: str
    request_fingerprint: str | None
    response_fingerprint: str | None
    version: str | None
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "dependency_type": self.dependency_type,
            "provider": self.provider,
            "observed_at_utc": self.observed_at_utc,
            "request_fingerprint": self.request_fingerprint,
            "response_fingerprint": self.response_fingerprint,
            "version": self.version,
            "status": self.status,
        }


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    fingerprint_sha256: str
    parent_artifact_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "fingerprint_sha256": self.fingerprint_sha256,
            "parent_artifact_ids": list(self.parent_artifact_ids),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ExecutionManifest:
    execution_id: str
    investigation_id: str
    evidence_id: str
    input_sha256: str
    input_size_bytes: int
    input_media_type: str | None
    engine_id: str
    engine_version: str
    analysis_version: str
    ruleset_id: str | None
    ruleset_version: str | None
    ruleset_fingerprint: str | None
    configuration_fingerprint: str | None
    environment_fingerprint: str | None
    determinism_class: str
    started_at_utc: str
    completed_at_utc: str | None
    status: str
    parent_artifact_ids: tuple[str, ...]
    output_artifact_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    executed_components: tuple[str, ...]
    skipped_components: tuple[str, ...]
    failed_components: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "investigation_id": self.investigation_id,
            "evidence_id": self.evidence_id,
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "input_media_type": self.input_media_type,
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "analysis_version": self.analysis_version,
            "ruleset_id": self.ruleset_id,
            "ruleset_version": self.ruleset_version,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "configuration_fingerprint": self.configuration_fingerprint,
            "environment_fingerprint": self.environment_fingerprint,
            "determinism_class": self.determinism_class,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "status": self.status,
            "parent_artifact_ids": list(self.parent_artifact_ids),
            "output_artifact_ids": list(self.output_artifact_ids),
            "finding_ids": list(self.finding_ids),
            "dependency_ids": list(self.dependency_ids),
            "executed_components": list(self.executed_components),
            "skipped_components": list(self.skipped_components),
            "failed_components": list(self.failed_components),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ProvenanceRecord:
    provenance_id: str
    record_type: str
    sequence: int
    created_at_utc: str
    investigation_id: str
    evidence_id: str
    execution_id: str
    previous_record_hash: str | None
    record_hash: str
    execution_fingerprint: str
    status: str
    integrity_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance_id": self.provenance_id,
            "record_type": self.record_type,
            "sequence": self.sequence,
            "created_at_utc": self.created_at_utc,
            "investigation_id": self.investigation_id,
            "evidence_id": self.evidence_id,
            "execution_id": self.execution_id,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
            "execution_fingerprint": self.execution_fingerprint,
            "status": self.status,
            "integrity_state": self.integrity_state,
        }


@dataclass(frozen=True)
class ReplayComparison:
    execution_id: str
    original_execution_fingerprint: str
    replay_execution_fingerprint: str | None
    state: str
    dependency_drift: tuple[str, ...] = ()
    output_mismatches: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "original_execution_fingerprint": self.original_execution_fingerprint,
            "replay_execution_fingerprint": self.replay_execution_fingerprint,
            "state": self.state,
            "dependency_drift": list(self.dependency_drift),
            "output_mismatches": list(self.output_mismatches),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class ProvenanceVerification:
    valid: bool
    chain_valid: bool
    graph_valid: bool
    record_count: int
    verified_count: int
    orphan_count: int
    conflict_count: int
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "chain_valid": self.chain_valid,
            "graph_valid": self.graph_valid,
            "record_count": self.record_count,
            "verified_count": self.verified_count,
            "orphan_count": self.orphan_count,
            "conflict_count": self.conflict_count,
            "issues": list(self.issues),
        }
