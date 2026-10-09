from __future__ import annotations

import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .process_lock import ProcessSafeRLock

from .canonical import (
    artifact_fingerprint,
    execution_fingerprint,
    record_hash,
)
from .models import (
    ArtifactRef,
    DependencySnapshot,
    ExecutionManifest,
    ProvenanceRecord,
    ProvenanceVerification,
    ReplayComparison,
)
from .rules import (
    ALLOWED_DETERMINISM,
    DETERMINISTIC,
    EXTERNAL_STATE_DEPENDENT,
    INTEGRITY_CHAIN_VALID,
    INTEGRITY_CONFLICT,
    INTEGRITY_ORPHAN,
    INTEGRITY_TAMPERED,
    INTEGRITY_VALID,
    MAX_DEPENDENCY_COUNT,
    MAX_ID_CHARS,
    MAX_METADATA_KEYS,
    MAX_METADATA_VALUE_CHARS,
    MAX_REFERENCE_COUNT,
    NON_DETERMINISTIC,
    NON_REPLAYABLE,
    SCHEMA_VERSION,
    STATUS_DEPENDENCY_DRIFT,
    STATUS_FAILED,
    STATUS_MATCHED,
    STATUS_MISMATCHED,
    STATUS_NON_REPLAYABLE,
    STATUS_PARTIAL,
    STATUS_RECORDED,
    STATUS_REPLAY_READY,
    STATUS_REPLAYED,
    STATUS_VERIFIED,
    valid_identifier,
    valid_sha256,
)


class ProvenanceError(Exception):
    pass


class ProvenanceConflictError(ProvenanceError):
    pass


class ProvenanceIntegrityError(ProvenanceError):
    pass


class ProvenanceValidationError(ProvenanceError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_text(
    value: Any,
    *,
    field_name: str,
    max_chars: int = MAX_ID_CHARS,
    allow_none: bool = False,
) -> str | None:
    if value is None and allow_none:
        return None

    if not isinstance(value, str):
        raise ProvenanceValidationError(
            f"{field_name} must be a string."
        )

    value = value.strip()

    if not value:
        raise ProvenanceValidationError(
            f"{field_name} must not be empty."
        )

    if len(value) > max_chars:
        raise ProvenanceValidationError(
            f"{field_name} exceeds configured length."
        )

    if "\x00" in value:
        raise ProvenanceValidationError(
            f"{field_name} contains NUL."
        )

    return value


def _validate_id(value: Any, field_name: str) -> str:
    if not valid_identifier(value):
        raise ProvenanceValidationError(
            f"{field_name} is invalid."
        )

    return value.strip()


def _validate_sha256(value: Any, field_name: str) -> str:
    if not valid_sha256(value):
        raise ProvenanceValidationError(
            f"{field_name} must be a 64-character hex SHA-256."
        )

    return value.lower()


def _clean_refs(
    values: Iterable[str] | None,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if values is None:
        return ()

    values = list(values)

    if len(values) > MAX_REFERENCE_COUNT:
        raise ProvenanceValidationError(
            f"{field_name} exceeds configured reference limit."
        )

    cleaned = []

    for item in values:
        cleaned.append(_validate_id(item, field_name))

    if len(set(cleaned)) != len(cleaned):
        raise ProvenanceConflictError(
            f"{field_name} contains duplicates."
        )

    return tuple(cleaned)


def _clean_metadata(
    metadata: dict[str, Any] | None,
    *,
    field_name: str,
) -> dict[str, Any]:
    if metadata is None:
        return {}

    if not isinstance(metadata, dict):
        raise ProvenanceValidationError(
            f"{field_name} must be a dictionary."
        )

    if len(metadata) > MAX_METADATA_KEYS:
        raise ProvenanceValidationError(
            f"{field_name} has too many keys."
        )

    cleaned: dict[str, Any] = {}

    for key, value in metadata.items():
        key = str(key)

        if len(key) > MAX_METADATA_VALUE_CHARS:
            raise ProvenanceValidationError(
                f"{field_name} key too long."
            )

        if any(
            secret_term in key.lower()
            for secret_term in (
                "password",
                "secret",
                "api_key",
                "apikey",
                "token",
                "authorization",
                "cookie",
            )
        ):
            raise ProvenanceValidationError(
                f"{field_name} contains secret-like key: {key}"
            )

        if isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str):
                if len(value) > MAX_METADATA_VALUE_CHARS:
                    raise ProvenanceValidationError(
                        f"{field_name}.{key} exceeds configured size."
                    )
            cleaned[key] = value

        elif isinstance(value, (list, tuple)):
            if len(value) > MAX_REFERENCE_COUNT:
                raise ProvenanceValidationError(
                    f"{field_name}.{key} list too large."
                )

            safe_items = []
            for child in value:
                if isinstance(child, (str, int, float, bool)) or child is None:
                    if isinstance(child, str) and len(child) > MAX_METADATA_VALUE_CHARS:
                        raise ProvenanceValidationError(
                            f"{field_name}.{key} contains oversized string."
                        )
                    safe_items.append(child)
                else:
                    raise ProvenanceValidationError(
                        f"{field_name}.{key} contains unsupported nested value."
                    )

            cleaned[key] = safe_items

        elif isinstance(value, dict):
            cleaned[key] = _clean_metadata(
                value,
                field_name=f"{field_name}.{key}",
            )

        else:
            raise ProvenanceValidationError(
                f"{field_name}.{key} contains unsupported type: "
                f"{type(value).__name__}"
            )

    return cleaned


class AnalysisProvenanceEngine:
    """
    High-assurance analysis provenance ledger.

    Raw evidence is intentionally not stored here.
    The ledger stores identity, derivation metadata, fingerprints,
    dependency snapshots, graph relationships, and tamper-evident
    provenance records.
    """

    def __init__(
        self,
        *,
        storage_dir: str | Path,
        actor: str = "system",
    ) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.actor = _validate_text(
            actor,
            field_name="actor",
        )

        self.state_file = self.storage_dir / "state.json"
        self.events_file = self.storage_dir / "events.jsonl"
        self.lock_file = self.storage_dir / "provenance.ledger.lock"

        self._lock = ProcessSafeRLock(
            self.lock_file
        )
        self._journal_integrity_issues: list[str] = []

        with self._lock:
            self._state = self._load_state()

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    def _empty_state(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "sequence": 0,
            "last_record_hash": None,
            "executions": {},
            "artifacts": {},
            "dependencies": {},
            "finding_bindings": {},
            "records": [],
        }

    def _load_state(self) -> dict[str, Any]:
        self._journal_integrity_issues = []

        if not self.state_file.exists():
            return self._empty_state()

        try:
            payload = json.loads(
                self.state_file.read_text(
                    encoding="utf-8-sig"
                )
            )
        except Exception as exc:
            raise ProvenanceIntegrityError(
                "Provenance state cannot be parsed."
            ) from exc

        if not isinstance(payload, dict):
            raise ProvenanceIntegrityError(
                "Provenance state root must be a dictionary."
            )

        if payload.get("schema_version") != SCHEMA_VERSION:
            raise ProvenanceIntegrityError(
                "Unsupported provenance state schema."
            )

        payload.setdefault(
            "finding_bindings",
            {}
        )

        self._validate_state(payload)

        if self.events_file.exists():
            raw = self.events_file.read_bytes()
            chunks = raw.splitlines(keepends=True)
            parsed_events: list[dict[str, Any]] = []

            for index, chunk in enumerate(chunks):
                is_last = index == len(chunks) - 1
                has_newline = chunk.endswith(
                    b"\n"
                ) or chunk.endswith(b"\r")

                try:
                    event = json.loads(
                        chunk.decode("utf-8")
                    )

                    if not isinstance(event, dict):
                        raise ValueError(
                            "event must be an object"
                        )

                    parsed_events.append(event)

                except Exception as exc:
                    if is_last and not has_newline:
                        quarantine = self.events_file.with_name(
                            self.events_file.name
                            + ".recovery_torn_tail"
                        )

                        quarantine.write_bytes(chunk)

                        stable = b"".join(
                            chunks[:-1]
                        )

                        tmp = self.events_file.with_suffix(
                            self.events_file.suffix
                            + ".recovery.tmp"
                        )

                        with tmp.open("wb") as handle:
                            handle.write(stable)
                            handle.flush()
                            os.fsync(handle.fileno())

                        os.replace(
                            tmp,
                            self.events_file,
                        )
                        break

                    raise ProvenanceIntegrityError(
                        "Invalid non-final provenance event at "
                        f"line {index + 1}."
                    ) from exc

            state_records = payload["records"]

            common = min(
                len(parsed_events),
                len(state_records),
            )

            for index in range(common):
                if parsed_events[index] != state_records[index]:
                    self._journal_integrity_issues.append(
                        "Event journal diverges from persisted "
                        f"state at record index {index}."
                    )

            if len(parsed_events) < len(state_records):
                self._journal_integrity_issues.append(
                    "Event journal is shorter than persisted "
                    "provenance state."
                )

            if len(parsed_events) > len(state_records):
                extra = parsed_events[
                    len(state_records):
                ]

                quarantine = self.events_file.with_name(
                    self.events_file.name
                    + ".recovery_uncommitted_tail"
                )

                with quarantine.open(
                    "a",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    for event in extra:
                        handle.write(
                            json.dumps(
                                event,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                                allow_nan=False,
                            )
                            + "\n"
                        )

                stable_events = parsed_events[
                    :len(state_records)
                ]

                tmp = self.events_file.with_suffix(
                    self.events_file.suffix
                    + ".recovery.tmp"
                )

                with tmp.open(
                    "w",
                    encoding="utf-8",
                    newline="\n",
                ) as handle:
                    for event in stable_events:
                        handle.write(
                            json.dumps(
                                event,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                                allow_nan=False,
                            )
                            + "\n"
                        )

                    handle.flush()
                    os.fsync(handle.fileno())

                os.replace(
                    tmp,
                    self.events_file,
                )

                self._journal_integrity_issues.append(
                    "Complete uncommitted journal tail was "
                    "quarantined."
                )

        return payload

    def _validate_state(self, state: dict[str, Any]) -> None:
        required = {
            "schema_version",
            "sequence",
            "last_record_hash",
            "executions",
            "artifacts",
            "dependencies",
            "records",
        }

        missing = required - set(state)

        if missing:
            raise ProvenanceIntegrityError(
                f"Provenance state missing fields: {sorted(missing)}"
            )

        if not isinstance(state["sequence"], int):
            raise ProvenanceIntegrityError(
                "sequence must be an integer."
            )

        if state["sequence"] < 0:
            raise ProvenanceIntegrityError(
                "sequence cannot be negative."
            )

        if state["last_record_hash"] is not None:
            _validate_sha256(
                state["last_record_hash"],
                "last_record_hash",
            )

        if not isinstance(state["executions"], dict):
            raise ProvenanceIntegrityError(
                "executions must be a dictionary."
            )

        if not isinstance(state["artifacts"], dict):
            raise ProvenanceIntegrityError(
                "artifacts must be a dictionary."
            )

        if not isinstance(state["dependencies"], dict):
            raise ProvenanceIntegrityError(
                "dependencies must be a dictionary."
            )

        if not isinstance(
            state.get("finding_bindings", {}),
            dict,
        ):
            raise ProvenanceIntegrityError(
                "finding_bindings must be a dictionary."
            )

        artifact_ids = set(
            state["artifacts"]
        )

        for finding_id, bound_artifacts in state.get(
            "finding_bindings",
            {},
        ).items():
            if not isinstance(finding_id, str) or not finding_id:
                raise ProvenanceIntegrityError(
                    "finding_bindings contains an invalid finding ID."
                )

            if not isinstance(bound_artifacts, list):
                raise ProvenanceIntegrityError(
                    f"Finding binding for {finding_id} must be a list."
                )

            if len(bound_artifacts) > MAX_REFERENCE_COUNT:
                raise ProvenanceIntegrityError(
                    f"Finding binding limit exceeded: {finding_id}"
                )

            for artifact_id in bound_artifacts:
                if artifact_id not in artifact_ids:
                    raise ProvenanceIntegrityError(
                        "Finding binding references unknown artifact: "
                        f"{artifact_id}"
                    )

        if not isinstance(state["records"], list):
            raise ProvenanceIntegrityError(
                "records must be a list."
            )

    def _atomic_write_state(self) -> None:
        payload = json.dumps(
            self._state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

        if len(payload.encode("utf-8")) > 64 * 1024 * 1024:
            raise ProvenanceIntegrityError(
                "Provenance state exceeds 64 MiB."
            )

        tmp = self.state_file.with_suffix(
            self.state_file.suffix + ".tmp"
        )

        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp, self.state_file)

    def _append_event(self, event: dict[str, Any]) -> None:
        line = json.dumps(
            event,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

        if len(line.encode("utf-8")) > 512 * 1024:
            raise ProvenanceIntegrityError(
                "Provenance event exceeds 512 KiB."
            )

        with self.events_file.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    # --------------------------------------------------------
    # Execution
    # --------------------------------------------------------

    def create_execution(
        self,
        *,
        investigation_id: str,
        evidence_id: str,
        input_sha256: str,
        input_size_bytes: int,
        engine_id: str,
        engine_version: str,
        analysis_version: str,
        determinism_class: str,
        input_media_type: str | None = None,
        ruleset_id: str | None = None,
        ruleset_version: str | None = None,
        ruleset_fingerprint: str | None = None,
        configuration_fingerprint: str | None = None,
        environment_fingerprint: str | None = None,
        parent_artifact_ids: Iterable[str] | None = None,
        dependency_ids: Iterable[str] | None = None,
        executed_components: Iterable[str] | None = None,
        skipped_components: Iterable[str] | None = None,
        failed_components: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
        started_at_utc: str | None = None,
    ) -> ExecutionManifest:
        with self._lock:
            investigation_id = _validate_id(
                investigation_id,
                "investigation_id",
            )
            evidence_id = _validate_id(
                evidence_id,
                "evidence_id",
            )
            input_sha256 = _validate_sha256(
                input_sha256,
                "input_sha256",
            )

            if not isinstance(input_size_bytes, int):
                raise ProvenanceValidationError(
                    "input_size_bytes must be an integer."
                )

            if input_size_bytes < 0:
                raise ProvenanceValidationError(
                    "input_size_bytes cannot be negative."
                )

            engine_id = _validate_text(
                engine_id,
                field_name="engine_id",
                max_chars=128,
            )
            engine_version = _validate_text(
                engine_version,
                field_name="engine_version",
                max_chars=128,
            )
            analysis_version = _validate_text(
                analysis_version,
                field_name="analysis_version",
                max_chars=128,
            )

            if determinism_class not in ALLOWED_DETERMINISM:
                raise ProvenanceValidationError(
                    f"Unsupported determinism_class: {determinism_class}"
                )

            parent_artifact_ids = _clean_refs(
                parent_artifact_ids,
                field_name="parent_artifact_ids",
            )

            dependency_ids = _clean_refs(
                dependency_ids,
                field_name="dependency_ids",
            )

            executed_components = _clean_refs(
                executed_components,
                field_name="executed_components",
            )

            skipped_components = _clean_refs(
                skipped_components,
                field_name="skipped_components",
            )

            failed_components = _clean_refs(
                failed_components,
                field_name="failed_components",
            )

            metadata = _clean_metadata(
                metadata,
                field_name="metadata",
            )

            execution_id = (
                "EXEC-"
                + secrets.token_hex(10).upper()
            )

            manifest = ExecutionManifest(
                execution_id=execution_id,
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                input_sha256=input_sha256,
                input_size_bytes=input_size_bytes,
                input_media_type=_validate_text(
                    input_media_type,
                    field_name="input_media_type",
                    max_chars=256,
                    allow_none=True,
                ),
                engine_id=engine_id,
                engine_version=engine_version,
                analysis_version=analysis_version,
                ruleset_id=_validate_text(
                    ruleset_id,
                    field_name="ruleset_id",
                    max_chars=128,
                    allow_none=True,
                ),
                ruleset_version=_validate_text(
                    ruleset_version,
                    field_name="ruleset_version",
                    max_chars=128,
                    allow_none=True,
                ),
                ruleset_fingerprint=(
                    _validate_sha256(
                        ruleset_fingerprint,
                        "ruleset_fingerprint",
                    )
                    if ruleset_fingerprint is not None
                    else None
                ),
                configuration_fingerprint=(
                    _validate_sha256(
                        configuration_fingerprint,
                        "configuration_fingerprint",
                    )
                    if configuration_fingerprint is not None
                    else None
                ),
                environment_fingerprint=(
                    _validate_sha256(
                        environment_fingerprint,
                        "environment_fingerprint",
                    )
                    if environment_fingerprint is not None
                    else None
                ),
                determinism_class=determinism_class,
                started_at_utc=started_at_utc or _utc_now(),
                completed_at_utc=None,
                status=STATUS_RECORDED,
                parent_artifact_ids=parent_artifact_ids,
                output_artifact_ids=(),
                finding_ids=(),
                dependency_ids=dependency_ids,
                executed_components=executed_components,
                skipped_components=skipped_components,
                failed_components=failed_components,
                metadata=metadata,
            )

            if execution_id in self._state["executions"]:
                raise ProvenanceConflictError(
                    "Generated execution ID collision."
                )

            self._state["executions"][execution_id] = {
                **manifest.to_dict(),
                "execution_fingerprint": execution_fingerprint(
                    manifest.to_dict()
                ),
            }

            self._atomic_write_state()

            return manifest

    def finalize_execution(
        self,
        execution_id: str,
        *,
        output_artifact_ids: Iterable[str] | None = None,
        finding_ids: Iterable[str] | None = None,
        status: str = STATUS_VERIFIED,
        completed_at_utc: str | None = None,
    ) -> ProvenanceRecord:
        with self._lock:
            execution_id = _validate_id(
                execution_id,
                "execution_id",
            )

            execution = self._state[
                "executions"
            ].get(execution_id)

            if execution is None:
                raise ProvenanceValidationError(
                    f"Unknown execution: {execution_id}"
                )

            output_artifact_ids = _clean_refs(
                output_artifact_ids,
                field_name="output_artifact_ids",
            )

            finding_ids = _clean_refs(
                finding_ids,
                field_name="finding_ids",
            )

            for artifact_id in output_artifact_ids:
                if artifact_id not in self._state[
                    "artifacts"
                ]:
                    raise ProvenanceValidationError(
                        f"Unknown output artifact: {artifact_id}"
                    )

            if status not in {
                STATUS_VERIFIED,
                STATUS_PARTIAL,
                STATUS_FAILED,
                STATUS_REPLAY_READY,
            }:
                raise ProvenanceValidationError(
                    f"Unsupported execution final status: {status}"
                )

            execution[
                "output_artifact_ids"
            ] = list(output_artifact_ids)

            execution[
                "finding_ids"
            ] = list(finding_ids)

            execution[
                "finding_lineage"
            ] = {
                finding_id: {
                    "artifact_ids": list(
                        self._state[
                            "finding_bindings"
                        ].get(
                            finding_id,
                            [],
                        )
                    ),
                    "binding_state": (
                        "BOUND"
                        if self._state[
                            "finding_bindings"
                        ].get(finding_id)
                        else "UNBOUND_LEGACY"
                    ),
                }
                for finding_id in finding_ids
            }

            execution[
                "completed_at_utc"
            ] = (
                completed_at_utc or _utc_now()
            )

            execution["status"] = status

            fingerprint = execution_fingerprint(
                execution
            )

            execution[
                "execution_fingerprint"
            ] = fingerprint

            sequence = (
                self._state["sequence"] + 1
            )

            previous_record_hash = self._state[
                "last_record_hash"
            ]

            record_material = {
                "provenance_id": (
                    "PROV-"
                    + secrets.token_hex(10).upper()
                ),
                "record_type": (
                    "EXECUTION_FINALIZED"
                ),
                "sequence": sequence,
                "created_at_utc": _utc_now(),
                "investigation_id": execution[
                    "investigation_id"
                ],
                "evidence_id": execution[
                    "evidence_id"
                ],
                "execution_id": execution_id,
                "execution_fingerprint": fingerprint,
                "status": status,
                "integrity_state": INTEGRITY_VALID,
                "record_hash_schema_version": 1,
            }

            current_hash = record_hash(
                record_without_hash=record_material,
                previous_record_hash=previous_record_hash,
            )

            record = {
                **record_material,
                "previous_record_hash": (
                    previous_record_hash
                ),
                "record_hash": current_hash,
            }

            self._state["sequence"] = sequence
            self._state[
                "last_record_hash"
            ] = current_hash

            self._state["records"].append(
                record
            )

            self._append_event(record)
            self._atomic_write_state()

            return ProvenanceRecord(
                provenance_id=record[
                    "provenance_id"
                ],
                record_type=record[
                    "record_type"
                ],
                sequence=record["sequence"],
                created_at_utc=record[
                    "created_at_utc"
                ],
                investigation_id=record[
                    "investigation_id"
                ],
                evidence_id=record[
                    "evidence_id"
                ],
                execution_id=record[
                    "execution_id"
                ],
                previous_record_hash=record[
                    "previous_record_hash"
                ],
                record_hash=record[
                    "record_hash"
                ],
                execution_fingerprint=record[
                    "execution_fingerprint"
                ],
                status=record["status"],
                integrity_state=record[
                    "integrity_state"
                ],
            )

    # --------------------------------------------------------
    # Artifacts
    # --------------------------------------------------------

    def register_artifact(
        self,
        *,
        artifact_type: str,
        payload: dict[str, Any],
        parent_artifact_ids: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
        finding_ids: Iterable[str] | None = None,
    ) -> ArtifactRef:
        with self._lock:
            artifact_type = _validate_text(
                artifact_type,
                field_name="artifact_type",
                max_chars=128,
            )

            if not isinstance(payload, dict):
                raise ProvenanceValidationError(
                    "artifact payload must be a dictionary."
                )

            parent_artifact_ids = _clean_refs(
                parent_artifact_ids,
                field_name="parent_artifact_ids",
            )

            finding_ids = list(
                _clean_refs(
                    finding_ids,
                    field_name="finding_ids",
                )
            )

            # Preserve the legacy semantic contract: a finding artifact
            # carrying an explicit finding_id establishes a binding even
            # when legacy callers do not pass finding_ids.
            if artifact_type == "finding":
                payload_finding_id = payload.get(
                    "finding_id"
                )

                if (
                    isinstance(payload_finding_id, str)
                    and payload_finding_id.strip()
                    and payload_finding_id.strip()
                    not in finding_ids
                ):
                    finding_ids.append(
                        payload_finding_id.strip()
                    )

            finding_ids = _clean_refs(
                finding_ids,
                field_name="finding_ids",
            )

            for parent_id in parent_artifact_ids:
                if parent_id not in self._state["artifacts"]:
                    raise ProvenanceValidationError(
                        f"Unknown parent artifact: {parent_id}"
                    )

            metadata = _clean_metadata(
                metadata,
                field_name="metadata",
            )

            fingerprint = artifact_fingerprint(
                artifact_type=artifact_type,
                artifact_payload=payload,
            )

            artifact_id = (
                "ART-"
                + fingerprint[:24].upper()
            )

            existing = self._state[
                "artifacts"
            ].get(artifact_id)

            if existing is not None:
                if (
                    existing[
                        "fingerprint_sha256"
                    ] != fingerprint
                    or existing[
                        "artifact_type"
                    ] != artifact_type
                    or tuple(
                        existing.get(
                            "finding_ids",
                            [],
                        )
                    ) != finding_ids
                ):
                    raise ProvenanceConflictError(
                        f"Artifact identity collision: {artifact_id}"
                    )

                return ArtifactRef(
                    artifact_id=artifact_id,
                    artifact_type=existing[
                        "artifact_type"
                    ],
                    fingerprint_sha256=existing[
                        "fingerprint_sha256"
                    ],
                    parent_artifact_ids=tuple(
                        existing[
                            "parent_artifact_ids"
                        ]
                    ),
                    metadata=dict(
                        existing["metadata"]
                    ),
                )

            artifact = ArtifactRef(
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                fingerprint_sha256=fingerprint,
                parent_artifact_ids=parent_artifact_ids,
                metadata=metadata,
            )

            stored = artifact.to_dict()
            stored["finding_ids"] = list(
                finding_ids
            )

            self._state["artifacts"][
                artifact_id
            ] = stored

            for finding_id in finding_ids:
                bindings = self._state[
                    "finding_bindings"
                ].setdefault(
                    finding_id,
                    [],
                )

                if artifact_id not in bindings:
                    bindings.append(
                        artifact_id
                    )
                    bindings.sort()

            self._validate_state(
                self._state
            )
            self._atomic_write_state()

            return artifact

    # --------------------------------------------------------
    # Dependencies
    # --------------------------------------------------------

    def register_dependency(
        self,
        dependency: DependencySnapshot,
    ) -> str:
        with self._lock:
            if len(self._state["dependencies"]) >= MAX_DEPENDENCY_COUNT:
                raise ProvenanceValidationError(
                    "Dependency limit exceeded."
                )

            dependency_id = _validate_id(
                dependency.dependency_id,
                "dependency_id",
            )

            request_fp = dependency.request_fingerprint
            response_fp = dependency.response_fingerprint

            if request_fp is not None:
                request_fp = _validate_sha256(
                    request_fp,
                    "request_fingerprint",
                )

            if response_fp is not None:
                response_fp = _validate_sha256(
                    response_fp,
                    "response_fingerprint",
                )

            payload = dependency.to_dict()

            payload["dependency_id"] = dependency_id
            payload["request_fingerprint"] = request_fp
            payload["response_fingerprint"] = response_fp

            existing = self._state["dependencies"].get(
                dependency_id
            )

            if existing is not None:
                existing_canonical = dict(existing)
                payload_canonical = dict(payload)

                if existing_canonical != payload_canonical:
                    raise ProvenanceConflictError(
                        f"Dependency conflict: {dependency_id}"
                    )

                return dependency_id

            self._state["dependencies"][dependency_id] = payload
            self._atomic_write_state()

            return dependency_id

    # --------------------------------------------------------
    # Replay / dependency drift
    # --------------------------------------------------------

    def prepare_replay(
        self,
        execution_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            execution_id = _validate_id(
                execution_id,
                "execution_id",
            )

            execution = self._state["executions"].get(
                execution_id
            )

            if execution is None:
                raise ProvenanceValidationError(
                    f"Unknown execution: {execution_id}"
                )

            determinism = execution[
                "determinism_class"
            ]

            if determinism in {
                NON_REPLAYABLE,
                NON_DETERMINISTIC,
            }:
                execution["status"] = STATUS_NON_REPLAYABLE
                self._atomic_write_state()

                return {
                    "execution_id": execution_id,
                    "ready": False,
                    "state": STATUS_NON_REPLAYABLE,
                    "reason": (
                        f"Execution determinism class "
                        f"is {determinism}."
                    ),
                }

            missing_dependencies = [
                dep_id
                for dep_id in execution[
                    "dependency_ids"
                ]
                if dep_id not in self._state["dependencies"]
            ]

            if missing_dependencies:
                return {
                    "execution_id": execution_id,
                    "ready": False,
                    "state": STATUS_NON_REPLAYABLE,
                    "missing_dependencies": missing_dependencies,
                }

            return {
                "execution_id": execution_id,
                "ready": True,
                "state": STATUS_REPLAY_READY,
                "evidence_id": execution["evidence_id"],
                "input_sha256": execution["input_sha256"],
                "engine_id": execution["engine_id"],
                "engine_version": execution["engine_version"],
                "analysis_version": execution["analysis_version"],
                "ruleset_fingerprint": execution[
                    "ruleset_fingerprint"
                ],
                "configuration_fingerprint": execution[
                    "configuration_fingerprint"
                ],
                "environment_fingerprint": execution[
                    "environment_fingerprint"
                ],
                "dependency_ids": list(
                    execution["dependency_ids"]
                ),
                "output_artifact_ids": list(
                    execution["output_artifact_ids"]
                ),
                "finding_ids": list(
                    execution["finding_ids"]
                ),
            }

    def compare_replay(
        self,
        execution_id: str,
        *,
        replay_execution_fingerprint: str | None,
        dependency_fingerprints: dict[str, str] | None = None,
        replay_output_artifact_ids: Iterable[str] | None = None,
    ) -> ReplayComparison:
        with self._lock:
            execution_id = _validate_id(
                execution_id,
                "execution_id",
            )

            execution = self._state[
                "executions"
            ].get(execution_id)

            if execution is None:
                raise ProvenanceValidationError(
                    f"Unknown execution: {execution_id}"
                )

            original_fp = execution[
                "execution_fingerprint"
            ]

            drift: list[str] = []
            issues: list[str] = []

            dependency_fingerprints = (
                dependency_fingerprints or {}
            )

            for dep_id in execution[
                "dependency_ids"
            ]:
                original = self._state[
                    "dependencies"
                ].get(dep_id)

                if original is None:
                    issues.append(
                        f"Missing dependency snapshot: {dep_id}"
                    )
                    continue

                original_fp_value = (
                    original.get(
                        "response_fingerprint"
                    )
                    or original.get(
                        "request_fingerprint"
                    )
                )

                replay_fp = dependency_fingerprints.get(
                    dep_id
                )

                if (
                    original_fp_value is not None
                    and replay_fp is not None
                    and original_fp_value.lower()
                    != str(replay_fp).lower()
                ):
                    drift.append(dep_id)

            replay_supplied = (
                replay_output_artifact_ids
                is not None
            )

            replay_outputs = _clean_refs(
                replay_output_artifact_ids,
                field_name="replay_output_artifact_ids",
            )

            original_outputs = tuple(
                execution[
                    "output_artifact_ids"
                ]
            )

            def artifact_signature(
                artifact_id: str,
            ):
                artifact = self._state[
                    "artifacts"
                ].get(artifact_id)

                if artifact is None:
                    return (
                        "UNKNOWN",
                        artifact_id,
                    )

                return (
                    artifact.get(
                        "artifact_type"
                    ),
                    artifact.get(
                        "fingerprint_sha256"
                    ),
                    tuple(
                        sorted(
                            artifact.get(
                                "parent_artifact_ids",
                                [],
                            )
                        )
                    ),
                    tuple(
                        sorted(
                            artifact.get(
                                "finding_ids",
                                [],
                            )
                        )
                    ),
                )

            output_mismatches: tuple[str, ...] = ()

            if replay_supplied:
                original_sig = sorted(
                    artifact_signature(
                        artifact_id
                    )
                    for artifact_id
                    in original_outputs
                )

                replay_sig = sorted(
                    artifact_signature(
                        artifact_id
                    )
                    for artifact_id
                    in replay_outputs
                )

                if original_sig != replay_sig:
                    output_mismatches = tuple(
                        sorted(
                            {
                                repr(item)
                                for item in (
                                    set(original_sig)
                                    ^ set(replay_sig)
                                )
                            }
                        )
                    )

            if issues:
                state = STATUS_NON_REPLAYABLE

            elif drift:
                state = STATUS_DEPENDENCY_DRIFT

            elif replay_execution_fingerprint is None:
                state = STATUS_MISMATCHED
                issues.append(
                    "Replay fingerprint was not supplied."
                )

            elif output_mismatches:
                state = STATUS_MISMATCHED
                issues.append(
                    "Replay output artifacts differ by "
                    "type, fingerprint, parents, or finding lineage."
                )

            elif (
                replay_execution_fingerprint.lower()
                == original_fp.lower()
            ):
                state = STATUS_MATCHED

            else:
                state = STATUS_MISMATCHED

            # Observational only: deliberately no execution mutation
            # and no persistence.
            return ReplayComparison(
                execution_id=execution_id,
                original_execution_fingerprint=original_fp,
                replay_execution_fingerprint=(
                    replay_execution_fingerprint
                ),
                state=state,
                dependency_drift=tuple(
                    sorted(drift)
                ),
                output_mismatches=output_mismatches,
                issues=tuple(issues),
            )

    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    def verify_chain(self) -> ProvenanceVerification:
        with self._lock:
            records = self._state["records"]

            issues: list[str] = list(
                self._journal_integrity_issues
            )

            chain_valid = not bool(
                self._journal_integrity_issues
            )

            previous_hash = None

            for expected_sequence, record in enumerate(
                records,
                start=1,
            ):
                provenance_id = record.get(
                    "provenance_id"
                )

                if record.get(
                    "sequence"
                ) != expected_sequence:
                    chain_valid = False
                    issues.append(
                        "Sequence mismatch at record "
                        f"{provenance_id}"
                    )

                if record.get(
                    "previous_record_hash"
                ) != previous_hash:
                    chain_valid = False
                    issues.append(
                        "Previous-record hash mismatch at "
                        f"{provenance_id}"
                    )

                # integrity_state remains INCLUDED in the
                # authenticated material. Verification is
                # strictly read-only and NEVER mutates it.
                hash_schema_version = record.get(
                    "record_hash_schema_version",
                    1,
                )

                if hash_schema_version != 1:
                    chain_valid = False
                    issues.append(
                        "Unsupported record hash schema at "
                        f"{provenance_id}"
                    )

                material = {
                    key: value
                    for key, value in record.items()
                    if key not in {
                        "record_hash",
                        "previous_record_hash",
                    }
                }

                recalculated = record_hash(
                    record_without_hash=material,
                    previous_record_hash=record.get(
                        "previous_record_hash"
                    ),
                )

                if recalculated != record.get(
                    "record_hash"
                ):
                    chain_valid = False
                    issues.append(
                        "Record hash mismatch at "
                        f"{provenance_id}"
                    )

                previous_hash = record.get(
                    "record_hash"
                )

            if self._state[
                "last_record_hash"
            ] != previous_hash:
                chain_valid = False
                issues.append(
                    "State last_record_hash mismatch."
                )

            (
                graph_valid,
                orphan_count,
                conflict_count,
            ) = self._verify_graph()

            valid = (
                chain_valid
                and graph_valid
            )

            return ProvenanceVerification(
                valid=valid,
                chain_valid=chain_valid,
                graph_valid=graph_valid,
                record_count=len(records),
                verified_count=(
                    len(records)
                    if valid
                    else max(
                        0,
                        len(records) - len(issues),
                    )
                ),
                orphan_count=orphan_count,
                conflict_count=conflict_count,
                issues=tuple(issues),
            )

    def _verify_graph(
        self,
    ) -> tuple[bool, int, int]:
        orphan_count = 0
        conflict_count = 0
        valid = True

        execution_ids = set(
            self._state["executions"]
        )

        artifact_ids = set(
            self._state["artifacts"]
        )

        dependency_ids = set(
            self._state["dependencies"]
        )

        # ----------------------------------------------------
        # Execution integrity
        # ----------------------------------------------------

        for execution_id, execution in self._state[
            "executions"
        ].items():

            if execution_id != execution.get(
                "execution_id"
            ):
                conflict_count += 1
                valid = False

            if not execution.get(
                "investigation_id"
            ):
                conflict_count += 1
                valid = False

            if not execution.get(
                "evidence_id"
            ):
                conflict_count += 1
                valid = False

            for artifact_id in (
                execution.get(
                    "parent_artifact_ids",
                    [],
                )
                + execution.get(
                    "output_artifact_ids",
                    [],
                )
            ):
                if artifact_id not in artifact_ids:
                    orphan_count += 1
                    valid = False

            for dependency_id in execution.get(
                "dependency_ids",
                [],
            ):
                if dependency_id not in dependency_ids:
                    orphan_count += 1
                    valid = False

        # ----------------------------------------------------
        # Finding ↔ artifact lineage integrity
        # ----------------------------------------------------

        finding_bindings = self._state.get(
            "finding_bindings",
            {},
        )

        for finding_id, bound_artifacts in (
            finding_bindings.items()
        ):
            for artifact_id in bound_artifacts:
                artifact = self._state[
                    "artifacts"
                ].get(artifact_id)

                if artifact is None:
                    orphan_count += 1
                    valid = False
                    continue

                if finding_id not in artifact.get(
                    "finding_ids",
                    [],
                ):
                    conflict_count += 1
                    valid = False

        for execution in self._state[
            "executions"
        ].values():
            for finding_id in execution.get(
                "finding_ids",
                [],
            ):
                bound = finding_bindings.get(
                    finding_id,
                    [],
                )

                lineage = execution.get(
                    "finding_lineage",
                    {},
                ).get(
                    finding_id,
                    {},
                )

                declared_state = lineage.get(
                    "binding_state"
                )

                if bound:
                    if declared_state != "BOUND":
                        conflict_count += 1
                        valid = False

                    if not any(
                        artifact_id in execution.get(
                            "output_artifact_ids",
                            [],
                        )
                        for artifact_id in bound
                    ):
                        conflict_count += 1
                        valid = False

                elif declared_state not in {
                    None,
                    "UNBOUND_LEGACY",
                }:
                    conflict_count += 1
                    valid = False

        # ----------------------------------------------------
        # Artifact integrity
        # ----------------------------------------------------

        for artifact_id, artifact in self._state[
            "artifacts"
        ].items():

            if artifact_id != artifact.get(
                "artifact_id"
            ):
                conflict_count += 1
                valid = False

            for parent_id in artifact.get(
                "parent_artifact_ids",
                [],
            ):
                if parent_id not in artifact_ids:
                    orphan_count += 1
                    valid = False

        # ----------------------------------------------------
        # Provenance record → execution binding
        # ----------------------------------------------------

        for record in self._state[
            "records"
        ]:

            record_execution_id = record.get(
                "execution_id"
            )

            if record_execution_id not in execution_ids:
                orphan_count += 1
                valid = False
                continue

            execution = self._state[
                "executions"
            ][record_execution_id]

            if record.get(
                "evidence_id"
            ) != execution.get(
                "evidence_id"
            ):
                conflict_count += 1
                valid = False

            if record.get(
                "investigation_id"
            ) != execution.get(
                "investigation_id"
            ):
                conflict_count += 1
                valid = False

            if record.get(
                "execution_fingerprint"
            ) != execution.get(
                "execution_fingerprint"
            ):
                conflict_count += 1
                valid = False

        return (
            valid,
            orphan_count,
            conflict_count,
        )

    # --------------------------------------------------------
    # Query / export
    # --------------------------------------------------------

    def get_execution(
        self,
        execution_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            execution_id = _validate_id(
                execution_id,
                "execution_id",
            )

            execution = self._state["executions"].get(
                execution_id
            )

            if execution is None:
                raise ProvenanceValidationError(
                    f"Unknown execution: {execution_id}"
                )

            return json.loads(
                json.dumps(
                    execution,
                    ensure_ascii=False,
                )
            )

    def get_artifact(
        self,
        artifact_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            artifact_id = _validate_id(
                artifact_id,
                "artifact_id",
            )

            artifact = self._state["artifacts"].get(
                artifact_id
            )

            if artifact is None:
                raise ProvenanceValidationError(
                    f"Unknown artifact: {artifact_id}"
                )

            return json.loads(
                json.dumps(
                    artifact,
                    ensure_ascii=False,
                )
            )

    def list_records(
        self,
        *,
        investigation_id: str | None = None,
        evidence_id: str | None = None,
        execution_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            result = []

            for record in self._state["records"]:
                if (
                    investigation_id is not None
                    and record[
                        "investigation_id"
                    ]
                    != investigation_id
                ):
                    continue

                if (
                    evidence_id is not None
                    and record["evidence_id"]
                    != evidence_id
                ):
                    continue

                if (
                    execution_id is not None
                    and record["execution_id"]
                    != execution_id
                ):
                    continue

                result.append(
                    json.loads(
                        json.dumps(
                            record,
                            ensure_ascii=False,
                        )
                    )
                )

            return result

    def export_execution_bundle(
        self,
        execution_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            execution = self.get_execution(
                execution_id
            )

            artifact_ids = set(
                execution["parent_artifact_ids"]
                + execution["output_artifact_ids"]
            )

            artifacts = [
                self.get_artifact(artifact_id)
                for artifact_id in sorted(
                    artifact_ids
                )
            ]

            dependencies = [
                dict(
                    self._state["dependencies"][
                        dep_id
                    ]
                )
                for dep_id in execution[
                    "dependency_ids"
                ]
                if dep_id in self._state[
                    "dependencies"
                ]
            ]

            records = self.list_records(
                execution_id=execution_id
            )

            finding_ids = execution.get(
                "finding_ids",
                [],
            )

            finding_bindings = {
                finding_id: list(
                    self._state.get(
                        "finding_bindings",
                        {},
                    ).get(
                        finding_id,
                        [],
                    )
                )
                for finding_id in finding_ids
            }

            return {
                "schema_version": SCHEMA_VERSION,
                "execution": execution,
                "artifacts": artifacts,
                "dependencies": dependencies,
                "finding_bindings": finding_bindings,
                "records": records,
            }
