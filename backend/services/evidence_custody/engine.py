from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.attachment_intelligence.hashing import (
    calculate_hashes_from_bytes,
)

from .models import (
    CustodyEvent,
    EvidenceHashSet,
    EvidenceManifest,
    EvidenceRecord,
    VerificationResult,
)

from .rules import (
    ANALYSIS_NAME,
    ANALYSIS_VERSION,
    ALLOWED_TRANSITIONS,
    EVENT_TO_STATE,
    MAX_ACTOR_CHARS,
    MAX_CASE_ID_CHARS,
    MAX_DESTINATION_CHARS,
    MAX_EVIDENCE_ID_CHARS,
    MAX_EVIDENCE_RECORDS,
    MAX_EVIDENCE_SIZE_BYTES,
    MAX_EVENTS_PER_EVIDENCE,
    MAX_EXPORT_ITEMS,
    MAX_MANIFEST_ITEMS,
    MAX_METADATA_KEYS,
    MAX_PATH_CHARS,
    MAX_PURPOSE_CHARS,
    MAX_REASON_CHARS,
    MAX_SOURCE_CHARS,
    MAX_PERSISTED_EVENT_BYTES,
    MAX_PERSISTED_STATE_BYTES,
    STATE_SCHEMA_VERSION,
    CustodyEventType,
    EvidenceState,
)


class EvidenceCustodyError(Exception):
    pass


class EvidenceNotFoundError(EvidenceCustodyError):
    pass


class EvidenceIntegrityError(EvidenceCustodyError):
    pass


class InvalidCustodyTransitionError(EvidenceCustodyError):
    pass




class _CrossProcessStorageLock:
    """
    Advisory filesystem lock used together with the in-process
    RLock. It serializes cooperating processes sharing the same
    custody ledger.
    """

    def __init__(self, lock_path: Path):
        self.lock_path = Path(lock_path)
        self.handle = None

    def __enter__(self):
        self.lock_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.handle = open(
            self.lock_path,
            "a+b",
        )

        if os.name == "nt":
            import msvcrt

            self.handle.seek(0)

            msvcrt.locking(
                self.handle.fileno(),
                msvcrt.LK_LOCK,
                1,
            )

        else:
            import fcntl

            fcntl.flock(
                self.handle.fileno(),
                fcntl.LOCK_EX,
            )

        return self

    def __exit__(
        self,
        exc_type,
        exc,
        tb,
    ):

        if self.handle is None:
            return False

        try:

            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)

                try:
                    msvcrt.locking(
                        self.handle.fileno(),
                        msvcrt.LK_UNLCK,
                        1,
                    )
                except OSError:
                    pass

            else:
                import fcntl

                fcntl.flock(
                    self.handle.fileno(),
                    fcntl.LOCK_UN,
                )

        finally:

            self.handle.close()
            self.handle = None

        return False


def _validate_storage_evidence_id(
    evidence_id: str,
) -> str:
    """
    Evidence IDs are identifiers, never filesystem paths.

    Reject path traversal, Windows drive syntax, UNC paths,
    separators, whitespace tricks, and unsupported characters.
    """

    if not isinstance(evidence_id, str):
        raise ValueError(
            "evidence_id must be a string."
        )

    if not evidence_id:
        raise ValueError(
            "evidence_id must not be empty."
        )

    if len(evidence_id) > MAX_EVIDENCE_ID_CHARS:
        raise ValueError(
            "evidence_id exceeds configured limit."
        )

    if evidence_id in {
        ".",
        "..",
    }:
        raise ValueError(
            "evidence_id cannot be '.' or '..'."
        )

    if "/" in evidence_id:
        raise ValueError(
            "evidence_id cannot contain '/'."
        )

    if "\\" in evidence_id:
        raise ValueError(
            "evidence_id cannot contain '\\'."
        )

    if ":" in evidence_id:
        raise ValueError(
            "evidence_id cannot contain ':'."
        )

    if evidence_id != evidence_id.strip():
        raise ValueError(
            "evidence_id cannot contain surrounding whitespace."
        )

    if not re.fullmatch(
        r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        evidence_id,
    ):
        raise ValueError(
            "evidence_id contains unsupported characters."
        )

    return evidence_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    )


def _clamp(value: str | None, limit: int) -> str | None:
    if value is None:
        return None

    value = str(value)

    if len(value) <= limit:
        return value

    return value[:limit]


def _require_nonempty(
    value: str,
    field_name: str,
    limit: int,
) -> str:
    value = str(value or "").strip()

    if not value:
        raise ValueError(
            f"{field_name} must not be empty."
        )

    if len(value) > limit:
        raise ValueError(
            f"{field_name} exceeds configured limit."
        )

    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def _sha512_text(value: str) -> str:
    return hashlib.sha512(
        value.encode("utf-8")
    ).hexdigest()


def _safe_id(prefix: str) -> str:
    return (
        f"{prefix}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}_"
        f"{secrets.token_hex(6)}"
    )


def _core_record_payload(
    record: EvidenceRecord,
) -> dict[str, Any]:
    return {
        "evidence_id": record.evidence_id,
        "case_id": record.case_id,
        "investigation_id": record.investigation_id,
        "artifact_type": record.artifact_type,
        "original_filename": record.original_filename,
        "media_type": record.media_type,
        "source": record.source,
        "acquisition_timestamp_utc": record.acquisition_timestamp_utc,
        "collector": record.collector,
        "acquisition_method": record.acquisition_method,
        "size_bytes": record.size_bytes,
        "hashes": record.hashes.to_dict(),
        "preservation_path": record.preservation_path,
        "preservation_verified": record.preservation_verified,
        "created_timestamp_utc": record.created_timestamp_utc,
        "core_metadata": record.core_metadata,
    }


def _seal_hash(
    record: EvidenceRecord,
) -> str:
    return _sha512_text(
        _canonical_json(
            _core_record_payload(record)
        )
    )


def _event_hash_payload(
    *,
    event_id: str,
    evidence_id: str,
    sequence: int,
    event_type: str,
    timestamp_utc: str,
    actor: str,
    purpose: str,
    source: str | None,
    destination: str | None,
    reason: str | None,
    previous_event_hash: str | None,
    resulting_state: str,
    evidence_sha256: str,
    metadata: dict[str, Any],
) -> str:
    payload = {
        "event_id": event_id,
        "evidence_id": evidence_id,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp_utc": timestamp_utc,
        "actor": actor,
        "purpose": purpose,
        "source": source,
        "destination": destination,
        "reason": reason,
        "previous_event_hash": previous_event_hash,
        "resulting_state": resulting_state,
        "evidence_sha256": evidence_sha256,
        "metadata": metadata,
    }

    return _sha512_text(
        _canonical_json(payload)
    )


def _ensure_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    if metadata is None:
        return {}

    if not isinstance(metadata, dict):
        raise ValueError(
            "metadata must be a dictionary."
        )

    if len(metadata) > MAX_METADATA_KEYS:
        raise ValueError(
            "metadata exceeds configured key limit."
        )

    result = {}

    for key, value in metadata.items():
        key = str(key)

        if len(key) > 256:
            raise ValueError(
                "metadata key exceeds configured limit."
            )

        # Make metadata JSON-safe without allowing arbitrary
        # mutable runtime objects into the ledger.
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"metadata value for '{key}' is not JSON serializable."
            ) from exc

        result[key] = value

    return result


def _normalize_hashset(
    hashes: dict[str, str],
) -> EvidenceHashSet:
    sha256 = str(
        hashes.get("sha256", "")
    ).lower()

    sha512 = str(
        hashes.get("sha512", "")
    ).lower()

    if len(sha256) != 64:
        raise ValueError(
            "Invalid SHA-256 hash."
        )

    if len(sha512) != 128:
        raise ValueError(
            "Invalid SHA-512 hash."
        )

    int(sha256, 16)
    int(sha512, 16)

    return EvidenceHashSet(
        sha256=sha256,
        sha512=sha512,
    )


def preserve_evidence_bytes(
    data: bytes,
    vault_dir: str | Path,
    evidence_id: str,
) -> tuple[str, EvidenceHashSet]:
    """
    Write a content-addressed preservation copy.

    The bytes are never modified by this function.
    The returned path is verified against the original hashes
    before the function reports success.
    """
    if not isinstance(
        data,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError(
            "data must be bytes-like."
        )

    raw = bytes(data)

    if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
        raise ValueError(
            "Evidence exceeds maximum supported preservation size."
        )

    evidence_id = _validate_storage_evidence_id(
        evidence_id
    )

    hashes = calculate_hashes_from_bytes(
        raw,
        algorithms=("sha256", "sha512"),
    )

    hashset = _normalize_hashset(
        hashes
    )

    vault = Path(vault_dir)

    if len(str(vault)) > MAX_PATH_CHARS:
        raise ValueError(
            "vault_dir path is too long."
        )

    evidence_root = vault / evidence_id
    evidence_root.mkdir(
        parents=True,
        exist_ok=False,
    )

    final_path = (
        evidence_root
        / f"{hashset.sha256}.evidence"
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=".preserve-",
        dir=str(evidence_root),
    )

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

        temp_path = Path(temp_name)

        os.replace(
            temp_path,
            final_path,
        )

        with open(final_path, "rb") as handle:
            preserved = handle.read()

        preserved_hashes = _normalize_hashset(
            calculate_hashes_from_bytes(
                preserved,
                algorithms=("sha256", "sha512"),
            )
        )

        if preserved_hashes != hashset:
            try:
                final_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            raise EvidenceIntegrityError(
                "Preservation copy hash verification failed."
            )

        try:
            final_path.chmod(0o444)
        except OSError:
            pass

        return str(final_path), hashset

    except Exception:
        try:
            Path(temp_name).unlink(
                missing_ok=True
            )
        except OSError:
            pass

        try:
            if evidence_root.exists():
                evidence_root.rmdir()
        except OSError:
            pass

        raise


class EvidenceCustodyLedger:
    """
    Append-only in-process evidence and custody ledger.

    The ledger is intentionally independent from:
    - attachment hashing
    - case management
    - investigation management
    - forensic detection engines

    It consumes their evidence and provides preservation,
    provenance and chain-of-custody state.
    """

    def __init__(
        self,
        *,
        ledger_path: str | Path | None = None,
    ) -> None:
        self._thread_lock = threading.RLock()

        self._records: dict[str, EvidenceRecord] = {}
        self._events: dict[str, list[CustodyEvent]] = {}

        # Independent chain commitment for each evidence item.
        # This allows verification to detect event deletion,
        # insertion, duplication and terminal-event replacement,
        # not merely mutation of the events that remain.
        self._anchors: dict[str, dict[str, object]] = {}

        self.ledger_path = (
            Path(ledger_path)
            if ledger_path is not None
            else None
        )

        self._process_lock_path = (
            Path(str(self.ledger_path) + ".lock")
            if self.ledger_path is not None
            else None
        )

        self._state_path = None

        if self.ledger_path is not None:
            if len(str(self.ledger_path)) > MAX_PATH_CHARS:
                raise ValueError(
                    "ledger_path is too long."
                )

            self.ledger_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self._state_path = Path(
                str(self.ledger_path)
                + ".state.json"
            )

            self._recover_from_disk()

    @contextmanager
    def _storage_guard(self):
        """
        Thread-safe and cooperating-process-safe storage guard.
        """

        self._thread_lock.acquire()

        process_lock = None

        try:

            if self._process_lock_path is not None:
                process_lock = _CrossProcessStorageLock(
                    self._process_lock_path
                )
                process_lock.__enter__()

            yield self

        finally:

            if process_lock is not None:
                process_lock.__exit__(
                    None,
                    None,
                    None,
                )

            self._thread_lock.release()


    def _state_body(self) -> dict[str, object]:
        return {
            "schema": "evidence_custody_state",
            "schema_version": STATE_SCHEMA_VERSION,
            "records": {
                evidence_id: record.to_dict()
                for evidence_id, record
                in self._records.items()
            },
            "events": {
                evidence_id: [
                    event.to_dict()
                    for event in events
                ]
                for evidence_id, events
                in self._events.items()
            },
            "anchors": {
                evidence_id: dict(anchor)
                for evidence_id, anchor
                in self._anchors.items()
            },
        }

    def _persist_state(
        self,
    ) -> None:
        if self._state_path is None:
            return

        body = self._state_body()

        canonical = _canonical_json(
            body
        )

        integrity = _sha512_text(
            canonical
        )

        payload = {
            **body,
            "state_sha512": integrity,
        }

        serialized = (
            _canonical_json(payload)
            + "\n"
        )

        encoded_size = len(
            serialized.encode("utf-8")
        )

        if encoded_size > MAX_PERSISTED_STATE_BYTES:
            raise EvidenceCustodyError(
                "Durable state snapshot exceeds configured size limit."
            )

        fd, temp_name = tempfile.mkstemp(
            prefix=".evidence-state-",
            dir=str(self._state_path.parent),
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                temp_name,
                self._state_path,
            )

        except Exception:
            try:
                Path(temp_name).unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            raise

    @staticmethod
    def _record_from_dict(
        payload: dict[str, object],
    ) -> EvidenceRecord:
        hashes = _normalize_hashset(
            payload.get("hashes", {})
        )

        return EvidenceRecord(
            evidence_id=str(
                payload["evidence_id"]
            ),
            case_id=payload.get(
                "case_id"
            ),
            investigation_id=payload.get(
                "investigation_id"
            ),
            artifact_type=str(
                payload["artifact_type"]
            ),
            original_filename=payload.get(
                "original_filename"
            ),
            media_type=payload.get(
                "media_type"
            ),
            source=str(
                payload["source"]
            ),
            acquisition_timestamp_utc=str(
                payload[
                    "acquisition_timestamp_utc"
                ]
            ),
            collector=str(
                payload["collector"]
            ),
            acquisition_method=str(
                payload["acquisition_method"]
            ),
            size_bytes=int(
                payload["size_bytes"]
            ),
            hashes=hashes,
            preservation_path=payload.get(
                "preservation_path"
            ),
            preservation_verified=bool(
                payload.get(
                    "preservation_verified",
                    False,
                )
            ),
            state=str(
                payload.get(
                    "state",
                    "ACQUIRED",
                )
            ),
            sealed=bool(
                payload.get(
                    "sealed",
                    False,
                )
            ),
            seal_hash=payload.get(
                "seal_hash"
            ),
            created_timestamp_utc=str(
                payload.get(
                    "created_timestamp_utc",
                    "",
                )
            ),
            updated_timestamp_utc=str(
                payload.get(
                    "updated_timestamp_utc",
                    "",
                )
            ),
            custody_event_ids=[
                str(item)
                for item in payload.get(
                    "custody_event_ids",
                    [],
                )
            ],
            core_metadata=dict(
                payload.get(
                    "core_metadata",
                    {},
                )
            ),
        )

    @staticmethod
    def _event_from_dict(
        payload: dict[str, object],
    ) -> CustodyEvent:
        return CustodyEvent(
            event_id=str(
                payload["event_id"]
            ),
            evidence_id=str(
                payload["evidence_id"]
            ),
            sequence=int(
                payload["sequence"]
            ),
            event_type=str(
                payload["event_type"]
            ),
            timestamp_utc=str(
                payload["timestamp_utc"]
            ),
            actor=str(
                payload["actor"]
            ),
            purpose=str(
                payload["purpose"]
            ),
            source=payload.get(
                "source"
            ),
            destination=payload.get(
                "destination"
            ),
            reason=payload.get(
                "reason"
            ),
            previous_event_hash=payload.get(
                "previous_event_hash"
            ),
            event_hash=str(
                payload["event_hash"]
            ),
            resulting_state=str(
                payload["resulting_state"]
            ),
            evidence_sha256=str(
                payload["evidence_sha256"]
            ),
            metadata=dict(
                payload.get(
                    "metadata",
                    {},
                )
            ),
        )

    def _read_persisted_state(
        self,
    ) -> None:
        if self._state_path is None:
            return

        if not self._state_path.exists():
            return

        raw = self._state_path.read_bytes()

        if len(raw) > MAX_PERSISTED_STATE_BYTES:
            raise EvidenceIntegrityError(
                "Durable state snapshot exceeds configured limit."
            )

        try:
            payload = json.loads(
                raw.decode("utf-8")
            )
        except Exception as exc:
            raise EvidenceIntegrityError(
                "Durable state snapshot is not valid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise EvidenceIntegrityError(
                "Durable state snapshot must be an object."
            )

        if payload.get("schema") != (
            "evidence_custody_state"
        ):
            raise EvidenceIntegrityError(
                "Unsupported evidence custody state schema."
            )

        if payload.get(
            "schema_version"
        ) != STATE_SCHEMA_VERSION:
            raise EvidenceIntegrityError(
                "Unsupported evidence custody state version."
            )

        stored_integrity = payload.get(
            "state_sha512"
        )

        if not isinstance(
            stored_integrity,
            str,
        ):
            raise EvidenceIntegrityError(
                "Durable state integrity commitment is missing."
            )

        body = dict(payload)
        del body["state_sha512"]

        calculated_integrity = _sha512_text(
            _canonical_json(body)
        )

        if calculated_integrity != stored_integrity:
            raise EvidenceIntegrityError(
                "Durable state snapshot integrity check failed."
            )

        raw_records = body.get(
            "records",
            {},
        )

        raw_events = body.get(
            "events",
            {},
        )

        raw_anchors = body.get(
            "anchors",
            {},
        )

        if not isinstance(
            raw_records,
            dict,
        ) or not isinstance(
            raw_events,
            dict,
        ) or not isinstance(
            raw_anchors,
            dict,
        ):
            raise EvidenceIntegrityError(
                "Durable state contains invalid registry structures."
            )

        if len(raw_records) > MAX_EVIDENCE_RECORDS:
            raise EvidenceIntegrityError(
                "Durable state contains too many evidence records."
            )

        self._records = {
            str(evidence_id): self._record_from_dict(
                record_payload
            )
            for evidence_id, record_payload
            in raw_records.items()
        }

        self._events = {}

        for evidence_id, event_payloads in raw_events.items():
            if evidence_id not in self._records:
                raise EvidenceIntegrityError(
                    "Durable state contains events for unknown evidence."
                )

            if not isinstance(
                event_payloads,
                list,
            ):
                raise EvidenceIntegrityError(
                    "Evidence event collection is invalid."
                )

            if len(event_payloads) > MAX_EVENTS_PER_EVIDENCE:
                raise EvidenceIntegrityError(
                    "Evidence event collection exceeds configured limit."
                )

            parsed = []

            for item in event_payloads:
                if not isinstance(
                    item,
                    dict,
                ):
                    raise EvidenceIntegrityError(
                        "Custody event payload is invalid."
                    )

                event = self._event_from_dict(
                    item
                )

                if event.evidence_id != str(
                    evidence_id
                ):
                    raise EvidenceIntegrityError(
                        "Custody event evidence identity mismatch."
                    )

                parsed.append(event)

            self._events[str(evidence_id)] = parsed

        for evidence_id in self._records:
            self._events.setdefault(
                evidence_id,
                [],
            )

        self._anchors = {}

        for evidence_id, anchor in raw_anchors.items():
            if evidence_id not in self._records:
                raise EvidenceIntegrityError(
                    "Durable state contains anchor for unknown evidence."
                )

            if not isinstance(
                anchor,
                dict,
            ):
                raise EvidenceIntegrityError(
                    "Evidence chain anchor is invalid."
                )

            self._anchors[str(evidence_id)] = dict(
                anchor
            )

        for evidence_id, record in self._records.items():
            if evidence_id not in self._anchors:
                raise EvidenceIntegrityError(
                    "Evidence chain anchor is missing."
                )

            events = self._events.get(
                evidence_id,
                [],
            )

            stored_ids = list(
                record.custody_event_ids
            )

            actual_ids = [
                event.event_id
                for event in events
            ]

            if stored_ids != actual_ids:
                raise EvidenceIntegrityError(
                    "Evidence custody-event references are inconsistent."
                )

            if events:
                if not self.verify_chain(
                    evidence_id
                ):
                    raise EvidenceIntegrityError(
                        "Persisted evidence chain failed verification."
                    )

            if record.sealed:
                if not record.seal_hash:
                    raise EvidenceIntegrityError(
                        "Sealed evidence is missing its seal hash."
                    )

                if _seal_hash(record) != (
                    record.seal_hash
                ):
                    raise EvidenceIntegrityError(
                        "Persisted evidence seal verification failed."
                    )

    def _read_event_log(
        self,
    ) -> dict[str, list[CustodyEvent]]:
        if self.ledger_path is None:
            return {}

        if not self.ledger_path.exists():
            return {}

        grouped: dict[str, list[CustodyEvent]] = {}
        seen_event_ids: set[str] = set()

        with open(
            self.ledger_path,
            "rb",
        ) as handle:
            line_number = 0

            for raw_line in handle:
                line_number += 1

                if not raw_line.strip():
                    continue

                if len(raw_line) > (
                    MAX_PERSISTED_EVENT_BYTES
                ):
                    raise EvidenceIntegrityError(
                        f"Custody event line {line_number} exceeds configured limit."
                    )

                try:
                    payload = json.loads(
                        raw_line.decode("utf-8")
                    )
                except Exception as exc:
                    raise EvidenceIntegrityError(
                        f"Custody event line {line_number} is invalid JSON."
                    ) from exc

                if not isinstance(
                    payload,
                    dict,
                ):
                    raise EvidenceIntegrityError(
                        f"Custody event line {line_number} is invalid."
                    )

                event = self._event_from_dict(
                    payload
                )

                if event.event_id in seen_event_ids:
                    raise EvidenceIntegrityError(
                        "Duplicate custody event ID detected in durable event log."
                    )

                seen_event_ids.add(
                    event.event_id
                )

                if event.evidence_id not in self._records:
                    raise EvidenceIntegrityError(
                        "Durable event references unknown evidence."
                    )

                events = grouped.setdefault(
                    event.evidence_id,
                    [],
                )

                if len(events) >= MAX_EVENTS_PER_EVIDENCE:
                    raise EvidenceIntegrityError(
                        "Durable event log exceeds per-evidence limit."
                    )

                events.append(event)

        return grouped

    def _reconcile_event_log(
        self,
    ) -> bool:
        logged = self._read_event_log()

        snapshot_event_ids = set()

        for events in self._events.values():
            snapshot_event_ids.update(
                event.event_id
                for event in events
            )

        logged_event_ids = set()

        for events in logged.values():
            logged_event_ids.update(
                event.event_id
                for event in events
            )

        missing = (
            snapshot_event_ids
            - logged_event_ids
        )

        if missing:
            raise EvidenceIntegrityError(
                "Durable event log is missing persisted custody events."
            )

        extra_found = False

        for evidence_id, snapshot_events in self._events.items():
            log_events = logged.get(
                evidence_id,
                [],
            )

            if len(log_events) < len(
                snapshot_events
            ):
                raise EvidenceIntegrityError(
                    "Durable event log is truncated."
                )

            for index, snapshot_event in enumerate(
                snapshot_events
            ):
                logged_event = log_events[index]

                if logged_event.to_dict() != (
                    snapshot_event.to_dict()
                ):
                    raise EvidenceIntegrityError(
                        "Durable event log diverges from persisted custody state."
                    )

            if len(log_events) > len(
                snapshot_events
            ):
                extra_found = True

            self._events[
                evidence_id
            ] = list(log_events)

        # Every logged event has now been incorporated.
        for evidence_id in self._records:
            self._events.setdefault(
                evidence_id,
                [],
            )

        # Reconstruct state from the durable event sequence.
        for evidence_id, record in self._records.items():
            events = self._events.get(
                evidence_id,
                [],
            )

            record.custody_event_ids = [
                event.event_id
                for event in events
            ]

            if events:
                record.state = events[-1].resulting_state
                record.updated_timestamp_utc = (
                    events[-1].timestamp_utc
                )

                sealed_events = [
                    event
                    for event in events
                    if event.event_type == (
                        CustodyEventType.SEALED.value
                    )
                ]

                if sealed_events:
                    record.sealed = True

                    seal_value = (
                        sealed_events[-1]
                        .metadata
                        .get("seal_hash")
                    )

                    if isinstance(
                        seal_value,
                        str,
                    ):
                        record.seal_hash = seal_value

            self._refresh_chain_anchor(
                record
            )

            if events:
                if not self.verify_chain(
                    evidence_id
                ):
                    raise EvidenceIntegrityError(
                        "Recovered custody chain failed verification."
                    )

                if record.sealed:
                    if not record.seal_hash:
                        raise EvidenceIntegrityError(
                            "Recovered sealed evidence has no seal hash."
                        )

                    if _seal_hash(record) != (
                        record.seal_hash
                    ):
                        raise EvidenceIntegrityError(
                            "Recovered evidence seal verification failed."
                        )

        return extra_found

    def _recover_from_disk(
        self,
    ) -> None:
        if self.ledger_path is None:
            return

        has_state = (
            self._state_path is not None
            and self._state_path.exists()
        )

        has_event_log = (
            self.ledger_path.exists()
        )

        if not has_state and not has_event_log:
            return

        if has_event_log and not has_state:
            raise EvidenceIntegrityError(
                "Custody event log exists without its durable evidence state snapshot."
            )

        self._read_persisted_state()

        extra_recovered = self._reconcile_event_log()

        if extra_recovered:
            # A crash may have persisted an event before its
            # state snapshot. Persist the reconciled recovery.
            self._persist_state()

    def _build_chain_anchor(
        self,
        record: EvidenceRecord,
    ) -> dict[str, object]:
        event_list = self._events.get(
            record.evidence_id,
            [],
        )

        terminal_hash = (
            event_list[-1].event_hash
            if event_list
            else None
        )

        payload = {
            "evidence_id": record.evidence_id,
            "event_count": len(event_list),
            "terminal_event_hash": terminal_hash,
            "evidence_sha256": record.hashes.sha256,
        }

        anchor_digest = _sha512_text(
            _canonical_json(payload)
        )

        return {
            **payload,
            "anchor_digest": anchor_digest,
        }

    def _refresh_chain_anchor(
        self,
        record: EvidenceRecord,
    ) -> None:
        self._anchors[
            record.evidence_id
        ] = self._build_chain_anchor(record)

    def _chain_anchor_valid(
        self,
        record: EvidenceRecord,
    ) -> bool:
        stored = self._anchors.get(
            record.evidence_id
        )

        if not isinstance(stored, dict):
            return False

        event_list = self._events.get(
            record.evidence_id,
            [],
        )

        expected = self._build_chain_anchor(
            record
        )

        return stored == expected

    def chain_anchor(
        self,
        evidence_id: str,
    ) -> dict[str, object]:
        self.get(evidence_id)

        anchor = self._anchors.get(
            evidence_id
        )

        if not isinstance(anchor, dict):
            raise EvidenceIntegrityError(
                "Evidence chain anchor is unavailable."
            )

        return dict(anchor)

    def _persist_event(
        self,
        event: CustodyEvent,
    ) -> None:
        if self.ledger_path is None:
            return

        line = (
            _canonical_json(
                event.to_dict()
            )
            + "\n"
        )

        if len(
            line.encode("utf-8")
        ) > MAX_PERSISTED_EVENT_BYTES:
            raise EvidenceCustodyError(
                "Custody event exceeds configured persistence size limit."
            )

        with open(
            self.ledger_path,
            "a",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def _append_event(
        self,
        record: EvidenceRecord,
        *,
        event_type: CustodyEventType,
        actor: str,
        purpose: str,
        source: str | None = None,
        destination: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
        target_state: str | None = None,
    ) -> CustodyEvent:
        actor = _require_nonempty(
            actor,
            "actor",
            MAX_ACTOR_CHARS,
        )

        purpose = _require_nonempty(
            purpose,
            "purpose",
            MAX_PURPOSE_CHARS,
        )

        source = _clamp(
            source,
            MAX_SOURCE_CHARS,
        )

        destination = _clamp(
            destination,
            MAX_DESTINATION_CHARS,
        )

        reason = _clamp(
            reason,
            MAX_REASON_CHARS,
        )

        metadata = _ensure_metadata(
            metadata
        )

        event_list = self._events.setdefault(
            record.evidence_id,
            [],
        )

        if len(event_list) >= MAX_EVENTS_PER_EVIDENCE:
            raise EvidenceCustodyError(
                "Maximum custody-event limit reached."
            )

        sequence = len(event_list) + 1

        previous_hash = (
            event_list[-1].event_hash
            if event_list
            else None
        )

        resulting_state = (
            target_state
            if target_state is not None
            else record.state
        )

        event_id = _safe_id("evt")

        timestamp = _utc_now()

        event_hash = _event_hash_payload(
            event_id=event_id,
            evidence_id=record.evidence_id,
            sequence=sequence,
            event_type=event_type.value,
            timestamp_utc=timestamp,
            actor=actor,
            purpose=purpose,
            source=source,
            destination=destination,
            reason=reason,
            previous_event_hash=previous_hash,
            resulting_state=resulting_state,
            evidence_sha256=record.hashes.sha256,
            metadata=metadata,
        )

        event = CustodyEvent(
            event_id=event_id,
            evidence_id=record.evidence_id,
            sequence=sequence,
            event_type=event_type.value,
            timestamp_utc=timestamp,
            actor=actor,
            purpose=purpose,
            source=source,
            destination=destination,
            reason=reason,
            previous_event_hash=previous_hash,
            event_hash=event_hash,
            resulting_state=resulting_state,
            evidence_sha256=record.hashes.sha256,
            metadata=metadata,
        )

        self._persist_event(event)

        event_list.append(event)

        record.custody_event_ids.append(
            event.event_id
        )

        record.updated_timestamp_utc = timestamp

        # Update the independent commitment only after the
        # complete event has been appended successfully.
        self._refresh_chain_anchor(record)

        if target_state is not None:
            record.state = target_state

        # Persist the complete evidence state only after the
        # event log has been durably appended AND the in-memory
        # record has been advanced to the resulting state.
        self._persist_state()

        return event

    def register(
        self,
        *,
        data: bytes,
        artifact_type: str,
        source: str,
        collector: str,
        acquisition_method: str,
        original_filename: str | None = None,
        media_type: str | None = None,
        case_id: str | None = None,
        investigation_id: str | None = None,
        evidence_id: str | None = None,
        preservation_dir: str | Path | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        with self._storage_guard():
            if len(self._records) >= MAX_EVIDENCE_RECORDS:
                raise EvidenceCustodyError(
                    "Maximum evidence-record limit reached."
                )

            if not isinstance(
                data,
                (bytes, bytearray, memoryview),
            ):
                raise TypeError(
                    "data must be bytes-like."
                )

            raw = bytes(data)

            if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
                raise ValueError(
                    "Evidence exceeds maximum supported size."
                )

            artifact_type = _require_nonempty(
                artifact_type,
                "artifact_type",
                256,
            )

            source = _require_nonempty(
                source,
                "source",
                MAX_SOURCE_CHARS,
            )

            collector = _require_nonempty(
                collector,
                "collector",
                MAX_ACTOR_CHARS,
            )

            acquisition_method = _require_nonempty(
                acquisition_method,
                "acquisition_method",
                512,
            )

            if case_id is not None:
                case_id = _require_nonempty(
                    case_id,
                    "case_id",
                    MAX_CASE_ID_CHARS,
                )

            if investigation_id is not None:
                investigation_id = _require_nonempty(
                    investigation_id,
                    "investigation_id",
                    MAX_CASE_ID_CHARS,
                )

            if evidence_id is None:
                evidence_id = _safe_id(
                    "evd"
                )
            else:
                evidence_id = _validate_storage_evidence_id(
                    evidence_id
                )

            if evidence_id in self._records:
                raise EvidenceCustodyError(
                    "Evidence ID already exists."
                )

            metadata = _ensure_metadata(
                metadata
            )

            created = _utc_now()

            hashes = _normalize_hashset(
                calculate_hashes_from_bytes(
                    raw,
                    algorithms=("sha256", "sha512"),
                )
            )

            preservation_path = None
            preservation_verified = False

            if preservation_dir is not None:
                preservation_path, preserved_hashes = (
                    preserve_evidence_bytes(
                        raw,
                        preservation_dir,
                        evidence_id,
                    )
                )

                if preserved_hashes != hashes:
                    raise EvidenceIntegrityError(
                        "Preservation hashes do not match acquisition hashes."
                    )

                preservation_verified = True

            record = EvidenceRecord(
                evidence_id=evidence_id,
                case_id=case_id,
                investigation_id=investigation_id,
                artifact_type=artifact_type,
                original_filename=_clamp(
                    original_filename,
                    1024,
                ),
                media_type=_clamp(
                    media_type,
                    256,
                ),
                source=source,
                acquisition_timestamp_utc=created,
                collector=collector,
                acquisition_method=acquisition_method,
                size_bytes=len(raw),
                hashes=hashes,
                preservation_path=preservation_path,
                preservation_verified=preservation_verified,
                state=EvidenceState.ACQUIRED.value,
                sealed=False,
                seal_hash=None,
                created_timestamp_utc=created,
                updated_timestamp_utc=created,
                custody_event_ids=[],
                core_metadata=metadata,
            )

            self._records[evidence_id] = record
            self._events[evidence_id] = []

            # Persist a valid zero-event snapshot before the first
            # event reaches the durable event log. If the process
            # stops immediately after this snapshot, recovery still
            # has a complete evidence identity to work with.
            self._refresh_chain_anchor(record)
            self._persist_state()

            self._append_event(
                record,
                event_type=CustodyEventType.COLLECTED,
                actor=collector,
                purpose="Evidence acquisition and registration",
                source=source,
                metadata={
                    "acquisition_method": acquisition_method,
                    "artifact_type": artifact_type,
                    "size_bytes": len(raw),
                },
                target_state=EvidenceState.ACQUIRED.value,
            )

            return record

    def get(
        self,
        evidence_id: str,
    ) -> EvidenceRecord:
        record = self._records.get(
            evidence_id
        )

        if record is None:
            raise EvidenceNotFoundError(
                f"Evidence not found: {evidence_id}"
            )

        return record

    def events(
        self,
        evidence_id: str,
    ) -> list[CustodyEvent]:
        self.get(evidence_id)

        return list(
            self._events.get(
                evidence_id,
                [],
            )
        )

    def seal(
        self,
        evidence_id: str,
        *,
        actor: str,
        purpose: str = "Evidence sealing",
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            if record.sealed:
                raise InvalidCustodyTransitionError(
                    "Evidence is already sealed."
                )

            if record.state not in {
                EvidenceState.ACQUIRED.value,
                EvidenceState.IN_CUSTODY.value,
            }:
                raise InvalidCustodyTransitionError(
                    f"Cannot seal evidence in state {record.state}."
                )

            record.seal_hash = _seal_hash(
                record
            )

            record.sealed = True

            event = self._append_event(
                record,
                event_type=CustodyEventType.SEALED,
                actor=actor,
                purpose=purpose,
                metadata={
                    "seal_hash": record.seal_hash,
                },
                target_state=EvidenceState.SEALED.value,
            )

            return event

    def transfer(
        self,
        evidence_id: str,
        *,
        actor: str,
        source: str,
        destination: str,
        purpose: str,
        reason: str | None = None,
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            if not record.sealed:
                raise InvalidCustodyTransitionError(
                    "Evidence must be sealed before transfer."
                )

            if record.state == EvidenceState.COMPROMISED.value:
                raise InvalidCustodyTransitionError(
                    "Compromised evidence cannot be transferred."
                )

            if not source or not destination:
                raise ValueError(
                    "Transfer requires source and destination."
                )

            return self._append_event(
                record,
                event_type=CustodyEventType.TRANSFERRED,
                actor=actor,
                purpose=purpose,
                source=source,
                destination=destination,
                reason=reason,
                target_state=EvidenceState.IN_CUSTODY.value,
            )

    def receive(
        self,
        evidence_id: str,
        *,
        actor: str,
        destination: str,
        purpose: str = "Custody receipt",
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            return self._append_event(
                record,
                event_type=CustodyEventType.RECEIVED,
                actor=actor,
                purpose=purpose,
                destination=destination,
                target_state=EvidenceState.IN_CUSTODY.value,
            )

    def access(
        self,
        evidence_id: str,
        *,
        actor: str,
        purpose: str,
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            if not record.sealed:
                raise InvalidCustodyTransitionError(
                    "Evidence must be sealed before access is logged."
                )

            return self._append_event(
                record,
                event_type=CustodyEventType.ACCESSED,
                actor=actor,
                purpose=purpose,
            )

    def export(
        self,
        evidence_id: str,
        *,
        actor: str,
        destination: str,
        purpose: str,
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            if not record.sealed:
                raise InvalidCustodyTransitionError(
                    "Evidence must be sealed before export."
                )

            return self._append_event(
                record,
                event_type=CustodyEventType.EXPORTED,
                actor=actor,
                purpose=purpose,
                destination=destination,
            )

    def archive(
        self,
        evidence_id: str,
        *,
        actor: str,
        destination: str,
        purpose: str = "Evidence archival",
    ) -> CustodyEvent:
        with self._storage_guard():
            record = self.get(evidence_id)

            if not record.sealed:
                raise InvalidCustodyTransitionError(
                    "Evidence must be sealed before archival."
                )

            return self._append_event(
                record,
                event_type=CustodyEventType.ARCHIVED,
                actor=actor,
                purpose=purpose,
                destination=destination,
                target_state=EvidenceState.ARCHIVED.value,
            )

    def verify(
        self,
        evidence_id: str,
        *,
        data: bytes | None = None,
        actor: str = "system",
        purpose: str = "Evidence integrity verification",
    ) -> VerificationResult:
        with self._storage_guard():
            record = self.get(evidence_id)
            issues: list[str] = []

            calculated_sha256 = None
            calculated_sha512 = None
            evidence_hash_match = False

            if data is not None:
                hashes = _normalize_hashset(
                    calculate_hashes_from_bytes(
                        bytes(data),
                        algorithms=("sha256", "sha512"),
                    )
                )

                calculated_sha256 = hashes.sha256
                calculated_sha512 = hashes.sha512

                evidence_hash_match = (
                    hashes.sha256
                    == record.hashes.sha256
                    and hashes.sha512
                    == record.hashes.sha512
                )

                if not evidence_hash_match:
                    issues.append(
                        "Provided evidence bytes do not match acquisition hashes."
                    )

            else:
                evidence_hash_match = True

            # A seal is a lifecycle control, not a prerequisite for
            # verifying the underlying evidence integrity. For evidence
            # that has not yet been sealed, there is no seal hash to match,
            # so seal verification is not applicable and must not be treated
            # as an integrity failure.
            seal_match = True

            if record.sealed:
                calculated_seal = _seal_hash(
                    record
                )

                seal_match = (
                    calculated_seal
                    == record.seal_hash
                )

                if not seal_match:
                    issues.append(
                        "Evidence seal hash mismatch."
                    )

            preservation_match = False

            if record.preservation_path:
                preservation_path = Path(
                    record.preservation_path
                )

                try:
                    with open(
                        preservation_path,
                        "rb",
                    ) as handle:
                        preserved = handle.read()

                    preserved_hashes = _normalize_hashset(
                        calculate_hashes_from_bytes(
                            preserved,
                            algorithms=("sha256", "sha512"),
                        )
                    )

                    preservation_match = (
                        preserved_hashes.sha256
                        == record.hashes.sha256
                        and preserved_hashes.sha512
                        == record.hashes.sha512
                    )

                    if not preservation_match:
                        issues.append(
                            "Preservation copy hash mismatch."
                        )

                except OSError:
                    issues.append(
                        "Preservation copy is unavailable."
                    )

            else:
                preservation_match = True

            chain_valid = self.verify_chain(
                evidence_id
            )

            if not chain_valid:
                issues.append(
                    "Custody event hash chain verification failed."
                )

            verified = (
                evidence_hash_match
                and seal_match
                and chain_valid
                and preservation_match
            )

            event_type = (
                CustodyEventType.VERIFIED
                if verified
                else CustodyEventType.INTEGRITY_FAILURE
            )

            target_state = (
                record.state
                if verified
                else EvidenceState.COMPROMISED.value
            )

            self._append_event(
                record,
                event_type=event_type,
                actor=actor,
                purpose=purpose,
                reason=(
                    None
                    if verified
                    else " / ".join(issues)
                ),
                metadata={
                    "evidence_hash_match": evidence_hash_match,
                    "seal_hash_match": seal_match,
                    "custody_chain_valid": chain_valid,
                    "preservation_copy_match": preservation_match,
                },
                target_state=target_state,
            )

            return VerificationResult(
                evidence_id=evidence_id,
                verified=verified,
                evidence_hash_match=evidence_hash_match,
                seal_hash_match=seal_match,
                custody_chain_valid=chain_valid,
                preservation_copy_match=preservation_match,
                calculated_sha256=calculated_sha256,
                calculated_sha512=calculated_sha512,
                expected_sha256=record.hashes.sha256,
                expected_sha512=record.hashes.sha512,
                issues=issues,
            )

    def verify_chain(
        self,
        evidence_id: str,
    ) -> bool:
        record = self.get(evidence_id)
        event_list = self._events.get(
            evidence_id,
            [],
        )

        # The commitment is deliberately checked BEFORE
        # validating individual events. A chain can otherwise
        # appear internally consistent after an event is removed.
        if not self._chain_anchor_valid(record):
            return False

        expected_sequence = 1
        previous_hash = None

        for event in event_list:
            if event.sequence != expected_sequence:
                return False

            if event.previous_event_hash != previous_hash:
                return False

            expected_hash = _event_hash_payload(
                event_id=event.event_id,
                evidence_id=event.evidence_id,
                sequence=event.sequence,
                event_type=event.event_type,
                timestamp_utc=event.timestamp_utc,
                actor=event.actor,
                purpose=event.purpose,
                source=event.source,
                destination=event.destination,
                reason=event.reason,
                previous_event_hash=event.previous_event_hash,
                resulting_state=event.resulting_state,
                evidence_sha256=event.evidence_sha256,
                metadata=event.metadata,
            )

            if expected_hash != event.event_hash:
                return False

            if event.evidence_sha256 != record.hashes.sha256:
                return False

            previous_hash = event.event_hash
            expected_sequence += 1

        # A valid committed chain must contain exactly the
        # same event count and terminal event hash that were
        # committed after the last legitimate append.
        anchor = self._anchors.get(
            evidence_id
        )

        if not isinstance(anchor, dict):
            return False

        if anchor.get("event_count") != len(
            event_list
        ):
            return False

        terminal_hash = (
            event_list[-1].event_hash
            if event_list
            else None
        )

        if anchor.get(
            "terminal_event_hash"
        ) != terminal_hash:
            return False

        if anchor.get(
            "evidence_sha256"
        ) != record.hashes.sha256:
            return False

        expected_anchor_digest = _sha512_text(
            _canonical_json(
                {
                    "evidence_id": evidence_id,
                    "event_count": len(event_list),
                    "terminal_event_hash": terminal_hash,
                    "evidence_sha256": record.hashes.sha256,
                }
            )
        )

        if anchor.get(
            "anchor_digest"
        ) != expected_anchor_digest:
            return False

        return bool(event_list)

    def manifest(
        self,
    ) -> EvidenceManifest:
        items = []

        for record in list(
            self._records.values()
        )[:MAX_MANIFEST_ITEMS]:
            items.append(
                {
                    "evidence_id": record.evidence_id,
                    "state": record.state,
                    "sealed": record.sealed,
                    "seal_hash": record.seal_hash,
                    "sha256": record.hashes.sha256,
                    "sha512": record.hashes.sha512,
                    "size_bytes": record.size_bytes,
                    "case_id": record.case_id,
                    "investigation_id": record.investigation_id,
                    "preservation_path": record.preservation_path,
                    "preservation_verified": record.preservation_verified,
                    "custody_event_count": len(
                        self._events.get(
                            record.evidence_id,
                            [],
                        )
                    ),
                    "custody_chain_valid": self.verify_chain(
                        record.evidence_id
                    ),
                    "chain_anchor": self._anchors.get(
                        record.evidence_id
                    ),
                }
            )

        canonical = _canonical_json(
            items
        )

        return EvidenceManifest(
            manifest_version=ANALYSIS_VERSION,
            generated_timestamp_utc=_utc_now(),
            evidence_count=len(items),
            evidences=items,
            manifest_sha256=_sha256_text(
                canonical
            ),
            manifest_sha512=_sha512_text(
                canonical
            ),
        )

    def export_record(
        self,
        evidence_id: str,
        *,
        include_events: bool = True,
    ) -> dict[str, Any]:
        record = self.get(
            evidence_id
        )

        result = {
            "analysis": {
                "name": ANALYSIS_NAME,
                "version": ANALYSIS_VERSION,
                "static_only": True,
            },
            "evidence": record.to_dict(),
            "integrity": {
                "chain_valid": self.verify_chain(
                    evidence_id
                ),
                "event_count": len(
                    self._events.get(
                        evidence_id,
                        [],
                    )
                ),
                "chain_anchor": self._anchors.get(
                    evidence_id
                ),
                "durable_state_path": (
                    str(self._state_path)
                    if self._state_path is not None
                    else None
                ),
                "durable_event_log_path": (
                    str(self.ledger_path)
                    if self.ledger_path is not None
                    else None
                ),
            },
        }

        if include_events:
            result["custody_events"] = [
                event.to_dict()
                for event in self.events(
                    evidence_id
                )[:MAX_EXPORT_ITEMS]
            ]

        canonical = _canonical_json(
            result
        )

        result["export_integrity"] = {
            "sha256": _sha256_text(
                canonical
            ),
            "sha512": _sha512_text(
                canonical
            ),
        }

        return result


def register_evidence(
    data: bytes,
    *,
    artifact_type: str,
    source: str,
    collector: str,
    acquisition_method: str,
    **kwargs: Any,
) -> tuple[
    EvidenceCustodyLedger,
    EvidenceRecord,
]:
    ledger = EvidenceCustodyLedger()

    record = ledger.register(
        data=data,
        artifact_type=artifact_type,
        source=source,
        collector=collector,
        acquisition_method=acquisition_method,
        **kwargs,
    )

    return ledger, record


def verify_evidence(
    ledger: EvidenceCustodyLedger,
    evidence_id: str,
    *,
    data: bytes | None = None,
) -> VerificationResult:
    return ledger.verify(
        evidence_id,
        data=data,
    )


__all__ = [
    "EvidenceCustodyLedger",
    "EvidenceCustodyError",
    "EvidenceNotFoundError",
    "EvidenceIntegrityError",
    "InvalidCustodyTransitionError",
    "register_evidence",
    "preserve_evidence_bytes",
    "verify_evidence",
]
