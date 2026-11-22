"""Durable, content-free Gmail synchronization checkpoint and dedupe store."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from .errors import SyncError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gmail_sync_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    history_id TEXT,
    watch_expiration_ms INTEGER,
    last_watch_renewal_ms INTEGER,
    last_sync_ms INTEGER,
    last_poll_ms INTEGER,
    last_pubsub_pull_ms INTEGER,
    last_scan_ms INTEGER,
    failed_sync_count INTEGER NOT NULL DEFAULT 0,
    last_error_category TEXT,
    health_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
    bootstrap_status TEXT NOT NULL DEFAULT 'NOT_STARTED',
    recovery_baseline_id TEXT,
    recovery_status TEXT NOT NULL DEFAULT 'NONE',
    coverage_status TEXT NOT NULL DEFAULT 'UNKNOWN'
);
CREATE TABLE IF NOT EXISTS gmail_detected_messages (
    message_id TEXT PRIMARY KEY,
    detected_at_ms INTEGER NOT NULL,
    discovery_source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    processing_attempts INTEGER NOT NULL DEFAULT 0,
    available_at_ms INTEGER NOT NULL DEFAULT 0,
    processing_started_at_ms INTEGER,
    last_failure_category TEXT
);
CREATE INDEX IF NOT EXISTS idx_gmail_detected_at ON gmail_detected_messages(detected_at_ms);
CREATE TABLE IF NOT EXISTS gmail_agent_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at_ms INTEGER NOT NULL,
    category TEXT NOT NULL
);
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _validate_history_id(value: str) -> str:
    value = str(value)
    if not value.isdigit():
        raise SyncError("Gmail history cursor is malformed.")
    return value


def _later_history_id(left: str | None, right: str) -> str:
    right = _validate_history_id(right)
    if left is None:
        return right
    left = _validate_history_id(left)
    return max((left, right), key=lambda item: (len(item), item))


class SyncStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.executescript(_SCHEMA)
                self._migrate_detected_messages(connection)
                connection.execute("INSERT OR IGNORE INTO gmail_sync_state(singleton) VALUES(1)")
        except sqlite3.Error as exc:
            raise SyncError("Gmail checkpoint store could not be initialized.") from exc

    @staticmethod
    def _migrate_detected_messages(connection: sqlite3.Connection) -> None:
        """Add metadata-only worker lifecycle fields to existing Phase 1B databases."""
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(gmail_detected_messages)")}
        additions = {
            "processing_attempts": "INTEGER NOT NULL DEFAULT 0",
            "available_at_ms": "INTEGER NOT NULL DEFAULT 0",
            "processing_started_at_ms": "INTEGER",
            "last_failure_category": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE gmail_detected_messages ADD COLUMN {name} {declaration}")
        connection.execute("UPDATE gmail_detected_messages SET status='PENDING' WHERE status='DETECTED'")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_gmail_work_ready "
            "ON gmail_detected_messages(status, available_at_ms, detected_at_ms)"
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        return connection

    def get_state(self) -> dict[str, Any]:
        try:
            with self._connect() as connection:
                row = connection.execute("SELECT * FROM gmail_sync_state WHERE singleton=1").fetchone()
                result = dict(row)
                result["pending_count"] = connection.execute(
                    "SELECT COUNT(*) FROM gmail_detected_messages WHERE status IN ('PENDING','RETRY_PENDING','PROCESSING')"
                ).fetchone()[0]
                result["rejected_notification_count"] = connection.execute(
                    "SELECT COUNT(*) FROM gmail_agent_events WHERE category='RejectedNotification'"
                ).fetchone()[0]
                return result
        except sqlite3.Error as exc:
            raise SyncError("Gmail checkpoint state could not be read.") from exc

    def get_history_id(self) -> str | None:
        return self.get_state().get("history_id")

    def begin_bootstrap(self, history_id: str, expiration_ms: int) -> None:
        history_id = _validate_history_id(history_id)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT history_id, bootstrap_status FROM gmail_sync_state WHERE singleton=1").fetchone()
                if row["history_id"] is None:
                    connection.execute(
                        "UPDATE gmail_sync_state SET history_id=?, watch_expiration_ms=?, last_watch_renewal_ms=?, bootstrap_status='PENDING', recovery_status='BOOTSTRAP_PENDING', health_status='SYNCING' WHERE singleton=1",
                        (history_id, expiration_ms, _now_ms()),
                    )
                else:
                    connection.execute(
                        "UPDATE gmail_sync_state SET watch_expiration_ms=?, last_watch_renewal_ms=?, health_status='SYNCING' WHERE singleton=1",
                        (expiration_ms, _now_ms()),
                    )
                connection.commit()
        except sqlite3.Error as exc:
            raise SyncError("Gmail bootstrap checkpoint could not be recorded.") from exc

    def record_watch_renewal(self, expiration_ms: int) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE gmail_sync_state SET watch_expiration_ms=?, last_watch_renewal_ms=?, health_status=CASE WHEN health_status='NOT_CONFIGURED' THEN 'READY' ELSE health_status END WHERE singleton=1",
                    (expiration_ms, _now_ms()),
                )
        except sqlite3.Error as exc:
            raise SyncError("Gmail watch renewal could not be recorded.") from exc

    def begin_recovery(self, baseline_history_id: str, expiration_ms: int) -> None:
        baseline_history_id = _validate_history_id(baseline_history_id)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE gmail_sync_state SET recovery_baseline_id=?, recovery_status='RESYNC_PENDING', watch_expiration_ms=?, last_watch_renewal_ms=?, health_status='RESYNC_REQUIRED', coverage_status='PARTIAL' WHERE singleton=1",
                    (baseline_history_id, expiration_ms, _now_ms()),
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise SyncError("Gmail recovery baseline could not be recorded.") from exc

    def record_failure(self, error_category: str, *, status: str = "DEGRADED") -> None:
        safe_category = "".join(c for c in str(error_category) if c.isalnum() or c in "_.-")[:80] or "UnknownError"
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE gmail_sync_state SET failed_sync_count=failed_sync_count+1, last_error_category=?, health_status=? WHERE singleton=1",
                    (safe_category, status),
                )
        except sqlite3.Error as exc:
            raise SyncError("Gmail synchronization failure status could not be saved.") from exc

    def record_poll(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("UPDATE gmail_sync_state SET last_poll_ms=? WHERE singleton=1", (_now_ms(),))
        except sqlite3.Error as exc:
            raise SyncError("Gmail polling health timestamp could not be saved.") from exc

    def record_pubsub_pull(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("UPDATE gmail_sync_state SET last_pubsub_pull_ms=? WHERE singleton=1", (_now_ms(),))
        except sqlite3.Error as exc:
            raise SyncError("Pub/Sub health timestamp could not be saved.") from exc

    def record_rejected_notification(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO gmail_agent_events(recorded_at_ms, category) VALUES(?, 'RejectedNotification')",
                    (_now_ms(),),
                )
        except sqlite3.Error as exc:
            raise SyncError("Rejected Pub/Sub notification could not be durably recorded.") from exc

    def commit_sync(
        self,
        history_id: str,
        message_ids: set[str],
        *,
        source: str,
        coverage_status: str = "COMPLETE",
        complete_bootstrap: bool = False,
        complete_recovery: bool = False,
    ) -> int:
        history_id = _validate_history_id(history_id)
        if source not in {"history", "bootstrap_backfill", "expired_history_backfill"}:
            raise SyncError("Gmail discovery source is invalid.")
        normalized: set[str] = set()
        for message_id in message_ids:
            if not isinstance(message_id, str) or not message_id or len(message_id) > 1024:
                continue
            normalized.add(message_id)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute("SELECT history_id FROM gmail_sync_state WHERE singleton=1").fetchone()[0]
                next_history_id = _later_history_id(current, history_id)
                before = connection.total_changes
                now_ms = _now_ms()
                connection.executemany(
                    "INSERT OR IGNORE INTO gmail_detected_messages(message_id, detected_at_ms, discovery_source, status, available_at_ms) VALUES(?,?,?,'PENDING',?)",
                    [(message_id, now_ms, source, now_ms) for message_id in normalized],
                )
                inserted = connection.total_changes - before
                connection.execute(
                    "UPDATE gmail_sync_state SET history_id=?, last_sync_ms=?, last_scan_ms=?, failed_sync_count=0, last_error_category=NULL, health_status='HEALTHY', coverage_status=?, bootstrap_status=CASE WHEN ? THEN 'COMPLETE' ELSE bootstrap_status END, recovery_status=CASE WHEN ? THEN 'NONE' ELSE recovery_status END, recovery_baseline_id=CASE WHEN ? THEN NULL ELSE recovery_baseline_id END WHERE singleton=1",
                    (next_history_id, now_ms, now_ms if inserted else connection.execute("SELECT last_scan_ms FROM gmail_sync_state WHERE singleton=1").fetchone()[0], coverage_status, int(complete_bootstrap), int(complete_recovery), int(complete_recovery)),
                )
                connection.commit()
                return inserted
        except sqlite3.Error as exc:
            raise SyncError("Gmail messages and checkpoint could not be durably committed.") from exc

    def prune_dedupe_records(self, retention_days: int) -> int:
        cutoff = _now_ms() - retention_days * 86400 * 1000
        try:
            with self._connect() as connection:
                cursor = connection.execute("DELETE FROM gmail_detected_messages WHERE detected_at_ms < ?", (cutoff,))
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise SyncError("Expired Gmail dedupe records could not be pruned.") from exc

    def detected_message_ids(self, limit: int = 100) -> list[str]:
        limit = max(1, min(int(limit), 1000))
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT message_id FROM gmail_detected_messages WHERE status IN ('PENDING','RETRY_PENDING') ORDER BY detected_at_ms LIMIT ?",
                    (limit,),
                ).fetchall()
                return [str(row[0]) for row in rows]
        except sqlite3.Error as exc:
            raise SyncError("Pending Gmail message references could not be read.") from exc

    def claim_pending_references(
        self, *, limit: int = 25, lease_seconds: int = 300, max_attempts: int = 5,
    ) -> list[str]:
        """Atomically recover stale leases and claim a bounded batch of opaque IDs."""
        limit = max(1, min(int(limit), 500))
        lease_ms = max(30, int(lease_seconds)) * 1000
        max_attempts = max(1, min(int(max_attempts), 20))
        now_ms = _now_ms()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE gmail_detected_messages SET status=CASE WHEN processing_attempts>=? THEN 'FAILED' ELSE 'RETRY_PENDING' END, "
                    "available_at_ms=?, processing_started_at_ms=NULL, "
                    "last_failure_category=CASE WHEN processing_attempts>=? THEN 'LeaseExpiredMaxAttempts' ELSE 'LeaseExpired' END "
                    "WHERE status='PROCESSING' AND processing_started_at_ms<=?",
                    (max_attempts, now_ms, max_attempts, now_ms - lease_ms),
                )
                connection.execute(
                    "UPDATE gmail_detected_messages SET status='FAILED', last_failure_category='MaxAttemptsExceeded' "
                    "WHERE status='RETRY_PENDING' AND processing_attempts>=?",
                    (max_attempts,),
                )
                rows = connection.execute(
                    "SELECT message_id FROM gmail_detected_messages "
                    "WHERE status IN ('PENDING','RETRY_PENDING') AND available_at_ms<=? "
                    "ORDER BY detected_at_ms, message_id LIMIT ?",
                    (now_ms, limit),
                ).fetchall()
                ids = [str(row[0]) for row in rows]
                if ids:
                    connection.executemany(
                        "UPDATE gmail_detected_messages SET status='PROCESSING', processing_attempts=processing_attempts+1, "
                        "processing_started_at_ms=? WHERE message_id=? AND status IN ('PENDING','RETRY_PENDING')",
                        [(now_ms, message_id) for message_id in ids],
                    )
                connection.commit()
                return ids
        except sqlite3.Error as exc:
            raise SyncError("Pending Gmail references could not be claimed.") from exc

    def complete_reference(self, message_id: str) -> None:
        """Complete metadata-only handling; no message data is accepted or persisted."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE gmail_detected_messages SET status='COMPLETED', processing_started_at_ms=NULL, "
                    "last_failure_category=NULL WHERE message_id=? AND status='PROCESSING'",
                    (message_id,),
                )
                if cursor.rowcount != 1:
                    raise SyncError("Gmail reference is not currently claimed.")
                connection.commit()
        except sqlite3.Error as exc:
            raise SyncError("Gmail reference completion could not be committed.") from exc

    def release_reference(self, message_id: str) -> None:
        """Return an unprocessed claimed reference for immediate restart pickup."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE gmail_detected_messages SET status='RETRY_PENDING', available_at_ms=?, "
                    "processing_started_at_ms=NULL WHERE message_id=? AND status='PROCESSING'",
                    (_now_ms(), message_id),
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise SyncError("Unprocessed Gmail reference could not be released.") from exc

    def fail_reference(
        self, message_id: str, category: str, *, max_attempts: int = 5,
        retry_base_seconds: int = 5, retry_max_seconds: int = 900,
        permanent: bool = False,
    ) -> str:
        """Persist a sanitized bounded retry/terminal transition for a claimed ID."""
        safe_category = "".join(c for c in str(category) if c.isalnum() or c in "_.-")[:80] or "WorkerError"
        max_attempts = max(1, min(int(max_attempts), 20))
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT processing_attempts FROM gmail_detected_messages WHERE message_id=? AND status='PROCESSING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise SyncError("Gmail reference is not currently claimed.")
                attempts = int(row[0])
                terminal = bool(permanent) or attempts >= max_attempts
                delay = min(max(1, int(retry_base_seconds)) * (2 ** max(0, attempts - 1)), max(1, int(retry_max_seconds)))
                status = "FAILED" if terminal else "RETRY_PENDING"
                connection.execute(
                    "UPDATE gmail_detected_messages SET status=?, available_at_ms=?, processing_started_at_ms=NULL, last_failure_category=? "
                    "WHERE message_id=? AND status='PROCESSING'",
                    (status, _now_ms() + (0 if terminal else delay * 1000), safe_category, message_id),
                )
                connection.commit()
                return status
        except sqlite3.Error as exc:
            raise SyncError("Gmail reference failure state could not be committed.") from exc

