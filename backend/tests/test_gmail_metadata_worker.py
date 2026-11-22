import logging
import sqlite3
import threading
import time

import pytest

from services.gmail_connector.errors import SyncError
from services.gmail_connector.store import SyncStore
from services.gmail_connector.worker import GmailReferenceWorker


def add_refs(store, *message_ids):
    return store.commit_sync("101", set(message_ids), source="history")


def row(store, message_id):
    with store._connect() as connection:
        return dict(connection.execute(
            "SELECT * FROM gmail_detected_messages WHERE message_id=?", (message_id,)
        ).fetchone())


def test_consumes_only_pending_reference_and_completes_metadata_state(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "opaque-1")
    result = GmailReferenceWorker(store).run_once()
    assert (result.claimed_count, result.completed_count) == (1, 1)
    assert row(store, "opaque-1")["status"] == "COMPLETED"
    assert store.detected_message_ids() == []


def test_duplicate_history_discovery_does_not_create_second_job(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    assert add_refs(store, "same-id") == 1
    assert add_refs(store, "same-id") == 0
    assert GmailReferenceWorker(store).run_once().completed_count == 1
    assert row(store, "same-id")["processing_attempts"] == 1


def test_batch_is_bounded_and_concurrent_claim_cannot_duplicate(tmp_path):
    first = SyncStore(tmp_path / "sync.db")
    second = SyncStore(tmp_path / "sync.db")
    add_refs(first, "a", "b", "c")
    assert len(first.claim_pending_references(limit=2)) == 2
    assert second.claim_pending_references(limit=2) == ["c"]
    assert second.claim_pending_references(limit=2) == []


def test_transient_failure_is_sanitized_and_retry_is_bounded(tmp_path, monkeypatch, caplog):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "retry-me")
    original = store.complete_reference
    calls = 0

    def flaky(message_id):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("private body token=never-log")
        original(message_id)

    monkeypatch.setattr(store, "complete_reference", flaky)
    result = GmailReferenceWorker(store, retry_base_seconds=1).run_once()
    assert result.retry_count == 1
    assert row(store, "retry-me")["status"] == "RETRY_PENDING"
    assert row(store, "retry-me")["last_failure_category"] == "RuntimeError"
    assert "private body" not in caplog.text
    with store._connect() as connection:
        connection.execute("UPDATE gmail_detected_messages SET available_at_ms=0 WHERE message_id='retry-me'")
    monkeypatch.setattr(store, "complete_reference", original)
    assert GmailReferenceWorker(store).run_once().completed_count == 1


def test_max_attempts_moves_reference_to_terminal_failure(tmp_path, monkeypatch):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "permanent")
    monkeypatch.setattr(store, "complete_reference", lambda _id: (_ for _ in ()).throw(ValueError("x")))
    result = GmailReferenceWorker(store, max_attempts=5).run_once()
    assert result.failed_count == 1
    assert row(store, "permanent")["status"] == "FAILED"
    assert store.claim_pending_references() == []


def test_stale_processing_claim_recovers_after_restart(tmp_path):
    path = tmp_path / "sync.db"
    store = SyncStore(path)
    add_refs(store, "crash-recovery")
    assert store.claim_pending_references(lease_seconds=30) == ["crash-recovery"]
    with store._connect() as connection:
        connection.execute(
            "UPDATE gmail_detected_messages SET processing_started_at_ms=0 WHERE message_id='crash-recovery'"
        )
    restarted = SyncStore(path)
    assert restarted.claim_pending_references(lease_seconds=30) == ["crash-recovery"]
    assert row(restarted, "crash-recovery")["status"] == "PROCESSING"
    assert row(restarted, "crash-recovery")["processing_attempts"] == 2


def test_completion_is_transactional_and_requires_claim(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "not-claimed")
    with pytest.raises(SyncError):
        store.complete_reference("not-claimed")
    assert row(store, "not-claimed")["status"] == "PENDING"
    assert store.claim_pending_references() == ["not-claimed"]
    store.complete_reference("not-claimed")
    assert row(store, "not-claimed")["status"] == "COMPLETED"


def test_completion_transaction_rolls_back_on_database_failure(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "rollback")
    assert store.claim_pending_references() == ["rollback"]
    with store._connect() as connection:
        connection.execute(
            "CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON gmail_detected_messages "
            "WHEN NEW.status='COMPLETED' BEGIN SELECT RAISE(ABORT, 'test rollback'); END"
        )
    with pytest.raises(SyncError):
        store.complete_reference("rollback")
    assert row(store, "rollback")["status"] == "PROCESSING"


def test_restart_preserves_completion_and_reference_state(tmp_path):
    path = tmp_path / "restart.db"
    store = SyncStore(path)
    add_refs(store, "durable")
    assert GmailReferenceWorker(store).run_once().completed_count == 1
    restarted = SyncStore(path)
    assert row(restarted, "durable")["status"] == "COMPLETED"
    assert restarted.get_history_id() == "101"


def test_worker_has_no_gmail_or_content_processing_dependency(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "opaque-only")
    # The worker accepts only the existing store and has no client/parser injection.
    worker = GmailReferenceWorker(store)
    assert not hasattr(worker, "client")
    assert worker.run_once().completed_count == 1
    with store._connect() as connection:
        columns = {item[1] for item in connection.execute("PRAGMA table_info(gmail_detected_messages)")}
    assert not columns.intersection({"body", "subject", "mime", "attachments", "headers"})


def test_existing_phase1b_database_migrates_detected_rows(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE gmail_detected_messages (message_id TEXT PRIMARY KEY, detected_at_ms INTEGER NOT NULL, discovery_source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'DETECTED')")
        connection.execute("INSERT INTO gmail_detected_messages VALUES('old-ref', 1, 'history', 'DETECTED')")
    store = SyncStore(path)
    assert row(store, "old-ref")["status"] == "PENDING"
    assert store.claim_pending_references() == ["old-ref"]


def test_graceful_stop_releases_unprocessed_claim_for_restart(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "shutdown-ref")
    worker = GmailReferenceWorker(store)
    worker.stop()
    assert worker.run_once().completed_count == 0
    assert row(store, "shutdown-ref")["status"] == "RETRY_PENDING"
    assert store.claim_pending_references() == ["shutdown-ref"]


def test_worker_loop_stops_cleanly_from_wait(tmp_path):
    store = SyncStore(tmp_path / "sync.db")
    worker = GmailReferenceWorker(store, poll_interval_seconds=10)
    thread = threading.Thread(target=worker.run_forever)
    thread.start()
    time.sleep(0.05)
    worker.stop()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_worker_does_not_log_message_identifier(tmp_path, caplog):
    store = SyncStore(tmp_path / "sync.db")
    add_refs(store, "secret-message-id")
    caplog.set_level(logging.DEBUG)
    GmailReferenceWorker(store).run_once()
    assert "secret-message-id" not in caplog.text
