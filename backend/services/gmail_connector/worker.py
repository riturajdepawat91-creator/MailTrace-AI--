"""Durable metadata-only worker for Gmail message references.

This worker has no Gmail client dependency. A successful run consumes only an
opaque stored message ID and records lifecycle state; email content retrieval,
parsing, classification, enrichment, quarantine, and SOC transfer are out of scope.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .errors import SyncError
from .store import SyncStore

log = logging.getLogger("mailtrace.gmail_worker")


@dataclass(frozen=True)
class WorkerResult:
    claimed_count: int
    completed_count: int
    retry_count: int
    failed_count: int


class GmailReferenceWorker:
    """Claim and complete bounded durable reference batches without fetching mail."""

    def __init__(
        self,
        store: SyncStore,
        *,
        batch_size: int = 25,
        lease_seconds: int = 300,
        max_attempts: int = 5,
        retry_base_seconds: int = 5,
        retry_max_seconds: int = 900,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self.store = store
        self.batch_size = max(1, min(int(batch_size), 500))
        self.lease_seconds = max(30, int(lease_seconds))
        self.max_attempts = max(1, min(int(max_attempts), 20))
        self.retry_base_seconds = max(1, int(retry_base_seconds))
        self.retry_max_seconds = max(self.retry_base_seconds, int(retry_max_seconds))
        self.poll_interval_seconds = max(0.1, float(poll_interval_seconds))
        self._stop = threading.Event()
        self._run_lock = threading.Lock()

    def run_once(self) -> WorkerResult:
        """Handle at most one bounded batch; only message IDs enter this method."""
        if not self._run_lock.acquire(blocking=False):
            return WorkerResult(0, 0, 0, 0)
        try:
            ids = self.store.claim_pending_references(
                limit=self.batch_size,
                lease_seconds=self.lease_seconds,
                max_attempts=self.max_attempts,
            )
            completed = retrying = failed = 0
            for index, message_id in enumerate(ids):
                if self._stop.is_set():
                    for pending_id in ids[index:]:
                        self.store.release_reference(pending_id)
                    break
                try:
                    # Phase 1C deliberately performs no content or provider calls.
                    self.store.complete_reference(message_id)
                    completed += 1
                except Exception as exc:
                    category = type(exc).__name__
                    try:
                        status = self.store.fail_reference(
                            message_id,
                            category,
                            max_attempts=self.max_attempts,
                            retry_base_seconds=self.retry_base_seconds,
                            retry_max_seconds=self.retry_max_seconds,
                            permanent=isinstance(exc, (ValueError, TypeError)),
                        )
                    except SyncError:
                        # The durable row remains PROCESSING and lease recovery
                        # handles it after restart/lease expiry.
                        log.warning("Metadata worker could not persist a failure transition.")
                        continue
                    if status == "FAILED":
                        failed += 1
                    else:
                        retrying += 1
            return WorkerResult(len(ids), completed, retrying, failed)
        finally:
            self._run_lock.release()

    def run_forever(self) -> None:
        """Run until stop is requested; operational errors are safely summarized."""
        while not self._stop.is_set():
            try:
                result = self.run_once()
                if result.claimed_count == 0:
                    self._stop.wait(self.poll_interval_seconds)
            except SyncError:
                log.warning("Metadata worker store operation failed; will retry.")
                self._stop.wait(self.poll_interval_seconds)
            except Exception as exc:
                log.warning("Metadata worker iteration failed (%s); will retry.", type(exc).__name__)
                self._stop.wait(self.poll_interval_seconds)

    def stop(self) -> None:
        """Request graceful shutdown and wake any idle worker wait."""
        self._stop.set()

    def wait_stopped(self, timeout: float | None = None) -> bool:
        """Wait for the current batch to release its run lock."""
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while self._run_lock.locked():
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True


__all__ = ["GmailReferenceWorker", "WorkerResult"]
