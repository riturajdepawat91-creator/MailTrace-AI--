"""Serialized Gmail History synchronization shared by push and polling."""
from __future__ import annotations

import base64
import json
import math
import threading
import time
from typing import Any

from .errors import GmailHistoryExpired, GmailNotFound, InvalidPubSubNotification, ReconnectRequired, SyncError
from .store import SyncStore


def _history_ids(page: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for row in page.get("history", []) if isinstance(page.get("history", []), list) else []:
        if not isinstance(row, dict):
            continue
        for event in row.get("messagesAdded", []) if isinstance(row.get("messagesAdded", []), list) else []:
            message = event.get("message", {}) if isinstance(event, dict) else {}
            labels = message.get("labelIds", []) if isinstance(message, dict) else []
            mid = message.get("id") if isinstance(message, dict) else None
            if isinstance(mid, str) and mid and (not labels or "INBOX" in labels):
                found.add(mid)
    return found


def _normalize_notification_history_id(value: Any) -> str | None:
    """Accept Gmail JSON integers and legacy decimal strings, excluding bool and zero."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        normalized = value.lstrip("0")
        return normalized or None
    return None


class GmailSyncEngine:
    def __init__(self, client: Any, store: SyncStore, *, recovery_window_hours: int = 24, recovery_max_messages: int = 500):
        self.client, self.store = client, store
        self.recovery_window_hours, self.recovery_max_messages = recovery_window_hours, recovery_max_messages
        self._lock = threading.Lock()

    def renew_watch_if_due(self, *, now_ms: int | None = None, renew_before_seconds: int = 172800, force: bool = False) -> bool:
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        state = self.store.get_state()
        if not force and state["watch_expiration_ms"] and state["watch_expiration_ms"] - now_ms > renew_before_seconds * 1000:
            return False
        watch = self.client.watch_inbox(self._topic_name)
        expiration = int(watch["expiration"])
        if not state["history_id"]:
            self.store.begin_bootstrap(str(watch["historyId"]), expiration)
        else:
            self.store.record_watch_renewal(expiration)
        return True

    @property
    def _topic_name(self) -> str:
        topic = getattr(self, "topic_name", None)
        if not topic:
            raise SyncError("Gmail Pub/Sub topic is not configured.")
        return topic

    def set_topic(self, topic_name: str) -> None:
        self.topic_name = topic_name

    def sync_until_current(self, source: str = "history") -> int:
        if source not in {"history", "poll", "pubsub"}:
            raise ValueError("invalid sync source")
        # A caller must never interpret a skipped concurrent sync as durable work and ack a push.
        self._lock.acquire()
        try:
            cursor = self.store.get_history_id()
            if cursor is None:
                watch = self.client.watch_inbox(self._topic_name)
                cursor = str(watch["historyId"])
                self.store.begin_bootstrap(cursor, int(watch["expiration"]))
                # Baseline is established now; history catches races after watch registration.
            return self._consume_history(cursor, source)
        except GmailHistoryExpired:
            try:
                self._recover_expired_cursor()
                return 0
            except ReconnectRequired:
                self.store.record_failure("ReconnectRequired", status="RECONNECT_REQUIRED")
                raise
            except Exception as exc:
                self.store.record_failure(type(exc).__name__, status="RESYNC_REQUIRED")
                raise
        except ReconnectRequired:
            self.store.record_failure("ReconnectRequired", status="RECONNECT_REQUIRED")
            raise
        except Exception as exc:
            category = type(exc).__name__
            self.store.record_failure(category)
            raise
        finally:
            self._lock.release()

    def _consume_history(self, cursor: str, source: str) -> int:
        token = None
        ids: set[str] = set()
        latest = cursor
        while True:
            page = self.client.history_page(cursor, page_token=token)
            ids.update(_history_ids(page))
            latest = max((latest, str(page["historyId"])), key=lambda x: (len(x), x))
            token = page.get("nextPageToken")
            if not token:
                break
        state = self.store.get_state()
        inserted = self.store.commit_sync(
            latest, ids, source="history",
            complete_bootstrap=state.get("bootstrap_status") == "PENDING",
        )
        if source == "poll":
            self.store.record_poll()
        elif source == "pubsub":
            self.store.record_pubsub_pull()
        return inserted

    def _recover_expired_cursor(self) -> None:
        # Register a fresh baseline first, then bounded recent Inbox backfill and history catch-up.
        watch = self.client.watch_inbox(self._topic_name)
        baseline = str(watch["historyId"])
        expiration = int(watch["expiration"])
        self.store.begin_recovery(baseline, expiration)
        # Gmail newer_than accepts d/m/y units, not hours. Search the enclosing day window,
        # then filter each bounded metadata result against the exact configured hour cutoff.
        query = f"newer_than:{max(1, math.ceil(self.recovery_window_hours / 24))}d"
        cutoff_ms = int(time.time() * 1000) - self.recovery_window_hours * 3600 * 1000
        page_token = None
        ids: set[str] = set()
        scanned = 0
        capped = False
        while scanned < self.recovery_max_messages:
            page = self.client.list_messages(page_token=page_token, page_size=min(100, self.recovery_max_messages - scanned), label_ids=("INBOX",), query=query)
            for item in page.get("messages", []) if isinstance(page.get("messages", []), list) else []:
                if isinstance(item, dict) and isinstance(item.get("id"), str):
                    scanned += 1
                    try:
                        metadata = self.client.get_message(item["id"], format="metadata")
                    except GmailNotFound:
                        # Message may have been deleted/moved between list and metadata lookup.
                        metadata = {}
                    labels = metadata.get("labelIds", []) if isinstance(metadata, dict) else []
                    still_in_inbox = not labels or "INBOX" in labels
                    try:
                        recent = int(metadata.get("internalDate", 0)) >= cutoff_ms
                    except (TypeError, ValueError):
                        recent = False
                    if recent and still_in_inbox:
                        ids.add(item["id"])
                    if scanned >= self.recovery_max_messages:
                        capped = bool(page.get("nextPageToken"))
                        break
            page_token = page.get("nextPageToken")
            if not page_token or scanned >= self.recovery_max_messages:
                break
        self.store.commit_sync(baseline, ids, source="expired_history_backfill", coverage_status="PARTIAL" if capped else "BOUNDED_RECOVERY", complete_recovery=True)
        self._consume_history(baseline, "history")

    def process_notification(self, data: bytes | str, expected_email: str) -> int:
        if isinstance(data, str):
            try:
                data = data.encode("ascii", "strict")
            except UnicodeEncodeError:
                raise InvalidPubSubNotification("Pub/Sub notification was malformed.") from None
        if len(data) > 16384:
            raise InvalidPubSubNotification("Pub/Sub notification exceeded its size limit.")
        try:
            # Pub/Sub client libraries already decode the outer Pub/Sub data field.
            # Accept base64url too for adapters that expose the REST representation.
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                padded = data + b"=" * (-len(data) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except Exception:
            raise InvalidPubSubNotification("Pub/Sub notification was malformed.") from None
        email = payload.get("emailAddress") if isinstance(payload, dict) else None
        raw_hint = payload.get("historyId") if isinstance(payload, dict) else None
        hint = _normalize_notification_history_id(raw_hint)
        if hint is None:
            raise InvalidPubSubNotification("Pub/Sub notification was malformed.")
        if not isinstance(email, str) or email.casefold() != expected_email.casefold():
            raise InvalidPubSubNotification("Pub/Sub notification did not match the connected mailbox.")
        # History cursor in notification is a wake-up hint only; always sync from durable cursor.
        # `hint` is validated and normalized, but deliberately does not replace that cursor.
        return self.sync_until_current("pubsub")
