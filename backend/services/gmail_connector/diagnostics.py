"""Content-free local Agent health projection."""
from __future__ import annotations

from typing import Any


def build_diagnostics(state: dict[str, Any], authorization_status: str) -> dict[str, Any]:
    """Return operational fields only; intentionally excludes email and credential material."""
    last_sync = state.get("last_sync_ms")
    last_pubsub = state.get("last_pubsub_pull_ms")
    return {
        "gmail_authorization": authorization_status,
        "gmail_api_connectivity": "CONNECTED" if last_sync else "NOT_CHECKED",
        "pubsub_subscription_connectivity": "CONNECTED" if last_pubsub else "NOT_CHECKED",
        "watch_expiration_ms": state.get("watch_expiration_ms"),
        "last_watch_renewal_ms": state.get("last_watch_renewal_ms"),
        "last_successful_sync_ms": last_sync,
        "last_processed_history_id": state.get("history_id"),
        "pending_sync_jobs": state.get("pending_count", 0),
        "rejected_notification_count": state.get("rejected_notification_count", 0),
        # Phase 1B records message references only; it does not run email scans.
        "last_scan_timestamp_ms": None,
        "failed_sync_count": state.get("failed_sync_count", 0),
        "last_error_category": state.get("last_error_category"),
        "recovery_status": state.get("recovery_status", "UNKNOWN"),
        "coverage_status": state.get("coverage_status", "UNKNOWN"),
        "health_status": state.get("health_status", "UNKNOWN"),
    }
