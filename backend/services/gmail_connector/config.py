"""Local Gmail/Pub/Sub Agent configuration; no credential material is parsed here."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import PubSubConfigurationError

_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_RESOURCE_RE = re.compile(r"^projects/([^/]+)/(topics|subscriptions)/([^/]+)$")


@dataclass(frozen=True)
class AgentConfig:
    project_id: str
    topic_name: str
    subscription_name: str
    poll_interval_seconds: int
    watch_renew_before_seconds: int
    pull_timeout_seconds: int
    recovery_window_hours: int
    recovery_max_messages: int
    dedupe_retention_days: int
    state_path: Path

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "AgentConfig":
        env = os.environ if environ is None else environ
        project_id = env.get("MAILTRACE_GMAIL_GCP_PROJECT", "").strip()
        topic_name = env.get("MAILTRACE_GMAIL_PUBSUB_TOPIC", "").strip()
        subscription_name = env.get("MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION", "").strip()
        missing = [
            name for name, value in (
                ("MAILTRACE_GMAIL_GCP_PROJECT", project_id),
                ("MAILTRACE_GMAIL_PUBSUB_TOPIC", topic_name),
                ("MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION", subscription_name),
            ) if not value
        ]
        if missing:
            raise PubSubConfigurationError("Required Gmail Agent settings are missing: " + ", ".join(missing))
        if not _PROJECT_RE.fullmatch(project_id):
            raise PubSubConfigurationError("MAILTRACE_GMAIL_GCP_PROJECT has an invalid project ID format.")
        topic_match = _RESOURCE_RE.fullmatch(topic_name)
        subscription_match = _RESOURCE_RE.fullmatch(subscription_name)
        if not topic_match or topic_match.group(2) != "topics":
            raise PubSubConfigurationError("MAILTRACE_GMAIL_PUBSUB_TOPIC must be a fully qualified topic resource.")
        if not subscription_match or subscription_match.group(2) != "subscriptions":
            raise PubSubConfigurationError("MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION must be a fully qualified subscription resource.")
        if topic_match.group(1) != project_id or subscription_match.group(1) != project_id:
            raise PubSubConfigurationError("Gmail watch topic and pull subscription must use the configured Gmail API project.")

        local_app_data = env.get("LOCALAPPDATA", "").strip()
        user_profile = env.get("USERPROFILE", "").strip()
        stable_root = Path(local_app_data) if local_app_data else (Path(user_profile) / "AppData" / "Local" if user_profile else None)
        if stable_root is None:
            raise PubSubConfigurationError("The Windows user profile is unavailable for the Gmail sync checkpoint store.")
        state_path = Path(env.get("MAILTRACE_GMAIL_STATE_PATH", str(stable_root / "MailTrace" / "gmail" / "sync.sqlite3")))

        return cls(
            project_id=project_id,
            topic_name=topic_name,
            subscription_name=subscription_name,
            poll_interval_seconds=_int_setting(env, "MAILTRACE_GMAIL_POLL_SECONDS", 60, 15, 3600),
            watch_renew_before_seconds=_int_setting(env, "MAILTRACE_GMAIL_WATCH_RENEW_BEFORE_SECONDS", 172800, 3600, 518400),
            pull_timeout_seconds=_int_setting(env, "MAILTRACE_GMAIL_PUBSUB_PULL_TIMEOUT_SECONDS", 5, 1, 30),
            recovery_window_hours=_int_setting(env, "MAILTRACE_GMAIL_RECOVERY_WINDOW_HOURS", 24, 1, 168),
            recovery_max_messages=_int_setting(env, "MAILTRACE_GMAIL_RECOVERY_MAX_MESSAGES", 500, 1, 5000),
            dedupe_retention_days=_int_setting(env, "MAILTRACE_GMAIL_DEDUPE_RETENTION_DAYS", 30, 1, 365),
            state_path=state_path,
        )


def _int_setting(env: dict[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = env.get(name, str(default)).strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise PubSubConfigurationError(f"{name} must be an integer from {minimum} to {maximum}.") from None
    if not minimum <= value <= maximum:
        raise PubSubConfigurationError(f"{name} must be an integer from {minimum} to {maximum}.")
    return value

