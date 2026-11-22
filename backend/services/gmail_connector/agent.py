"""Local foreground Windows Agent runner for Phase 1B; service installation is separate."""
from __future__ import annotations

import logging
import random
import signal
import argparse
import json
import time

from .client import GmailClient
from .config import AgentConfig
from .diagnostics import build_diagnostics
from .errors import InvalidPubSubNotification, PubSubConfigurationError, ReconnectRequired, SyncError
from .oauth import GmailOAuth
from .pubsub import PubSubPullSubscriber
from .store import SyncStore
from .sync import GmailSyncEngine

log = logging.getLogger("mailtrace.gmail_agent")


def process_delivery(engine: GmailSyncEngine, subscriber: PubSubPullSubscriber, delivery: object, expected_email: str, store: SyncStore | None = None) -> int:
    ack_id = getattr(delivery, "ack_id", None)
    message = getattr(delivery, "message", None)
    data = getattr(message, "data", None)
    if not isinstance(ack_id, str):
        raise PubSubConfigurationError("Pub/Sub delivery was malformed and could not be synchronized.")
    if not isinstance(data, (bytes, str)):
        if store is None:
            raise PubSubConfigurationError("Pub/Sub delivery was malformed and could not be synchronized.")
        store.record_rejected_notification()
        subscriber.acknowledge([ack_id])
        return 0
    try:
        count = engine.process_notification(data, expected_email)
    except InvalidPubSubNotification:
        if store is None:
            raise
        store.record_rejected_notification()
        subscriber.acknowledge([ack_id])
        return 0
    # Only acknowledge after Gmail changes and the durable cursor/job IDs committed.
    subscriber.acknowledge([ack_id])
    return count


def verify_one_notification(
    config: AgentConfig | None = None,
    *,
    oauth: GmailOAuth | None = None,
    subscriber: PubSubPullSubscriber | None = None,
) -> dict[str, int | str]:
    """Safely handle at most one queued delivery; never creates or renews a Gmail watch."""
    config = config or AgentConfig.from_env()
    oauth = oauth or GmailOAuth()
    client = GmailClient(oauth)
    store = SyncStore(config.state_path)
    if not store.get_history_id():
        raise SyncError("No durable Gmail history checkpoint exists; one-shot verification will not register a watch.")
    engine = GmailSyncEngine(client, store, recovery_window_hours=config.recovery_window_hours, recovery_max_messages=config.recovery_max_messages)
    engine.set_topic(config.topic_name)
    subscriber = subscriber or PubSubPullSubscriber(config.subscription_name)
    try:
        subscriber.validate_subscription(config.topic_name)
        profile = client.get_profile()
        expected_email = profile.get("emailAddress")
        if not isinstance(expected_email, str):
            raise PubSubConfigurationError("Gmail profile did not provide a mailbox identity.")
        deliveries = subscriber.pull_once(timeout_seconds=config.pull_timeout_seconds, max_messages=1)
        if not deliveries:
            return {"status": "EMPTY", "pulled_count": 0, "new_message_reference_count": 0, "acknowledged_count": 0}
        rejected_before = store.get_state().get("rejected_notification_count", 0)
        count = process_delivery(engine, subscriber, deliveries[0], expected_email, store)
        rejected_after = store.get_state().get("rejected_notification_count", 0)
        status = "REJECTED_RECORDED_AND_ACKED" if rejected_after > rejected_before else "SYNCED_AND_ACKED"
        return {"status": status, "pulled_count": 1, "new_message_reference_count": count, "acknowledged_count": 1}
    finally:
        subscriber.close()


def run_agent(config: AgentConfig | None = None, *, oauth: GmailOAuth | None = None, subscriber: PubSubPullSubscriber | None = None, stop_after: int | None = None) -> None:
    config = config or AgentConfig.from_env()
    oauth = oauth or GmailOAuth()
    client = GmailClient(oauth)
    store = SyncStore(config.state_path)
    engine = GmailSyncEngine(client, store, recovery_window_hours=config.recovery_window_hours, recovery_max_messages=config.recovery_max_messages)
    engine.set_topic(config.topic_name)
    subscriber = subscriber or PubSubPullSubscriber(config.subscription_name)
    subscriber.validate_subscription(config.topic_name)
    profile = client.get_profile()
    expected_email = profile.get("emailAddress")
    if not isinstance(expected_email, str):
        raise PubSubConfigurationError("Gmail profile did not provide a mailbox identity.")
    last_poll = 0.0
    failures = 0
    waiting_for_reconnect = False
    pubsub_was_unavailable = False
    iterations = 0
    keep_running = True

    def stop(_sig: int, _frame: object) -> None:
        nonlocal keep_running
        keep_running = False

    previous = {}
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
        try:
            previous[sig] = signal.signal(sig, stop)
        except (ValueError, OSError):
            pass
    try:
        while keep_running:
            try:
                if waiting_for_reconnect and oauth.authorization_status() == "CONNECTED":
                    engine.renew_watch_if_due(renew_before_seconds=config.watch_renew_before_seconds, force=True)
                    waiting_for_reconnect = False
                engine.renew_watch_if_due(renew_before_seconds=config.watch_renew_before_seconds)
                try:
                    deliveries = subscriber.pull_once(timeout_seconds=config.pull_timeout_seconds)
                except PubSubConfigurationError:
                    pubsub_was_unavailable = True
                    raise
                if pubsub_was_unavailable:
                    # Re-register Gmail's publisher watch after the pull path has recovered.
                    engine.renew_watch_if_due(renew_before_seconds=config.watch_renew_before_seconds, force=True)
                    pubsub_was_unavailable = False
                for delivery in deliveries:
                    process_delivery(engine, subscriber, delivery, expected_email, store)
                now = time.monotonic()
                if now - last_poll >= config.poll_interval_seconds:
                    engine.sync_until_current("poll")
                    last_poll = now
                failures = 0
            except ReconnectRequired:
                waiting_for_reconnect = True
                store.record_failure("ReconnectRequired", status="RECONNECT_REQUIRED")
                log.error("Gmail authorization requires reconnect; agent is waiting for user action.")
                time.sleep(min(60, config.poll_interval_seconds))
            except Exception as exc:
                failures += 1
                log.warning("Gmail Agent operation failed (%s); retrying with backoff.", type(exc).__name__)
                time.sleep(min(300, 2 ** min(failures, 8)) + random.random())
            iterations += 1
            if stop_after is not None and iterations >= stop_after:
                break
    finally:
        subscriber.close()
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="MailTrace local Gmail synchronization Agent")
    parser.add_argument("--diagnostics", action="store_true", help="print safe local sync health and exit")
    parser.add_argument("--verify-once", action="store_true", help="pull and safely handle at most one Pub/Sub notification")
    args = parser.parse_args()
    if args.diagnostics and args.verify_once:
        parser.error("--diagnostics and --verify-once cannot be combined")
    if args.diagnostics:
        config = AgentConfig.from_env()
        oauth = GmailOAuth()
        store = SyncStore(config.state_path)
        print(json.dumps(build_diagnostics(store.get_state(), oauth.authorization_status()), indent=2))
        return
    if args.verify_once:
        try:
            result = verify_one_notification()
        except Exception as exc:
            print(json.dumps({"status": "FAILED", "error_category": type(exc).__name__}))
            raise SystemExit(1) from None
        print(json.dumps(result, sort_keys=True))
        return
    run_agent()


if __name__ == "__main__":
    main()
