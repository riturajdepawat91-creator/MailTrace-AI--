import json
import time

import pytest

from services.gmail_connector.agent import process_delivery, run_agent, verify_one_notification
from services.gmail_connector.errors import GmailHistoryExpired, InvalidPubSubNotification, PubSubConfigurationError, SyncError
from services.gmail_connector.store import SyncStore
from services.gmail_connector.sync import GmailSyncEngine


class FakeGmail:
    def __init__(self):
        self.pages = []
        self.watch_calls = 0
        self.list_calls = []
        self.history_calls = []
        self.expire_once = False

    def watch_inbox(self, topic):
        self.watch_calls += 1
        return {"historyId": "200", "expiration": "1999999999999"}

    def history_page(self, start, *, page_token=None):
        self.history_calls.append((start, page_token))
        if self.expire_once:
            self.expire_once = False
            raise GmailHistoryExpired("expired")
        return self.pages.pop(0) if self.pages else {"historyId": "200", "history": []}

    def list_messages(self, **kwargs):
        self.list_calls.append(kwargs)
        return {"messages": [{"id": "recent-1"}], "nextPageToken": None}

    def get_message(self, message_id, *, format="metadata"):
        return {"id": message_id, "internalDate": str(int(time.time() * 1000))}


class FakeSubscriber:
    def __init__(self, events=None):
        self.events = events if events is not None else []
        self.acks = []

    def acknowledge(self, ack_ids):
        self.events.append("ack")
        self.acks.extend(ack_ids)


def setup_engine(tmp_path):
    store = SyncStore(tmp_path / "sync.sqlite3")
    store.begin_bootstrap("100", 1999999999999)
    gmail = FakeGmail()
    engine = GmailSyncEngine(gmail, store, recovery_window_hours=24, recovery_max_messages=10)
    engine.set_topic("projects/demo-project/topics/mailtrace")
    return engine, gmail, store


def notification(history="999"):
    return json.dumps({"emailAddress": "analyst@example.test", "historyId": history}).encode()


def test_pubsub_uses_history_cursor_not_notification_hint_and_dedupes(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    gmail.pages = [
        {"historyId": "102", "history": [{"messagesAdded": [{"message": {"id": "m-1", "labelIds": ["INBOX"]}}]}], "nextPageToken": "p2"},
        {"historyId": "103", "history": [{"messagesAdded": [{"message": {"id": "m-1", "labelIds": ["INBOX"]},}, {"message": {"id": "m-2", "labelIds": ["INBOX"]}}]}]},
    ]
    assert engine.process_notification(notification("999"), "analyst@example.test") == 2
    assert gmail.history_calls == [("100", None), ("100", "p2")]
    assert store.get_history_id() == "103"
    gmail.pages = [{"historyId": "103", "history": [{"messagesAdded": [{"message": {"id": "m-2", "labelIds": ["INBOX"]}}]}]}]
    assert engine.process_notification(notification("101"), "analyst@example.test") == 0
    assert set(store.detected_message_ids()) == {"m-1", "m-2"}


def test_wrong_mailbox_and_malformed_notification_rejected(tmp_path):
    engine, _, _ = setup_engine(tmp_path)
    with pytest.raises(InvalidPubSubNotification):
        engine.process_notification(notification(), "other@example.test")
    with pytest.raises(InvalidPubSubNotification):
        engine.process_notification(b"not-json", "analyst@example.test")


def test_integer_history_id_is_accepted_but_durable_cursor_drives_sync(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    payload = json.dumps({"emailAddress": "analyst@example.test", "historyId": 987654321}).encode()
    assert engine.process_notification(payload, "analyst@example.test") == 0
    assert gmail.history_calls == [("100", None)]
    assert store.get_history_id() == "200"


def test_integer_notification_one_shot_commits_before_ack_without_watch(monkeypatch, tmp_path):
    import services.gmail_connector.agent as agent_module
    engine, gmail, store = setup_engine(tmp_path)
    gmail.pages = [{"historyId": "101", "history": [{"messagesAdded": [{"message": {"id": "new-ref", "labelIds": ["INBOX"]}}]}]}]
    events = []

    class Api:
        def get_profile(self): return {"emailAddress": "analyst@example.test"}
        def __getattr__(self, name): return getattr(gmail, name)

    monkeypatch.setattr(agent_module, "GmailClient", lambda oauth: Api())
    monkeypatch.setattr(agent_module, "SyncStore", lambda path: store)

    class Config:
        state_path = tmp_path / "unused.sqlite3"
        topic_name = "projects/demo-project/topics/mailtrace"
        subscription_name = "projects/demo-project/subscriptions/agent"
        recovery_window_hours = 24
        recovery_max_messages = 10
        pull_timeout_seconds = 3

    class Subscriber(FakeSubscriber):
        def validate_subscription(self, topic): pass
        def pull_once(self, **kwargs):
            assert kwargs == {"timeout_seconds": 3, "max_messages": 1}
            return [type("Delivery", (), {"ack_id": "ack", "message": type("Message", (), {"data": notification(7000)})()})()]
        def acknowledge(self, ack_ids):
            assert store.get_history_id() == "101"
            events.append("ack")
            super().acknowledge(ack_ids)
        def close(self): events.append("closed")

    subscriber = Subscriber()
    result = verify_one_notification(Config(), oauth=object(), subscriber=subscriber)
    assert result == {"status": "SYNCED_AND_ACKED", "pulled_count": 1, "new_message_reference_count": 1, "acknowledged_count": 1}
    assert events == ["ack", "closed"]
    assert gmail.history_calls == [("100", None)]
    assert gmail.watch_calls == 0


def test_one_shot_empty_subscription_does_not_ack_or_register_watch(monkeypatch, tmp_path):
    import services.gmail_connector.agent as agent_module
    _, gmail, store = setup_engine(tmp_path)

    class Api:
        def get_profile(self): return {"emailAddress": "analyst@example.test"}

    monkeypatch.setattr(agent_module, "GmailClient", lambda oauth: Api())
    monkeypatch.setattr(agent_module, "SyncStore", lambda path: store)

    class Config:
        state_path = tmp_path / "unused.sqlite3"
        topic_name = "projects/demo-project/topics/mailtrace"
        subscription_name = "projects/demo-project/subscriptions/agent"
        recovery_window_hours = 24
        recovery_max_messages = 10
        pull_timeout_seconds = 3

    class Subscriber(FakeSubscriber):
        def validate_subscription(self, topic): pass
        def pull_once(self, **kwargs): return []
        def close(self): pass

    subscriber = Subscriber()
    result = verify_one_notification(Config(), oauth=object(), subscriber=subscriber)
    assert result == {"status": "EMPTY", "pulled_count": 0, "new_message_reference_count": 0, "acknowledged_count": 0}
    assert subscriber.acks == []
    assert gmail.watch_calls == 0


def test_digit_string_history_id_is_accepted_and_normalized(tmp_path):
    engine, gmail, _ = setup_engine(tmp_path)
    payload = json.dumps({"emailAddress": "analyst@example.test", "historyId": "000123"}).encode()
    assert engine.process_notification(payload, "analyst@example.test") == 0
    assert gmail.history_calls == [("100", None)]


def test_notification_history_id_normalizes_to_decimal_string():
    from services.gmail_connector.sync import _normalize_notification_history_id
    assert _normalize_notification_history_id(12345) == "12345"
    assert _normalize_notification_history_id("000123") == "123"


@pytest.mark.parametrize("history_value", [True, False, -1, 0, 1.5, None, "", "-1", "1.5", "１２"])
def test_invalid_history_id_values_are_rejected(tmp_path, history_value):
    engine, gmail, _ = setup_engine(tmp_path)
    payload = json.dumps({"emailAddress": "analyst@example.test", "historyId": history_value}).encode()
    with pytest.raises(InvalidPubSubNotification):
        engine.process_notification(payload, "analyst@example.test")
    assert gmail.history_calls == []


def test_missing_history_id_is_rejected(tmp_path):
    engine, gmail, _ = setup_engine(tmp_path)
    payload = json.dumps({"emailAddress": "analyst@example.test"}).encode()
    with pytest.raises(InvalidPubSubNotification):
        engine.process_notification(payload, "analyst@example.test")
    assert gmail.history_calls == []


def test_oversized_notification_is_rejected_before_sync(tmp_path):
    engine, gmail, _ = setup_engine(tmp_path)
    with pytest.raises(InvalidPubSubNotification):
        engine.process_notification(b" " * 16385, "analyst@example.test")
    assert gmail.history_calls == []


def test_invalid_notification_is_recorded_before_ack_without_persisting_payload(tmp_path):
    engine, _, store = setup_engine(tmp_path)
    payload = json.dumps({
        "emailAddress": "analyst@example.test",
        "historyId": True,
        "body": "SENSITIVE_TEST_BODY",
    }).encode()

    class CheckingSubscriber(FakeSubscriber):
        def acknowledge(self, ack_ids):
            assert store.get_state()["rejected_notification_count"] == 1
            super().acknowledge(ack_ids)

    subscriber = CheckingSubscriber()

    class Delivery:
        ack_id = "reject-ack"
        class message:
            data = payload

    assert process_delivery(engine, subscriber, Delivery(), "analyst@example.test", store) == 0
    assert subscriber.acks == ["reject-ack"]
    persisted = b"".join(path.read_bytes() for path in tmp_path.iterdir() if path.is_file())
    assert payload not in persisted
    assert b"SENSITIVE_TEST_BODY" not in persisted


def test_pubsub_ack_occurs_after_durable_sync(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    events = []
    subscriber = FakeSubscriber(events)
    gmail.pages = [{"historyId": "101", "history": [{"messagesAdded": [{"message": {"id": "m-1", "labelIds": ["INBOX"]}}]}]}]

    class ObservableEngine:
        def process_notification(self, data, email):
            count = engine.process_notification(data, email)
            assert store.get_history_id() == "101"
            events.append("commit")
            return count

    class Delivery:
        ack_id = "transport-ack"
        class message:
            data = notification()

    assert process_delivery(ObservableEngine(), subscriber, Delivery(), "analyst@example.test") == 1
    assert events == ["commit", "ack"]


def test_sync_failure_does_not_ack_delivery(tmp_path):
    engine, gmail, _ = setup_engine(tmp_path)
    subscriber = FakeSubscriber()
    class FailingGmail(FakeGmail):
        def history_page(self, start, *, page_token=None):
            raise RuntimeError("offline")
    engine.client = FailingGmail()

    class Delivery:
        ack_id = "transport-ack"
        class message:
            data = notification()

    with pytest.raises(RuntimeError):
        process_delivery(engine, subscriber, Delivery(), "analyst@example.test")
    assert subscriber.acks == []


def test_malformed_pubsub_payload_is_durably_recorded_before_ack(tmp_path):
    engine, _, store = setup_engine(tmp_path)
    events = []
    subscriber = FakeSubscriber(events)
    class Delivery:
        ack_id = "bad-payload"
        class message:
            data = b"not-json"
    assert process_delivery(engine, subscriber, Delivery(), "analyst@example.test", store) == 0
    assert store.get_state()["rejected_notification_count"] == 1
    assert subscriber.acks == ["bad-payload"]


def test_polling_uses_same_sync_cursor_and_records_poll_timestamp(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    gmail.pages = [{"historyId": "101", "history": [{"messagesAdded": [{"message": {"id": "poll-1", "labelIds": ["INBOX"]}}]}]}]
    assert engine.sync_until_current("poll") == 1
    state = store.get_state()
    assert state["history_id"] == "101"
    assert state["last_poll_ms"] is not None
    assert store.detected_message_ids() == ["poll-1"]


def test_diagnostics_excludes_message_ids_and_content(tmp_path):
    from services.gmail_connector.diagnostics import build_diagnostics
    engine, gmail, store = setup_engine(tmp_path)
    gmail.pages = [{"historyId": "101", "history": [{"messagesAdded": [{"message": {"id": "opaque-secret-id", "labelIds": ["INBOX"]}}]}]}]
    engine.sync_until_current("poll")
    result = build_diagnostics(store.get_state(), "CONNECTED")
    serialized = json.dumps(result)
    assert result["pending_sync_jobs"] == 1
    assert result["last_scan_timestamp_ms"] is None
    assert "opaque-secret-id" not in serialized
    assert "body" not in serialized.lower()


def test_expired_history_recovers_with_bounded_inbox_query(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    gmail.expire_once = True
    assert engine.sync_until_current("poll") == 0
    assert gmail.watch_calls == 1
    assert len(gmail.list_calls) == 1
    assert gmail.list_calls[0]["label_ids"] == ("INBOX",)
    assert gmail.list_calls[0]["query"] == "newer_than:1d"
    assert store.get_history_id() == "200"
    assert store.detected_message_ids() == ["recent-1"]


def test_state_restart_keeps_cursor_and_duplicate_prevention(tmp_path):
    path = tmp_path / "restart.sqlite3"
    store = SyncStore(path)
    store.begin_bootstrap("10", 1999999999999)
    store.commit_sync("11", {"same"}, source="history")
    restarted = SyncStore(path)
    assert restarted.get_history_id() == "11"
    assert restarted.commit_sync("12", {"same"}, source="history") == 0


def test_watch_renewal_only_when_inside_safety_window(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)
    store.record_watch_renewal(5_000_000)
    assert engine.renew_watch_if_due(now_ms=1_000_000, renew_before_seconds=100) is False
    assert engine.renew_watch_if_due(now_ms=4_999_950, renew_before_seconds=100) is True
    assert gmail.watch_calls == 1


def test_pubsub_client_ack_adapter_and_configured_dependency_failure(monkeypatch):
    from services.gmail_connector.pubsub import PubSubPullSubscriber

    class Client:
        def __init__(self): self.acks = []
        def pull(self, *, subscription, max_messages, return_immediately, timeout):
            self.pull_args = (subscription, max_messages, return_immediately, timeout)
            return type("Response", (), {"received_messages": []})()
        def get_subscription(self, request): return type("Subscription", (), {"topic": "projects/p/topics/t"})()
        def acknowledge(self, request): self.acks.append(request)

    client = Client()
    subscriber = PubSubPullSubscriber("projects/p/subscriptions/s", client=client)
    subscriber.validate_subscription("projects/p/topics/t")
    assert subscriber.pull_once() == []
    assert client.pull_args == ("projects/p/subscriptions/s", 5, True, 5)
    subscriber.acknowledge(["ack"])
    assert client.acks == [{"subscription": "projects/p/subscriptions/s", "ack_ids": ["ack"]}]


def test_pubsub_adapter_returns_successful_delivery_without_acknowledging():
    from services.gmail_connector.pubsub import PubSubPullSubscriber
    delivery = object()

    class Client:
        def pull(self, **kwargs):
            self.kwargs = kwargs
            return type("Response", (), {"received_messages": [delivery]})()

    client = Client()
    subscriber = PubSubPullSubscriber("projects/p/subscriptions/s", client=client)
    assert subscriber.pull_once(timeout_seconds=3, max_messages=1) == [delivery]
    assert client.kwargs["return_immediately"] is True
    assert client.kwargs["timeout"] == 3


def test_pubsub_rpc_timeout_is_sanitized_and_does_not_ack():
    from services.gmail_connector.pubsub import PubSubPullSubscriber

    class TimeoutClient:
        def pull(self, **kwargs):
            self.kwargs = kwargs
            raise TimeoutError("sensitive transport details")

    client = TimeoutClient()
    subscriber = PubSubPullSubscriber("projects/p/subscriptions/s", client=client)
    with pytest.raises(PubSubConfigurationError, match="Pub/Sub pull failed") as error:
        subscriber.pull_once(timeout_seconds=2, max_messages=1)
    assert "sensitive transport details" not in str(error.value)
    assert client.kwargs["return_immediately"] is True
    assert client.kwargs["timeout"] == 2


def test_agent_runs_history_poll_after_empty_pull(monkeypatch, tmp_path):
    import services.gmail_connector.agent as agent_module
    events = []

    class Config:
        state_path = tmp_path / "state.sqlite3"
        topic_name = "projects/p/topics/t"
        subscription_name = "projects/p/subscriptions/s"
        recovery_window_hours = 24
        recovery_max_messages = 10
        watch_renew_before_seconds = 3600
        pull_timeout_seconds = 2
        poll_interval_seconds = 60

    class OAuth:
        def authorization_status(self): return "CONNECTED"

    class Store:
        def __init__(self, path): pass
        def record_failure(self, *args, **kwargs): pass

    class GmailApi:
        def __init__(self, oauth): pass
        def get_profile(self): return {"emailAddress": "analyst@example.test"}

    class Engine:
        def __init__(self, *args, **kwargs): pass
        def set_topic(self, topic): pass
        def renew_watch_if_due(self, **kwargs): pass
        def sync_until_current(self, source): events.append(("history_sync", source))

    class Subscriber:
        def validate_subscription(self, topic): pass
        def pull_once(self, **kwargs):
            events.append(("pull", kwargs["timeout_seconds"]))
            return []
        def close(self): pass

    monkeypatch.setattr(agent_module, "SyncStore", Store)
    monkeypatch.setattr(agent_module, "GmailClient", GmailApi)
    monkeypatch.setattr(agent_module, "GmailSyncEngine", Engine)
    monkeypatch.setattr(agent_module.time, "monotonic", lambda: 100.0)
    run_agent(Config(), oauth=OAuth(), subscriber=Subscriber(), stop_after=1)
    assert events == [("pull", 2), ("history_sync", "poll")]


def test_agent_config_requires_project_matched_fully_qualified_resources(tmp_path):
    from services.gmail_connector.config import AgentConfig
    from services.gmail_connector.errors import PubSubConfigurationError
    env = {
        "MAILTRACE_GMAIL_GCP_PROJECT": "demo-project-123",
        "MAILTRACE_GMAIL_PUBSUB_TOPIC": "projects/demo-project-123/topics/mailtrace",
        "MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION": "projects/demo-project-123/subscriptions/agent",
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
    }
    assert AgentConfig.from_env(env).state_path.name == "sync.sqlite3"
    with pytest.raises(PubSubConfigurationError):
        AgentConfig.from_env({**env, "MAILTRACE_GMAIL_PUBSUB_TOPIC": "projects/other-project/topics/mailtrace"})


def test_network_failure_keeps_cursor_and_next_poll_recovers(tmp_path):
    engine, gmail, store = setup_engine(tmp_path)

    class OneFailure(FakeGmail):
        failed = False
        def history_page(self, start, *, page_token=None):
            if not self.failed:
                self.failed = True
                raise RuntimeError("temporary network loss")
            return {"historyId": "101", "history": [{"messagesAdded": [{"message": {"id": "recovered", "labelIds": ["INBOX"]}}]}]}

    engine.client = OneFailure()
    with pytest.raises(RuntimeError):
        engine.sync_until_current("poll")
    assert store.get_history_id() == "100"
    assert engine.sync_until_current("poll") == 1
    assert store.get_history_id() == "101"
