"""Small lazy-loaded Pub/Sub pull adapter; cloud identity remains separate from Gmail OAuth."""
from __future__ import annotations

from typing import Any

from .errors import PubSubConfigurationError


class PubSubPullSubscriber:
    def __init__(self, subscription_name: str, *, client: Any | None = None):
        self.subscription_name = subscription_name
        if client is None:
            try:
                from google.cloud import pubsub_v1
            except ImportError:
                raise PubSubConfigurationError("Install the pinned google-cloud-pubsub dependency to enable pull subscription.") from None
            try:
                client = pubsub_v1.SubscriberClient()
            except Exception:
                raise PubSubConfigurationError("Google Cloud ADC could not initialize the Pub/Sub subscriber identity.") from None
        self._client = client

    def pull_once(self, *, timeout_seconds: int = 5, max_messages: int = 5) -> list[Any]:
        try:
            response = self._client.pull(
                subscription=self.subscription_name,
                max_messages=max(1, min(max_messages, 20)),
                return_immediately=True,
                timeout=max(1, min(timeout_seconds, 30)),
            )
            return list(response.received_messages)
        except Exception:
            raise PubSubConfigurationError("Pub/Sub pull failed; check ADC, subscription access, and network connectivity.") from None

    def validate_subscription(self, expected_topic: str | None = None) -> None:
        """Confirm the ADC principal can read this subscription and its topic binding."""
        try:
            subscription = self._client.get_subscription(request={"subscription": self.subscription_name})
            topic = getattr(subscription, "topic", None)
            if not topic or (expected_topic and topic != expected_topic):
                raise ValueError("missing topic")
        except Exception:
            raise PubSubConfigurationError("Pub/Sub subscription is unavailable or ADC lacks subscriber access.") from None

    def acknowledge(self, ack_ids: list[str]) -> None:
        if not ack_ids:
            return
        try:
            self._client.acknowledge(request={"subscription": self.subscription_name, "ack_ids": ack_ids})
        except Exception:
            raise PubSubConfigurationError("Pub/Sub acknowledgment failed; messages may be redelivered safely.") from None

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()
