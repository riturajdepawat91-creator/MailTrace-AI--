"""Safe, content-free connector errors."""


class GmailConnectorError(RuntimeError):
    """Base error whose message is safe for user-facing diagnostics."""


class ReconnectRequired(GmailConnectorError):
    """The user must authorize Gmail again before requests can continue."""


class GmailRateLimited(GmailConnectorError):
    """Gmail asked the client to retry later."""


class GmailUnavailable(GmailConnectorError):
    """Gmail API could not complete a request."""


class GmailNotFound(GmailConnectorError):
    """A Gmail resource or history cursor was not found."""


class GmailHistoryExpired(GmailNotFound):
    """The Gmail History API cursor is no longer valid."""


class PubSubConfigurationError(GmailConnectorError):
    """Local Pub/Sub settings or Cloud resources are missing/invalid."""


class SyncError(GmailConnectorError):
    """Mailbox synchronization could not be completed safely."""


class InvalidPubSubNotification(GmailConnectorError):
    """A poison or unrelated Pub/Sub message was safely rejected."""
