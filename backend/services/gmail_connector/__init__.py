"""Read-only Gmail desktop connector for the MailTrace local prototype."""

from .client import GmailClient, GmailConnectorError, ReconnectRequired
from .oauth import GmailOAuth, OAuthConfigurationError
from .token_store import DpapiTokenStore, TokenStoreError

__all__ = [
    "DpapiTokenStore",
    "GmailClient",
    "GmailConnectorError",
    "GmailOAuth",
    "OAuthConfigurationError",
    "ReconnectRequired",
    "TokenStoreError",
]
