import json
import io
import os
import time
import urllib.error

import pytest

from services.gmail_connector.client import GmailClient
from services.gmail_connector.errors import GmailConnectorError, GmailRateLimited, GmailUnavailable, ReconnectRequired
from services.gmail_connector.oauth import (
    GMAIL_READONLY_SCOPE,
    GmailOAuth,
    OAuthConfigurationError,
    build_authorization_url,
    create_pkce_pair,
    load_desktop_client,
)
from services.gmail_connector.token_store import DpapiTokenStore, TokenStoreError, WindowsDpapi


class FakeProtector:
    """Reversible test protector; production code uses Windows DPAPI."""

    def protect(self, plaintext):
        return bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, ciphertext):
        return bytes(value ^ 0xA5 for value in ciphertext)


class MemoryTokenStore:
    def __init__(self, value=None):
        self.value = value
        self.deleted = False

    def load(self):
        return self.value

    def save(self, value):
        self.value = value

    def delete(self):
        self.value = None
        self.deleted = True

    def clear_local_authorization(self):
        self.delete()


class FakeResponse:
    def __init__(self, value, status=200):
        self.value = value
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return json.dumps(self.value).encode()


def test_pkce_pair_is_s256_and_verifier_has_valid_length():
    import base64
    import hashlib

    verifier, challenge = create_pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert 43 <= len(verifier) <= 128
    assert challenge == expected


def test_authorization_url_requests_only_gmail_readonly_with_pkce():
    from urllib.parse import parse_qs, urlparse
    from services.gmail_connector.oauth import DesktopClient

    client = DesktopClient("synthetic-client", "synthetic-secret",
                           "https://accounts.google.com/o/oauth2/v2/auth",
                           "https://oauth2.googleapis.com/token")
    url = build_authorization_url(client, "http://127.0.0.1:45000/oauth2callback", "state", "challenge")
    query = parse_qs(urlparse(url).query)
    assert query["scope"] == [GMAIL_READONLY_SCOPE]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["challenge"]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert "gmail.send" not in query["scope"][0]


def test_credentials_loader_accepts_desktop_shape_without_logging_secrets(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"installed": {
        "client_id": "synthetic-client-id",
        "client_secret": "synthetic-client-secret",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }}), encoding="utf-8")
    client = load_desktop_client(path)
    assert client.client_id == "synthetic-client-id"
    assert client.token_uri == "https://oauth2.googleapis.com/token"


def test_credentials_loader_rejects_web_client_and_bad_json(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text('{"web": {}}', encoding="utf-8")
    with pytest.raises(OAuthConfigurationError, match="Desktop"):
        load_desktop_client(path)
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(OAuthConfigurationError, match="valid JSON"):
        load_desktop_client(path)


def test_dpapi_token_store_persists_only_protected_bytes(tmp_path):
    path = tmp_path / "oauth.dpapi"
    store = DpapiTokenStore(path, protector=FakeProtector())
    tokens = {"access_token": "synthetic-access-token", "scope": GMAIL_READONLY_SCOPE}
    store.save(tokens)
    assert b"synthetic-access-token" not in path.read_bytes()
    assert store.load() == tokens
    store.delete()
    assert not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI is only available on Windows")
def test_windows_dpapi_round_trip():
    protector = WindowsDpapi()
    protected = protector.protect(b"synthetic-refresh-token")
    assert b"synthetic-refresh-token" not in protected
    assert protector.unprotect(protected) == b"synthetic-refresh-token"


def test_oauth_refresh_preserves_refresh_token_and_stores_new_access_token(tmp_path):
    store = DpapiTokenStore(tmp_path / "oauth.dpapi", protector=FakeProtector())
    store.save({
        "refresh_token": "synthetic-refresh-token",
        "access_token": "old-access-token",
        "expires_at": time.time() - 10,
        "scope": GMAIL_READONLY_SCOPE,
    })
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"installed": {
        "client_id": "synthetic-client-id", "client_secret": "synthetic-client-secret",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["http://localhost"],
    }}), encoding="utf-8")
    observed = {}

    def fake_urlopen(request, timeout):
        observed["body"] = request.data.decode()
        observed["timeout"] = timeout
        return FakeResponse({"access_token": "synthetic-new-access", "expires_in": 3600,
                             "scope": GMAIL_READONLY_SCOPE})

    oauth = GmailOAuth(store, credentials_path=credentials, urlopen=fake_urlopen)
    assert oauth.access_token() == "synthetic-new-access"
    saved = store.load()
    assert saved["refresh_token"] == "synthetic-refresh-token"
    assert saved["access_token"] == "synthetic-new-access"
    assert "gmail.readonly" not in observed["body"]  # refresh grants use prior consent, no broader scope


def test_oauth_invalid_grant_requires_reconnect_and_removes_local_token(tmp_path):
    store = MemoryTokenStore({"refresh_token": "synthetic", "scope": GMAIL_READONLY_SCOPE,
                              "expires_at": 0})
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"installed": {
        "client_id": "synthetic", "client_secret": "synthetic",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["http://localhost"],
    }}), encoding="utf-8")

    def rejected(_request, timeout):
        raise urllib.error.HTTPError(
            "https://oauth2.googleapis.com/token", 400, "bad request", {},
            io.BytesIO(b'{"error":"invalid_grant","error_description":"synthetic secret detail"}'),
        )

    oauth = GmailOAuth(store, credentials_path=credentials, urlopen=rejected)
    with pytest.raises(ReconnectRequired, match="expired or was revoked"):
        oauth.access_token()
    assert store.deleted


def test_gmail_list_paginates_and_yields_ids_only():
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, request.get_header("Authorization"), timeout))
        if len(calls) == 1:
            return FakeResponse({"messages": [{"id": "m1", "threadId": "t1"}], "nextPageToken": "page-2"})
        return FakeResponse({"messages": [{"id": "m2", "threadId": "t2"}]})

    client = GmailClient(MemoryTokenStore(), urlopen=fake_urlopen)
    client._oauth.access_token = lambda: "synthetic-access"
    assert list(client.iter_messages(page_size=1, max_messages=5)) == [
        {"id": "m1", "threadId": "t1"}, {"id": "m2", "threadId": "t2"}
    ]
    assert "labelIds=INBOX" in calls[0][0]
    assert "pageToken=page-2" in calls[1][0]
    assert calls[0][1] == "Bearer synthetic-access"


def test_get_message_defaults_to_metadata_and_can_fetch_full():
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        return FakeResponse({"id": "message-id", "payload": {"headers": []}})

    client = GmailClient(MemoryTokenStore(), urlopen=fake_urlopen)
    client._oauth.access_token = lambda: "synthetic-access"
    client.get_message("message/id")
    client.get_message("message-id", format="full")
    assert "format=metadata" in calls[0]
    assert "metadataHeaders=From" in calls[0]
    assert "message%2Fid" in calls[0]
    assert "format=full" in calls[1]
    with pytest.raises(ValueError):
        client.get_message("message-id", format="send")


@pytest.mark.parametrize("status,expected", [(401, ReconnectRequired), (403, GmailConnectorError),
                                               (429, GmailRateLimited), (503, GmailUnavailable)])
def test_gmail_http_errors_are_sanitized(status, expected):
    def denied(_request, timeout):
        raise urllib.error.HTTPError("https://gmail.googleapis.com", status, "failed", {}, None)

    client = GmailClient(MemoryTokenStore(), urlopen=denied)
    client._oauth.access_token = lambda: "synthetic-access"
    with pytest.raises(expected) as caught:
        client.get_profile()
    assert "synthetic-sensitive-response" not in str(caught.value)
    assert "synthetic-access" not in str(caught.value)


def test_revocation_failure_keeps_token_for_retry():
    store = MemoryTokenStore({"refresh_token": "synthetic-refresh", "scope": GMAIL_READONLY_SCOPE})

    def offline(_request, timeout):
        raise urllib.error.URLError("synthetic sensitive detail")

    oauth = GmailOAuth(store, urlopen=offline)
    with pytest.raises(OAuthConfigurationError, match="Could not reach Google"):
        oauth.logout()
    assert store.value["refresh_token"] == "synthetic-refresh"


def test_logout_revokes_refresh_token_then_clears_local_cache():
    store = MemoryTokenStore({"refresh_token": "synthetic-refresh-token", "scope": GMAIL_READONLY_SCOPE})
    calls = []

    def revoke(request, timeout):
        calls.append((request.full_url, request.data.decode(), timeout))
        return FakeResponse({})

    oauth = GmailOAuth(store, urlopen=revoke)
    oauth.logout()
    assert store.deleted
    assert store.value is None
    assert "token=synthetic-refresh-token" in calls[0][1]
    assert "synthetic-refresh-token" not in calls[0][0]

