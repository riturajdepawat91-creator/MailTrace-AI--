"""Desktop OAuth 2.0 Authorization Code + PKCE for Gmail readonly only."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .errors import ReconnectRequired
from .token_store import DpapiTokenStore, TokenStoreError

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def _default_client_secrets_path() -> Path:
    configured_path = os.environ.get("MAILTRACE_GMAIL_CREDENTIALS_PATH", "").strip()
    if configured_path:
        return Path(configured_path).expanduser()
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    root = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    return root / "mailtrace" / "secrets" / "credentials.json"


DEFAULT_CLIENT_SECRETS_PATH = _default_client_secrets_path()
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
TOKEN_EXPIRY_SKEW_SECONDS = 60


class OAuthConfigurationError(RuntimeError):
    """OAuth client setup is missing or invalid; never includes secret values."""


@dataclass(frozen=True)
class DesktopClient:
    client_id: str
    client_secret: str
    auth_uri: str
    token_uri: str


def load_desktop_client(path: Path = DEFAULT_CLIENT_SECRETS_PATH) -> DesktopClient:
    """Load only the configured external desktop credentials file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OAuthConfigurationError("Gmail OAuth credentials file is unavailable at the configured external path.") from exc
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OAuthConfigurationError("Gmail OAuth credentials file is not valid JSON.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("installed"), dict):
        raise OAuthConfigurationError("Gmail OAuth credentials must use a Desktop application client.")
    installed = document["installed"]
    required = ("client_id", "client_secret", "auth_uri", "token_uri", "redirect_uris")
    if any(not installed.get(key) for key in required) or not isinstance(installed.get("redirect_uris"), list):
        raise OAuthConfigurationError("Gmail OAuth Desktop client configuration is incomplete.")
    if not all(isinstance(installed.get(key), str) for key in required[:4]):
        raise OAuthConfigurationError("Gmail OAuth Desktop client configuration has invalid field types.")
    if not all(isinstance(uri, str) and uri for uri in installed["redirect_uris"]):
        raise OAuthConfigurationError("Gmail OAuth Desktop redirect configuration is invalid.")
    auth_uri = urlparse(installed["auth_uri"])
    token_uri = urlparse(installed["token_uri"])
    if (auth_uri.scheme, auth_uri.hostname, auth_uri.path) not in {
        ("https", "accounts.google.com", "/o/oauth2/v2/auth"),
        ("https", "accounts.google.com", "/o/oauth2/auth"),
    } or (token_uri.scheme, token_uri.hostname, token_uri.path) != (
        "https", "oauth2.googleapis.com", "/token"
    ):
        raise OAuthConfigurationError("OAuth endpoints must use the approved Google HTTPS endpoints.")
    return DesktopClient(
        client_id=installed["client_id"],
        client_secret=installed["client_secret"],
        auth_uri=installed["auth_uri"],
        token_uri=installed["token_uri"],
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorization_url(client: DesktopClient, redirect_uri: str, state: str, challenge: str) -> str:
    query = urllib.parse.urlencode({
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    })
    return client.auth_uri + ("&" if "?" in client.auth_uri else "?") + query


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = "MailTraceOAuth/1"
    sys_version = ""

    def log_message(self, _format: str, *args: Any) -> None:
        # Callback URLs contain authorization codes; do not log request lines.
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        expected_state = self.server.expected_state  # type: ignore[attr-defined]
        state = query.get("state", [""])[0]
        error = query.get("error", [""])[0]
        code = query.get("code", [""])[0]
        if parsed.path != "/oauth2callback" or not secrets.compare_digest(state, expected_state):
            self.server.callback_result = (None, "invalid_callback")  # type: ignore[attr-defined]
            status, message = 400, "Authorization could not be completed. You may close this window."
        elif error:
            self.server.callback_result = (None, "authorization_denied")  # type: ignore[attr-defined]
            status, message = 400, "Gmail authorization was not completed. You may close this window."
        elif not code or len(code) > 8192:
            self.server.callback_result = (None, "invalid_callback")  # type: ignore[attr-defined]
            status, message = 400, "Authorization could not be completed. You may close this window."
        else:
            self.server.callback_result = (code, None)  # type: ignore[attr-defined]
            status, message = 200, "MailTrace Gmail authorization is complete. You may close this window."
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GmailOAuth:
    def __init__(
        self,
        token_store: DpapiTokenStore | Any | None = None,
        *,
        credentials_path: Path = DEFAULT_CLIENT_SECRETS_PATH,
        opener: Callable[[str], bool] = webbrowser.open,
        urlopen: Callable[..., Any] = urllib.request.urlopen,
    ):
        self.token_store = token_store or DpapiTokenStore()
        self.credentials_path = Path(credentials_path)
        self._opener = opener
        self._urlopen = urlopen

    def _client(self) -> DesktopClient:
        return load_desktop_client(self.credentials_path)

    def authorize(self, *, timeout_seconds: int = 180) -> dict[str, Any]:
        """Open system browser and perform a loopback PKCE authorization."""
        client = self._client()
        verifier, challenge = create_pkce_pair()
        state = secrets.token_urlsafe(32)
        server = http.server.HTTPServer(("127.0.0.1", 0), _CallbackHandler)
        server.timeout = 0.5
        server.expected_state = state  # type: ignore[attr-defined]
        server.callback_result = (None, None)  # type: ignore[attr-defined]
        redirect_uri = f"http://127.0.0.1:{server.server_port}/oauth2callback"
        auth_url = build_authorization_url(client, redirect_uri, state, challenge)
        if not self._opener(auth_url):
            server.server_close()
            raise OAuthConfigurationError("Could not open the system browser for Gmail authorization.")
        deadline = time.monotonic() + max(1, min(timeout_seconds, 600))
        try:
            while time.monotonic() < deadline:
                server.handle_request()
                code, error = server.callback_result  # type: ignore[attr-defined]
                if code:
                    token = self._exchange_code(client, code, redirect_uri, verifier)
                    self._validate_token_scope(token)
                    self.token_store.save(token)
                    return token
                if error:
                    raise OAuthConfigurationError("Gmail authorization was denied or the local callback was invalid.")
            raise OAuthConfigurationError("Gmail authorization timed out; reconnect to try again.")
        finally:
            server.server_close()

    def _post_form(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._urlopen(request, timeout=20) as response:
                payload = response.read(65536)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                error_data = json.loads(exc.read(65536))
            except Exception:
                error_data = {}
            if isinstance(error_data, dict) and error_data.get("error") == "invalid_grant":
                raise ReconnectRequired("Gmail authorization expired or was revoked; reconnect is required.") from None
            raise OAuthConfigurationError(f"Google OAuth request failed (HTTP {status}).") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise OAuthConfigurationError("Google OAuth service is unavailable; retry when connected.") from None
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise OAuthConfigurationError("Google OAuth returned an invalid response.") from None
        if not isinstance(value, dict):
            raise OAuthConfigurationError("Google OAuth returned an invalid response.")
        return value

    def _exchange_code(self, client: DesktopClient, code: str, redirect_uri: str, verifier: str) -> dict[str, Any]:
        token = self._post_form(client.token_uri, {
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        })
        token["expires_at"] = time.time() + max(0, int(token.get("expires_in", 0)))
        token["scope"] = token.get("scope", GMAIL_READONLY_SCOPE)
        self._validate_token_scope(token)
        if not token.get("refresh_token"):
            raise OAuthConfigurationError("Google did not issue offline access; reconnect with the approved OAuth setup.")
        return token

    @staticmethod
    def _validate_token_scope(token: dict[str, Any]) -> None:
        scopes = set(str(token.get("scope", "")).split())
        if scopes != {GMAIL_READONLY_SCOPE}:
            raise OAuthConfigurationError("Google authorization did not grant exactly the approved Gmail readonly scope.")

    def access_token(self) -> str:
        try:
            token = self.token_store.load()
        except TokenStoreError:
            raise ReconnectRequired("The protected Gmail authorization is unavailable; reconnect is required.") from None
        if not token:
            raise ReconnectRequired("Gmail is not connected; authorize the mailbox first.")
        self._validate_token_scope(token)
        expires_at = float(token.get("expires_at") or 0)
        if token.get("access_token") and expires_at > time.time() + TOKEN_EXPIRY_SKEW_SECONDS:
            return str(token["access_token"])
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            self.token_store.delete()
            raise ReconnectRequired("Gmail authorization expired; reconnect is required.")
        client = self._client()
        try:
            refreshed = self._post_form(client.token_uri, {
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "refresh_token": str(refresh_token),
                "grant_type": "refresh_token",
            })
        except ReconnectRequired:
            self.token_store.delete()
            raise
        if refreshed.get("error") == "invalid_grant":
            self.token_store.delete()
            raise ReconnectRequired("Gmail authorization was revoked or expired; reconnect is required.")
        if "access_token" not in refreshed:
            raise ReconnectRequired("Gmail authorization could not be refreshed; reconnect is required.")
        refreshed["refresh_token"] = refresh_token
        refreshed["expires_at"] = time.time() + max(0, int(refreshed.get("expires_in", 0)))
        refreshed["scope"] = refreshed.get("scope", GMAIL_READONLY_SCOPE)
        self._validate_token_scope(refreshed)
        self.token_store.save(refreshed)
        return str(refreshed["access_token"])

    def logout(self) -> None:
        """Revoke the stored refresh token, then remove local protected state."""
        try:
            token = self.token_store.load()
        except TokenStoreError:
            self.token_store.delete()
            raise ReconnectRequired("Local Gmail authorization was removed; reconnect is required.") from None
        if not token:
            return
        refresh_token = token.get("refresh_token")
        if refresh_token:
            request = urllib.request.Request(
                GOOGLE_REVOKE_URL,
                data=urllib.parse.urlencode({"token": str(refresh_token)}).encode("ascii"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with self._urlopen(request, timeout=20):
                    pass
            except urllib.error.HTTPError as exc:
                if exc.code != 400:  # Revoked/unknown token is already disconnected.
                    raise OAuthConfigurationError("Google could not confirm Gmail permission revocation.") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise OAuthConfigurationError("Could not reach Google to revoke Gmail permission; local token was retained.") from None
        self.token_store.delete()

    def clear_local_authorization(self) -> None:
        """Forget protected local state after a server-rejected bearer token."""
        self.token_store.delete()

    def authorization_status(self) -> str:
        """Return a coarse local-only state without exposing token data or making network calls."""
        try:
            token = self.token_store.load()
        except TokenStoreError:
            return "UNAVAILABLE"
        if not token:
            return "NOT_CONNECTED"
        try:
            self._validate_token_scope(token)
        except OAuthConfigurationError:
            return "RECONNECT_REQUIRED"
        return "CONNECTED"
