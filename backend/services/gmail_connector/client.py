"""Read-only Gmail REST client with bounded pagination and safe errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any, Callable

from .errors import (
    GmailConnectorError,
    GmailHistoryExpired,
    GmailNotFound,
    GmailRateLimited,
    GmailUnavailable,
    ReconnectRequired,
)
from .oauth import GmailOAuth
from .token_store import TokenStoreError

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
ALLOWED_FORMATS = {"minimal", "metadata", "full", "raw"}


class GmailClient:
    def __init__(self, oauth: GmailOAuth, *, urlopen: Callable[..., Any] = urllib.request.urlopen):
        self._oauth = oauth
        self._urlopen = urlopen

    def _get_json(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._request_json(path, params, method="GET")

    def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request_json(path, {}, method="POST", body=body)

    def _request_json(
        self,
        path: str,
        params: dict[str, Any],
        *,
        method: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = urllib.parse.urlencode(params, doseq=True)
        url = f"{GMAIL_API_BASE}{path}" + (f"?{query}" if query else "")
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._oauth.access_token()}",
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            },
            method=method,
        )
        try:
            with self._urlopen(request, timeout=25) as response:
                payload = response.read(2_000_000)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                try:
                    self._oauth.clear_local_authorization()
                except TokenStoreError:
                    pass
                raise ReconnectRequired("Gmail authorization is no longer accepted; reconnect is required.") from None
            if exc.code == 403:
                raise GmailConnectorError("Gmail API denied access; verify Gmail readonly consent and API availability.") from None
            if exc.code == 404:
                raise GmailNotFound("Gmail resource was not found.") from None
            if exc.code == 429:
                raise GmailRateLimited("Gmail API rate limit reached; retry later.") from None
            if exc.code >= 500:
                raise GmailUnavailable(f"Gmail API is temporarily unavailable (HTTP {exc.code}).") from None
            raise GmailConnectorError(f"Gmail API request failed (HTTP {exc.code}).") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GmailUnavailable("Gmail API could not be reached; check network connectivity.") from None
        try:
            result = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GmailUnavailable("Gmail API returned an invalid response.") from None
        if not isinstance(result, dict):
            raise GmailUnavailable("Gmail API returned an invalid response.")
        return result

    def get_profile(self) -> dict[str, Any]:
        """Return mailbox profile metadata; caller should avoid logging email address."""
        return self._get_json("/users/me/profile", {})

    def list_messages(
        self,
        *,
        page_token: str | None = None,
        page_size: int = 100,
        label_ids: tuple[str, ...] = ("INBOX",),
        query: str | None = None,
    ) -> dict[str, Any]:
        if not 1 <= page_size <= 500:
            raise ValueError("page_size must be between 1 and 500")
        params: dict[str, Any] = {"maxResults": page_size, "labelIds": list(label_ids)}
        if query:
            params["q"] = query
        if page_token:
            params["pageToken"] = page_token
        return self._get_json("/users/me/messages", params)

    def iter_messages(self, *, page_size: int = 100, max_messages: int = 1000) -> Iterator[dict[str, str]]:
        """Yield opaque IDs only; mailbox content is not fetched by listing."""
        if max_messages < 1:
            raise ValueError("max_messages must be positive")
        page_token: str | None = None
        yielded = 0
        while yielded < max_messages:
            page = self.list_messages(page_token=page_token, page_size=min(page_size, 500))
            for item in page.get("messages", []):
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    continue
                yield {"id": item["id"], **({"threadId": item["threadId"]} if isinstance(item.get("threadId"), str) else {})}
                yielded += 1
                if yielded >= max_messages:
                    return
            page_token = page.get("nextPageToken")
            if not isinstance(page_token, str) or not page_token:
                return

    def get_message(self, message_id: str, *, format: str = "metadata") -> dict[str, Any]:
        """Fetch one message; metadata is default to minimize content exposure."""
        if not message_id or len(message_id) > 1024:
            raise ValueError("message_id is required and must be at most 1024 characters")
        if format not in ALLOWED_FORMATS:
            raise ValueError("format must be one of minimal, metadata, full, raw")
        params: dict[str, Any] = {"format": format}
        if format == "metadata":
            params["metadataHeaders"] = ["From", "To", "Date", "Message-ID", "Authentication-Results"]
        return self._get_json(f"/users/me/messages/{urllib.parse.quote(message_id, safe='')}", params)

    def watch_inbox(self, topic_name: str) -> dict[str, Any]:
        """Create/renew an Inbox-only Gmail watch using the existing readonly scope."""
        if not topic_name.startswith("projects/") or "/topics/" not in topic_name:
            raise ValueError("topic_name must be a fully qualified Pub/Sub topic resource")
        result = self._post_json("/users/me/watch", {
            "topicName": topic_name,
            "labelIds": ["INBOX"],
            "labelFilterBehavior": "include",
        })
        if not str(result.get("historyId", "")).isdigit() or not str(result.get("expiration", "")).isdigit():
            raise GmailUnavailable("Gmail watch returned invalid lifecycle metadata.")
        return result

    def history_page(self, start_history_id: str, *, page_token: str | None = None) -> dict[str, Any]:
        if not str(start_history_id).isdigit():
            raise ValueError("start_history_id must be a Gmail history ID")
        params: dict[str, Any] = {
            "startHistoryId": start_history_id,
            "historyTypes": ["messageAdded"],
            "labelId": "INBOX",
            "maxResults": 100,
        }
        if page_token:
            params["pageToken"] = page_token
        try:
            result = self._get_json("/users/me/history", params)
        except GmailNotFound:
            raise GmailHistoryExpired("Gmail history cursor expired; bounded recovery is required.") from None
        if not str(result.get("historyId", "")).isdigit():
            raise GmailUnavailable("Gmail history response did not contain a valid cursor.")
        return result


__all__ = ["GmailClient", "GmailConnectorError", "GmailRateLimited", "GmailUnavailable", "ReconnectRequired"]
