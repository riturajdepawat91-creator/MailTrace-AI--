"""
MailTrace AI — External Threat Intelligence Providers

Providers:
- ThreatFox
- URLhaus

No third-party HTTP package is required.
Uses Python standard-library urllib.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT.parent / ".env"


def _load_env_file() -> dict[str, str]:
    """
    Minimal .env loader.

    We intentionally do not print or expose secret values.
    """

    values: dict[str, str] = {}

    if not ENV_FILE.exists():
        return values

    try:
        for raw_line in ENV_FILE.read_text(
            encoding="utf-8"
        ).splitlines():

            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip()

            if (
                len(value) >= 2
                and value[0] == '"'
                and value[-1] == '"'
            ):
                value = value[1:-1]

            if (
                len(value) >= 2
                and value[0] == "'"
                and value[-1] == "'"
            ):
                value = value[1:-1]

            values[key] = value

    except Exception:
        return {}

    return values


def _get_secret(*names: str) -> str | None:

    env_values = _load_env_file()

    for name in names:

        value = os.getenv(name)

        if value:
            return value.strip()

        value = env_values.get(name)

        if value:
            return value.strip()

    return None


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:

    body = json.dumps(payload).encode("utf-8")

    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "MailTrace-AI/1.0",
    }

    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=request_headers,
        method="POST",
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:

        raw = response.read().decode(
            "utf-8",
            "replace",
        )

        return json.loads(raw)


def fetch_threatfox(days: int = 1) -> dict[str, Any]:

    auth_key = _get_secret(
        "THREATFOX_AUTH_KEY",
        "THREATFOX_API_KEY",
    )

    if not auth_key:
        return {
            "source": "threatfox",
            "configured": False,
            "success": False,
            "status": "not_configured",
            "count": 0,
            "data": [],
        }

    try:

        response = _post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {
                "query": "get_iocs",
                "days": max(
                    1,
                    min(int(days), 7),
                ),
            },
            headers={
                "Auth-Key": auth_key,
            },
        )

        data = response.get("data", [])

        if not isinstance(data, list):
            data = []

        return {
            "source": "threatfox",
            "configured": True,
            "success": response.get(
                "query_status"
            ) == "ok",
            "status": response.get(
                "query_status",
                "unknown",
            ),
            "count": len(data),
            "data": data,
        }

    except Exception as error:

        return {
            "source": "threatfox",
            "configured": True,
            "success": False,
            "status": "error",
            "count": 0,
            "data": [],
            "error": str(error),
        }


def search_threatfox(ioc: str) -> dict[str, Any]:

    auth_key = _get_secret(
        "THREATFOX_AUTH_KEY",
        "THREATFOX_API_KEY",
    )

    if not auth_key:
        return {
            "source": "threatfox",
            "configured": False,
            "success": False,
            "status": "not_configured",
            "count": 0,
            "data": [],
        }

    try:

        response = _post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {
                "query": "search_ioc",
                "search_term": ioc,
                "exact_match": True,
            },
            headers={
                "Auth-Key": auth_key,
            },
        )

        data = response.get("data", [])

        if not isinstance(data, list):
            data = []

        return {
            "source": "threatfox",
            "configured": True,
            "success": response.get(
                "query_status"
            ) == "ok",
            "status": response.get(
                "query_status",
                "unknown",
            ),
            "count": len(data),
            "data": data,
        }

    except Exception as error:

        return {
            "source": "threatfox",
            "configured": True,
            "success": False,
            "status": "error",
            "count": 0,
            "data": [],
            "error": str(error),
        }


def fetch_urlhaus_recent() -> dict[str, Any]:

    auth_key = _get_secret(
        "URLHAUS_AUTH_KEY",
        "URLHAUS_API_KEY",
    )

    if not auth_key:
        return {
            "source": "urlhaus",
            "configured": False,
            "success": False,
            "status": "not_configured",
            "count": 0,
            "data": [],
        }

    try:

        url = (
            "https://urlhaus-api.abuse.ch/v2/"
            "urls/recent/"
        )

        request = urllib.request.Request(
            url=url,
            headers={
                "Accept": "application/json",
                "Auth-Key": auth_key,
                "User-Agent": "MailTrace-AI/1.0",
            },
            method="GET",
        )

        with urllib.request.urlopen(
            request,
            timeout=20,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                "replace",
            )

            payload = json.loads(raw)

        data = payload.get(
            "urls",
            payload.get("data", []),
        )

        if not isinstance(data, list):
            data = []

        return {
            "source": "urlhaus",
            "configured": True,
            "success": True,
            "status": "ok",
            "count": len(data),
            "data": data,
        }

    except Exception as error:

        return {
            "source": "urlhaus",
            "configured": True,
            "success": False,
            "status": "error",
            "count": 0,
            "data": [],
            "error": str(error),
        }


def normalize_threatfox(item: dict[str, Any]) -> dict[str, Any]:

    return {
        "source": "threatfox",
        "external_id": str(
            item.get("id", "")
        ),
        "ioc": str(
            item.get("ioc", "")
        ),
        "ioc_type": str(
            item.get("ioc_type", "")
        ),
        "threat_type": str(
            item.get("threat_type", "")
        ),
        "malware": str(
            item.get("malware_printable")
            or item.get("malware")
            or ""
        ),
        "confidence": int(
            item.get(
                "confidence_level",
                0,
            )
            or 0
        ),
        "first_seen": str(
            item.get("first_seen", "")
        ),
        "last_seen": str(
            item.get("last_seen", "")
        ),
        "reference": str(
            item.get("reference", "")
        ),
        "raw_json": json.dumps(
            item,
            ensure_ascii=False,
        ),
    }


def normalize_urlhaus(item: dict[str, Any]) -> dict[str, Any]:

    return {
        "source": "urlhaus",
        "external_id": str(
            item.get("id", "")
        ),
        "ioc": str(
            item.get("url", "")
        ),
        "ioc_type": "url",
        "threat_type": str(
            item.get("threat", "")
        ),
        "malware": str(
            item.get("payloads")
            or item.get("tags")
            or ""
        ),
        "confidence": 0,
        "first_seen": str(
            item.get("date_added", "")
        ),
        "last_seen": str(
            item.get("last_online", "")
        ),
        "reference": str(
            item.get("urlhaus_reference", "")
        ),
        "raw_json": json.dumps(
            item,
            ensure_ascii=False,
        ),
    }


class ThreatIntelligenceEngine:

    @staticmethod
    def provider_status() -> dict[str, Any]:

        threatfox_key = _get_secret(
            "THREATFOX_AUTH_KEY",
            "THREATFOX_API_KEY",
        )

        urlhaus_key = _get_secret(
            "URLHAUS_AUTH_KEY",
            "URLHAUS_API_KEY",
        )

        return {
            "threatfox": {
                "configured": bool(
                    threatfox_key
                ),
                "status": (
                    "ready"
                    if threatfox_key
                    else "not_configured"
                ),
            },
            "urlhaus": {
                "configured": bool(
                    urlhaus_key
                ),
                "status": (
                    "ready"
                    if urlhaus_key
                    else "not_configured"
                ),
            },
        }

    @staticmethod
    def sync(
        days: int = 1,
    ) -> dict[str, Any]:

        threatfox = fetch_threatfox(days)

        urlhaus = fetch_urlhaus_recent()

        normalized: list[dict[str, Any]] = []

        for item in threatfox.get(
            "data",
            [],
        ):

            if isinstance(item, dict):

                normalized.append(
                    normalize_threatfox(item)
                )

        for item in urlhaus.get(
            "data",
            [],
        ):

            if isinstance(item, dict):

                normalized.append(
                    normalize_urlhaus(item)
                )

        return {
            "success": (
                threatfox.get("success", False)
                or urlhaus.get("success", False)
            ),
            "providers": {
                "threatfox": {
                    "success": threatfox.get(
                        "success",
                        False,
                    ),
                    "configured": threatfox.get(
                        "configured",
                        False,
                    ),
                    "count": threatfox.get(
                        "count",
                        0,
                    ),
                    "status": threatfox.get(
                        "status",
                    ),
                },
                "urlhaus": {
                    "success": urlhaus.get(
                        "success",
                        False,
                    ),
                    "configured": urlhaus.get(
                        "configured",
                        False,
                    ),
                    "count": urlhaus.get(
                        "count",
                        0,
                    ),
                    "status": urlhaus.get(
                        "status",
                    ),
                },
            },
            "count": len(normalized),
            "indicators": normalized,
        }
