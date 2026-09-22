import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error

from ..models import ProviderResult


def query_ipapi_network(ip: str) -> ProviderResult:

    started = time.perf_counter()

    url = (
        f"https://ipapi.co/"
        f"{urllib.parse.quote(ip)}/json/"
    )

    try:

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "MailTrace-AI/2.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("error"):

            return ProviderResult(
                provider="ipapi_network",
                success=False,
                error=data.get(
                    "reason",
                    "Network intelligence lookup failed."
                ),
                latency_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2
                )
            )

        return ProviderResult(
            provider="ipapi_network",
            success=True,
            data={
                "asn": data.get("asn"),
                "organization": data.get("org"),
                "network": data.get("network"),
                "version": data.get("version"),
            },
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except urllib.error.HTTPError as error:

        return ProviderResult(
            provider="ipapi_network",
            success=False,
            error=f"HTTP {error.code}: {error.reason}",
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except Exception as error:

        return ProviderResult(
            provider="ipapi_network",
            success=False,
            error=str(error),
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )


def classify_network(
    organization: str | None,
    hostname: str | None,
    asn: str | None
) -> dict:

    text = " ".join(
        value.lower()
        for value in (
            organization,
            hostname,
            asn
        )
        if value
    )

    hosting_keywords = (
        "amazon",
        "aws",
        "google cloud",
        "google llc",
        "microsoft",
        "azure",
        "digitalocean",
        "linode",
        "vultr",
        "ovh",
        "hetzner",
        "oracle cloud",
        "cloudflare",
        "data center",
        "datacenter",
        "hosting",
        "host"
    )

    hosting_matches = [
        keyword
        for keyword in hosting_keywords
        if keyword in text
    ]

    return {
        "hosting_signal": bool(hosting_matches),
        "hosting_matches": hosting_matches,
        "classification": (
            "cloud_or_hosting_infrastructure"
            if hosting_matches
            else "unknown_network_type"
        )
    }
