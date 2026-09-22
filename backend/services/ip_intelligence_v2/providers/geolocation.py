import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from ..models import ProviderResult


def _request_json(
    url: str,
    headers: dict | None = None,
    timeout: int = 8
):
    request = urllib.request.Request(
        url,
        headers=headers or {
            "User-Agent": "MailTrace-AI/2.0"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout
    ) as response:

        raw = response.read().decode("utf-8")

        return json.loads(raw)


def query_ipapi(ip: str) -> ProviderResult:

    started = time.perf_counter()

    url = f"https://ipapi.co/{urllib.parse.quote(ip)}/json/"

    try:

        data = _request_json(url)

        if data.get("error"):

            return ProviderResult(
                provider="ipapi",
                success=False,
                error=data.get(
                    "reason",
                    "ipapi returned an error."
                ),
                latency_ms=round(
                    (time.perf_counter() - started) * 1000,
                    2
                )
            )

        return ProviderResult(
            provider="ipapi",
            success=True,
            data={
                "country": data.get("country_name"),
                "country_code": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone"),
                "continent": data.get("continent_code"),
                "asn": data.get("asn"),
                "organization": data.get("org"),
            },
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except urllib.error.HTTPError as error:

        return ProviderResult(
            provider="ipapi",
            success=False,
            error=f"HTTP {error.code}: {error.reason}",
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except Exception as error:

        return ProviderResult(
            provider="ipapi",
            success=False,
            error=str(error),
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )


def query_ipinfo(ip: str) -> ProviderResult:

    started = time.perf_counter()

    token = os.getenv("IPINFO_TOKEN")

    if not token:

        return ProviderResult(
            provider="ipinfo",
            success=False,
            error="IPINFO_TOKEN is not configured.",
            latency_ms=0
        )

    url = (
        f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
        f"?token={urllib.parse.quote(token)}"
    )

    try:

        data = _request_json(
            url,
            headers={
                "User-Agent": "MailTrace-AI/2.0"
            }
        )

        location = data.get("loc")

        latitude = None
        longitude = None

        if location and "," in location:

            lat, lon = location.split(",", 1)

            try:
                latitude = float(lat)
                longitude = float(lon)
            except ValueError:
                pass

        return ProviderResult(
            provider="ipinfo",
            success=True,
            data={
                "country_code": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": latitude,
                "longitude": longitude,
                "timezone": data.get("timezone"),
                "asn": (
                    data.get("org", "").split(" ", 1)[0]
                    if data.get("org")
                    else None
                ),
                "organization": data.get("org"),
                "hostname": data.get("hostname"),
            },
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except urllib.error.HTTPError as error:

        return ProviderResult(
            provider="ipinfo",
            success=False,
            error=f"HTTP {error.code}: {error.reason}",
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except Exception as error:

        return ProviderResult(
            provider="ipinfo",
            success=False,
            error=str(error),
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )


def get_geolocation(ip: str) -> list[ProviderResult]:

    results = []

    primary = query_ipapi(ip)
    results.append(primary)

    # Use IPinfo only when configured.
    # This avoids unnecessary authenticated calls.
    if os.getenv("IPINFO_TOKEN"):

        secondary = query_ipinfo(ip)
        results.append(secondary)

    return results
