import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from ..models import ProviderResult


def query_abuseipdb(ip: str) -> ProviderResult:

    started = time.perf_counter()

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:

        return ProviderResult(
            provider="abuseipdb",
            success=False,
            error="ABUSEIPDB_API_KEY is not configured.",
            latency_ms=0
        )

    url = (
        "https://api.abuseipdb.com/api/v2/check?"
        + urllib.parse.urlencode({
            "ipAddress": ip,
            "maxAgeInDays": 90
        })
    )

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Key": api_key,
            "User-Agent": "MailTrace-AI/2.0"
        }
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        abuse = data.get("data", {})

        return ProviderResult(
            provider="abuseipdb",
            success=True,
            data={
                "abuse_confidence_score":
                    abuse.get("abuseConfidenceScore"),

                "total_reports":
                    abuse.get("totalReports"),

                "last_reported_at":
                    abuse.get("lastReportedAt"),

                "is_whitelisted":
                    abuse.get("isWhitelisted"),

                "country_code":
                    abuse.get("countryCode"),

                "usage_type":
                    abuse.get("usageType"),

                "isp":
                    abuse.get("isp"),

                "domain":
                    abuse.get("domain"),

                "hostnames":
                    abuse.get("hostnames", []),
            },
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except urllib.error.HTTPError as error:

        return ProviderResult(
            provider="abuseipdb",
            success=False,
            error=f"HTTP {error.code}: {error.reason}",
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )

    except Exception as error:

        return ProviderResult(
            provider="abuseipdb",
            success=False,
            error=str(error),
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2
            )
        )


def get_reputation(ip: str) -> list[ProviderResult]:

    results = []

    result = query_abuseipdb(ip)

    results.append(result)

    return results
