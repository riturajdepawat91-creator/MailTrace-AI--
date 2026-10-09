from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


# =========================================================
# IOC NORMALIZER
# =========================================================

IP_PORT_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{1,5})"
    r"(?!\w)"
)

IP_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"(?![\w.-])"
)


def _clean(value: str) -> str:
    return str(value).strip().rstrip(
        ".,;:!?)]}>\"'"
    )


def normalize_ip(value: str) -> str | None:
    value = _clean(value)

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def normalize_url(value: str) -> str | None:
    value = _clean(value)

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    if not parsed.hostname:
        return None

    return value


def normalize_domain(value: str) -> str | None:
    value = _clean(value).lower().rstrip(".")

    if not value:
        return None

    if "@" in value:
        return None

    if "/" in value:
        return None

    if ":" in value:
        return None

    if not DOMAIN_PATTERN.fullmatch(value):
        return None

    return value


def extract_ip_ports(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PORT_PATTERN.finditer(text):
        ip = normalize_ip(match.group("ip"))

        if not ip:
            continue

        port = int(match.group("port"))

        if port < 1 or port > 65535:
            continue

        ioc = f"{ip}:{port}"

        if ioc.lower() in seen:
            continue

        seen.add(ioc.lower())

        results.append({
            "ioc": ioc,
            "ioc_type": "ip:port",
            "value": ip,
            "port": port,
        })

    return results


def extract_ips(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PATTERN.finditer(text):
        ip = normalize_ip(match.group(0))

        if not ip:
            continue

        key = ip.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": ip,
            "ioc_type": "ip",
            "value": ip,
        })

    return results


def extract_urls(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in URL_PATTERN.finditer(text):
        url = normalize_url(match.group(0))

        if not url:
            continue

        key = url.lower()

        if key in seen:
            continue

        seen.add(key)

        parsed = urlparse(url)

        results.append({
            "ioc": url,
            "ioc_type": "url",
            "value": url,
            "domain": parsed.hostname.lower()
            if parsed.hostname
            else None,
        })

    return results


def extract_domains(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in DOMAIN_PATTERN.finditer(text):
        domain = normalize_domain(match.group(0))

        if not domain:
            continue

        key = domain.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": domain,
            "ioc_type": "domain",
            "value": domain,
        })

    return results


def extract_iocs(text: str) -> list[dict]:
    """
    Extract and normalize IP, IP:port, URL and domain IOCs.

    Values are deduplicated while preserving discovery order.
    """

    if not text:
        return []

    results = []
    seen = set()

    groups = [
        extract_ip_ports(text),
        extract_ips(text),
        extract_urls(text),
        extract_domains(text),
    ]

    for group in groups:
        for item in group:
            ioc = item.get("ioc")

            if not ioc:
                continue

            key = ioc.strip().lower()

            if key in seen:
                continue

            seen.add(key)
            results.append(item)

    return results


def summarize_iocs(iocs: list[dict]) -> dict:
    summary = {
        "total": 0,
        "ip": 0,
        "ip:port": 0,
        "url": 0,
        "domain": 0,
    }

    for item in iocs or []:
        ioc_type = item.get("ioc_type")

        summary["total"] += 1

        if ioc_type in summary:
            summary[ioc_type] += 1

    return summary
