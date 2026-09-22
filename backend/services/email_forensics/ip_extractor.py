from __future__ import annotations

import ipaddress
import re
from typing import Any


# =========================================================
# IP EXTRACTION
# =========================================================

IP_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r")"
    r"(?![0-9A-Fa-f:.])"
)


def extract_ip_candidates(
    received_headers: list[str]
) -> list[dict[str, Any]]:
    """
    Extract and classify IP addresses from Received headers.

    This module does not perform attribution.
    It only creates validated IP candidates and their
    local network classification.
    """

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    for header_index, header in enumerate(
        received_headers
    ):

        if not header:
            continue

        matches = IP_PATTERN.findall(header)

        for raw_ip in matches:

            try:
                address = ipaddress.ip_address(
                    raw_ip
                )
            except ValueError:
                continue

            normalized_ip = str(address)

            if normalized_ip in seen:
                continue

            seen.add(normalized_ip)

            if address.is_private:
                classification = "PRIVATE"

            elif address.is_loopback:
                classification = "LOOPBACK"

            elif address.is_reserved:
                classification = "RESERVED"

            elif address.is_link_local:
                classification = "LINK_LOCAL"

            elif address.is_unspecified:
                classification = "UNSPECIFIED"

            else:
                classification = "PUBLIC"

            candidates.append({
                "ip": normalized_ip,
                "version": address.version,
                "classification": classification,
                "is_public": (
                    classification == "PUBLIC"
                ),
                "header_index": header_index,
                "source_header": header
            })

    return candidates


def extract_public_ips(
    received_headers: list[str]
) -> list[str]:
    """
    Return only unique publicly routable IP candidates.
    """

    candidates = extract_ip_candidates(
        received_headers
    )

    return [
        item["ip"]
        for item in candidates
        if item["is_public"]
    ]
