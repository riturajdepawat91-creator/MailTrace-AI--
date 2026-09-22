from __future__ import annotations

import re
from typing import Any


# =========================================================
# RELAY CHAIN
# =========================================================

FROM_PATTERN = re.compile(
    r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|;|$)",
    re.IGNORECASE
)

BY_PATTERN = re.compile(
    r"\bby\s+([^\s;]+)",
    re.IGNORECASE
)


def build_relay_chain(
    received_headers: list[str],
    ip_candidates: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """
    Convert Received headers into an ordered relay chain.

    Important:
    RFC Received headers are normally added at the top,
    so the oldest hop appears later in the header list.

    This function therefore reverses the header order
    for chronological relay analysis.
    """

    ip_candidates = ip_candidates or []

    chain: list[dict[str, Any]] = []

    # -----------------------------------------------------
    # OLDEST -> NEWEST
    # -----------------------------------------------------

    ordered_headers = list(
        reversed(received_headers)
    )

    for hop_index, header in enumerate(
        ordered_headers
    ):

        if not header:
            continue

        from_match = FROM_PATTERN.search(header)
        by_match = BY_PATTERN.search(header)

        from_host = (
            from_match.group(1).strip()
            if from_match
            else None
        )

        by_host = (
            by_match.group(1).strip()
            if by_match
            else None
        )

        # -------------------------------------------------
        # MATCH IPs BELONGING TO THIS HEADER
        # -------------------------------------------------

        header_ips = [
            item
            for item in ip_candidates
            if item.get("source_header") == header
        ]

        ips = [
            item.get("ip")
            for item in header_ips
            if item.get("ip")
        ]

        classifications = [
            item.get("classification")
            for item in header_ips
            if item.get("classification")
        ]

        chain.append({
            "hop": hop_index + 1,
            "from": from_host,
            "by": by_host,
            "ips": ips,
            "ip_classifications": classifications,
            "header": header,
            "header_index": (
                received_headers.index(header)
                if header in received_headers
                else None
            ),
            "has_public_ip": any(
                item.get("is_public") is True
                for item in header_ips
            ),
        })

    return chain


def summarize_relay_chain(
    chain: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Generate a compact relay-chain summary.
    """

    public_hops = [
        hop
        for hop in chain
        if hop.get("has_public_ip")
    ]

    private_hops = [
        hop
        for hop in chain
        if any(
            classification == "PRIVATE"
            for classification
            in hop.get(
                "ip_classifications",
                []
            )
        )
    ]

    return {
        "hop_count": len(chain),
        "public_hop_count": len(public_hops),
        "private_hop_count": len(private_hops),
        "first_hop": (
            chain[0]
            if chain
            else None
        ),
        "last_hop": (
            chain[-1]
            if chain
            else None
        ),
    }
