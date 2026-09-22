from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any


# =========================================================
# TIMELINE ANALYZER
# =========================================================

def _parse_date(value: str | None) -> datetime | None:
    """
    Parse an RFC-style email date.
    """

    if not value:
        return None

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None


def analyze_timeline(
    headers: dict[str, Any]
) -> dict[str, Any]:
    """
    Analyze available email timestamps.

    This module only evaluates timestamps that are actually
    present in the email headers. Missing timestamps are not
    treated as suspicious.
    """

    received_headers = headers.get(
        "received",
        []
    )

    message_date = headers.get(
        "date"
    )

    parsed_message_date = _parse_date(
        message_date
    )

    # ---------------------------------------------------------
    # BASIC TIMELINE
    # ---------------------------------------------------------

    timeline: list[dict[str, Any]] = []

    if parsed_message_date:

        timeline.append({
            "type": "message_date",
            "timestamp": parsed_message_date.isoformat(),
            "source": "Date"
        })

    # ---------------------------------------------------------
    # RECEIVED TIMESTAMPS
    # ---------------------------------------------------------

    received_with_dates: list[dict[str, Any]] = []

    for index, header in enumerate(
        received_headers,
        start=1
    ):

        timestamp = None

        # Received headers normally end with:
        # ; Thu, 27 Aug 2026 18:00:00 +0530
        if ";" in header:

            date_part = header.rsplit(
                ";",
                1
            )[1].strip()

            parsed = _parse_date(
                date_part
            )

            if parsed:

                timestamp = parsed

        item = {
            "hop": index,
            "raw": header,
            "timestamp": (
                timestamp.isoformat()
                if timestamp
                else None
            )
        }

        received_with_dates.append(
            item
        )

        if timestamp:

            timeline.append({
                "type": "received",
                "hop": index,
                "timestamp": timestamp.isoformat(),
                "source": "Received"
            })

    # ---------------------------------------------------------
    # ORDER ANALYSIS
    # ---------------------------------------------------------

    dated_received = [
        item
        for item in received_with_dates
        if item["timestamp"]
    ]

    chronological_order = "UNKNOWN"

    if len(dated_received) >= 2:

        timestamps = [
            datetime.fromisoformat(
                item["timestamp"]
            )
            for item in dated_received
        ]

        ascending = all(
            timestamps[i] <= timestamps[i + 1]
            for i in range(
                len(timestamps) - 1
            )
        )

        descending = all(
            timestamps[i] >= timestamps[i + 1]
            for i in range(
                len(timestamps) - 1
            )
        )

        if ascending:
            chronological_order = "ASCENDING"

        elif descending:
            chronological_order = "DESCENDING"

        else:
            chronological_order = "INCONSISTENT"

    # ---------------------------------------------------------
    # HOP DELTAS
    # ---------------------------------------------------------

    hop_deltas: list[dict[str, Any]] = []

    if len(dated_received) >= 2:

        for index in range(
            len(dated_received) - 1
        ):

            current = datetime.fromisoformat(
                dated_received[index]["timestamp"]
            )

            next_item = datetime.fromisoformat(
                dated_received[index + 1]["timestamp"]
            )

            delta_seconds = (
                next_item - current
            ).total_seconds()

            hop_deltas.append({
                "from_hop": dated_received[index]["hop"],
                "to_hop": dated_received[index + 1]["hop"],
                "delta_seconds": delta_seconds
            })

    # ---------------------------------------------------------
    # SUSPICIOUS TIMING
    # ---------------------------------------------------------

    findings: list[dict[str, Any]] = []

    for delta in hop_deltas:

        seconds = delta["delta_seconds"]

        if seconds < 0:

            findings.append({
                "type": "timestamp_order",
                "severity": "HIGH",
                "title": "Received timestamps are out of order",
                "description": (
                    "A later observed relay timestamp appears "
                    "earlier than the preceding relay timestamp."
                ),
                "from_hop": delta["from_hop"],
                "to_hop": delta["to_hop"],
                "delta_seconds": seconds
            })

    # ---------------------------------------------------------
    # MESSAGE DATE COMPARISON
    # ---------------------------------------------------------

    if parsed_message_date and dated_received:

        first_received = datetime.fromisoformat(
            dated_received[0]["timestamp"]
        )

        message_delta = (
            first_received - parsed_message_date
        ).total_seconds()

        if message_delta < 0:

            findings.append({
                "type": "message_date",
                "severity": "MEDIUM",
                "title": "Message Date is later than a Received timestamp",
                "description": (
                    "The visible Date header appears later than "
                    "an observed Received timestamp."
                ),
                "delta_seconds": message_delta
            })

    # ---------------------------------------------------------
    # OVERALL STATUS
    # ---------------------------------------------------------

    if any(
        finding["severity"] == "HIGH"
        for finding in findings
    ):
        status = "SUSPICIOUS"

    elif findings:
        status = "REVIEW"

    elif dated_received:
        status = "CONSISTENT"

    else:
        status = "INSUFFICIENT_DATA"

    # ---------------------------------------------------------
    # SORT TIMELINE
    # ---------------------------------------------------------

    timeline.sort(
        key=lambda item: item["timestamp"]
    )

    return {
        "message_date": (
            parsed_message_date.isoformat()
            if parsed_message_date
            else None
        ),
        "received_count": len(
            received_headers
        ),
        "received_with_dates": received_with_dates,
        "dated_received_count": len(
            dated_received
        ),
        "chronological_order": chronological_order,
        "hop_deltas": hop_deltas,
        "timeline": timeline,
        "status": status,
        "findings": findings,
        "finding_count": len(findings)
    }
