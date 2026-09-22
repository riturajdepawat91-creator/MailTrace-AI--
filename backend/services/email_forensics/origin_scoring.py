from __future__ import annotations

from typing import Any


# =========================================================
# SMART ORIGIN SCORING
# =========================================================

def score_origin_candidates(
    relay_chain: list[dict[str, Any]],
    ip_intelligence: dict[str, dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """
    Rank possible origin IP candidates.

    This is evidence-based ranking only.
    It does NOT claim attribution or identify an attacker.
    """

    ip_intelligence = ip_intelligence or {}
    candidates: dict[str, dict[str, Any]] = {}

    for hop in relay_chain:

        hop_number = hop.get("hop")
        hop_ips = hop.get("ips", [])
        hop_classifications = hop.get(
            "ip_classifications",
            []
        )

        for position, ip in enumerate(hop_ips):

            if not ip:
                continue

            intelligence = ip_intelligence.get(ip, {})

            relay_classification = (
                hop_classifications[position]
                if position < len(hop_classifications)
                else None
            )

            candidate = candidates.setdefault(
                ip,
                {
                    "ip": ip,
                    "score": 0,
                    "hop": hop_number,
                    "classification": None,
                    "hostname": None,
                    "organization": None,
                    "asn": None,
                    "risk": None,
                    "risk_score": None,
                    "confidence": None,
                    "reasons": [],
                }
            )

            # -------------------------------------------------
            # CLASSIFICATION
            # -------------------------------------------------

            classification = intelligence.get("type")

            if not classification:
                classification = relay_classification

            candidate["classification"] = (
                classification
                or candidate["classification"]
            )

            # -------------------------------------------------
            # ADDRESS FLAGS
            # -------------------------------------------------

            is_private = (
                intelligence.get("is_private") is True
                or relay_classification == "PRIVATE"
            )

            is_loopback = (
                intelligence.get("is_loopback") is True
                or relay_classification == "LOOPBACK"
            )

            is_reserved = (
                intelligence.get("is_reserved") is True
                or relay_classification == "RESERVED"
            )

            is_documentation = (
                intelligence.get("is_documentation") is True
            )

            # -------------------------------------------------
            # NON-PUBLIC IPs
            # -------------------------------------------------

            if is_private:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Private IP; not considered a public origin candidate."
                ]

                continue

            if is_loopback:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Loopback IP; not a remote origin candidate."
                ]

                continue

            if is_reserved:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Reserved IP space; not considered a public origin candidate."
                ]

                continue

            if is_documentation:

                candidate["score"] = 0
                candidate["reasons"] = [
                    "Documentation/test IP; not evidence of a real Internet origin."
                ]

                continue

            # -------------------------------------------------
            # PUBLIC ROUTABILITY
            # -------------------------------------------------

            candidate["score"] += 25

            candidate["reasons"].append(
                "Publicly routable IP candidate."
            )

            # -------------------------------------------------
            # RELAY POSITION
            # -------------------------------------------------

            if isinstance(hop_number, int):

                if hop_number == 1:

                    candidate["score"] += 20

                    candidate["reasons"].append(
                        "Appears at the earliest observed relay position."
                    )

                elif hop_number == 2:

                    candidate["score"] += 12

                    candidate["reasons"].append(
                        "Appears near the beginning of the observed relay chain."
                    )

                elif hop_number <= 4:

                    candidate["score"] += 6

                    candidate["reasons"].append(
                        "Appears relatively early in the observed relay chain."
                    )

            # -------------------------------------------------
            # REVERSE DNS
            # -------------------------------------------------

            hostname = intelligence.get("hostname")

            if hostname:

                candidate["hostname"] = hostname
                candidate["score"] += 5

                candidate["reasons"].append(
                    "Reverse DNS hostname observed."
                )

            # -------------------------------------------------
            # ORGANIZATION
            # -------------------------------------------------

            organization = intelligence.get("organization")

            if organization:

                candidate["organization"] = organization
                candidate["score"] += 5

                candidate["reasons"].append(
                    "Network organization identified."
                )

            # -------------------------------------------------
            # ASN
            # -------------------------------------------------

            asn = intelligence.get("asn")

            if asn:

                candidate["asn"] = asn
                candidate["score"] += 5

                candidate["reasons"].append(
                    "ASN identified."
                )

            # -------------------------------------------------
            # THREAT INTELLIGENCE
            # -------------------------------------------------

            risk = intelligence.get("risk")
            risk_score = intelligence.get("risk_score")
            confidence = intelligence.get("confidence")

            candidate["risk"] = risk
            candidate["risk_score"] = risk_score
            candidate["confidence"] = confidence

            if isinstance(risk_score, (int, float)):

                if risk_score >= 80:

                    candidate["score"] += 20

                    candidate["reasons"].append(
                        "Strong external threat indicators observed."
                    )

                elif risk_score >= 60:

                    candidate["score"] += 15

                    candidate["reasons"].append(
                        "Significant threat indicators observed."
                    )

                elif risk_score >= 30:

                    candidate["score"] += 5

                    candidate["reasons"].append(
                        "Moderate threat indicators observed."
                    )

            # -------------------------------------------------
            # HOSTING / DATA CENTER
            # -------------------------------------------------

            if intelligence.get("is_hosting") is True:

                candidate["score"] += 2

                candidate["reasons"].append(
                    "IP is associated with hosting or data-center infrastructure."
                )

    # =========================================================
    # NORMALIZE
    # =========================================================

    results = list(candidates.values())

    for candidate in results:

        candidate["score"] = max(
            0,
            min(
                int(candidate["score"]),
                100
            )
        )

    # =========================================================
    # SORT
    # =========================================================

    results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    # =========================================================
    # RANK
    # =========================================================

    for rank, candidate in enumerate(
        results,
        start=1
    ):
        candidate["rank"] = rank

    return results


# =========================================================
# TOP CANDIDATE
# =========================================================

def get_top_origin_candidate(
    candidates: list[dict[str, Any]]
) -> dict[str, Any] | None:

    if not candidates:
        return None

    return candidates[0]
