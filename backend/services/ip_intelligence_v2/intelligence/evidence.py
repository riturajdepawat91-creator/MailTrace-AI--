from collections import defaultdict
from typing import Any

from ..models import Evidence, ProviderResult


# ==========================================
# EVIDENCE V3
# Correlated / Explainable Evidence Engine
# ==========================================


FIELD_CONFIDENCE = {
    "hostname": 0.85,
    "country": 0.75,
    "city": 0.65,
    "asn": 0.85,
    "organization": 0.80,
    "hosting_signal": 0.60,
    "abuse_confidence_score": 0.90,
    "total_reports": 0.90,
}


FIELD_DESCRIPTIONS = {
    "hostname": "Reverse DNS hostname observed.",
    "country": "Country returned by geolocation provider.",
    "city": "City returned by geolocation provider.",
    "asn": "Autonomous System Number observed.",
    "organization": "Network organization observed.",
    "hosting_signal": "Hosting/cloud infrastructure indicator.",
    "abuse_confidence_score": "External abuse-reputation score.",
    "total_reports": "Number of abuse reports returned by provider.",
}


def _normalize_value(
    field: str,
    value: Any
) -> str:

    if value is None:
        return ""

    if isinstance(value, bool):
        return str(value).lower()

    text = str(value).strip().lower()

    if field in {
        "hostname",
        "organization",
        "country",
        "city",
    }:
        return " ".join(text.split())

    if field == "asn":
        return text.replace(" ", "").upper()

    return text


def _build_correlations(
    evidence: list[dict]
) -> None:

    groups: dict[
        tuple[str, str],
        list[dict]
    ] = defaultdict(list)

    for item in evidence:

        field = item.get("field")
        value = item.get("value")

        if field is None or value is None:
            continue

        normalized = _normalize_value(
            field,
            value
        )

        if not normalized:
            continue

        groups[
            (field, normalized)
        ].append(item)

    # --------------------------------------
    # Add correlation metadata
    # --------------------------------------

    field_values: dict[
        str,
        set[str]
    ] = defaultdict(set)

    field_sources: dict[
        tuple[str, str],
        set[str]
    ] = defaultdict(set)

    for item in evidence:

        field = item.get("field")
        value = item.get("value")

        if field is None or value is None:
            continue

        normalized = _normalize_value(
            field,
            value
        )

        if not normalized:
            continue

        field_values[field].add(normalized)

        field_sources[
            (field, normalized)
        ].add(
            str(item.get("source", "unknown"))
        )

    for item in evidence:

        field = item.get("field")
        value = item.get("value")

        if field is None or value is None:
            continue

        normalized = _normalize_value(
            field,
            value
        )

        sources = field_sources.get(
            (field, normalized),
            set()
        )

        unique_values = field_values.get(
            field,
            set()
        )

        item["normalized_value"] = normalized

        item["source_count"] = len(
            sources
        )

        item["agreement_count"] = len(
            sources
        )

        item["corroborated"] = (
            len(sources) >= 2
        )

        item["conflict"] = (
            len(unique_values) > 1
        )

        if item["corroborated"]:

            item["evidence_strength"] = "strong"

        elif item["conflict"]:

            item["evidence_strength"] = "conflicted"

        else:

            item["evidence_strength"] = "single_source"

        # ----------------------------------
        # Correlation-adjusted confidence
        # ----------------------------------

        base_confidence = float(
            item.get("confidence", 0.0)
        )

        if item["corroborated"]:

            # Additional independent support,
            # capped at 0.99.
            adjusted = min(
                base_confidence
                + min(
                    (len(sources) - 1) * 0.07,
                    0.14
                ),
                0.99
            )

        elif item["conflict"]:

            # Conflicting providers reduce
            # certainty without automatically
            # increasing threat.
            adjusted = max(
                base_confidence - 0.15,
                0.10
            )

        else:

            adjusted = base_confidence

        item["confidence"] = round(
            adjusted,
            3
        )

        item["provenance"] = {
            "sources": sorted(sources),
            "independent_sources": len(
                sources
            ),
        }


def build_evidence(
    ip: str,
    provider_results: list[ProviderResult],
    profile: dict
) -> list[dict]:

    evidence: list[dict] = []

    def add(
        source: str,
        category: str,
        field: str,
        value: Any,
        confidence: float,
        description: str
    ):

        if value is None:
            return

        evidence.append(
            Evidence(
                source=source,
                category=category,
                field=field,
                value=value,
                confidence=confidence,
                description=description
            ).__dict__
        )

    # ======================================
    # ADDRESS CLASSIFICATION
    # ======================================

    address_flags = (
        (
            "is_private",
            "Private/non-routable address."
        ),
        (
            "is_loopback",
            "Loopback address."
        ),
        (
            "is_reserved",
            "Reserved address space."
        ),
        (
            "is_documentation",
            "Documentation/test address; "
            "not evidence of a real sender."
        ),
    )

    for field, description in address_flags:

        if profile.get(field):

            add(
                "local_validation",
                "network",
                field,
                True,
                1.0,
                description
            )

    # ======================================
    # PROVIDER EVIDENCE
    # ======================================

    for result in provider_results:

        if not result.success:
            continue

        data = result.data or {}

        field_mapping = (
            (
                "hostname",
                "dns"
            ),
            (
                "country",
                "geolocation"
            ),
            (
                "city",
                "geolocation"
            ),
            (
                "asn",
                "network"
            ),
            (
                "organization",
                "network"
            ),
            (
                "hosting_signal",
                "network"
            ),
            (
                "abuse_confidence_score",
                "reputation"
            ),
            (
                "total_reports",
                "reputation"
            ),
        )

        for field, category in field_mapping:

            value = data.get(field)

            if value is None:
                continue

            if field == "hosting_signal" and not value:
                continue

            add(
                result.provider,
                category,
                field,
                value,
                FIELD_CONFIDENCE.get(
                    field,
                    0.50
                ),
                FIELD_DESCRIPTIONS.get(
                    field,
                    f"{field} observed."
                )
            )

    # ======================================
    # CORRELATION
    # ======================================

    _build_correlations(
        evidence
    )

    # ======================================
    # Evidence-level summary metadata
    # ======================================

    for item in evidence:

        item["ip"] = ip

    return evidence
