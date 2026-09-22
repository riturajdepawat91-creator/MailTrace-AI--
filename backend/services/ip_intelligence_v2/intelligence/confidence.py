from collections import defaultdict

from ..models import ProviderResult


# ==========================================
# CONFIDENCE V3
# Correlation-Aware Intelligence Confidence
# ==========================================


def _clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 1.0
) -> float:

    return min(
        max(value, minimum),
        maximum
    )


def calculate_confidence(
    provider_results: list[ProviderResult],
    evidence: list[dict]
) -> float:
    """
    Calculate confidence in the collected IP intelligence.

    Confidence is NOT a maliciousness score.

    V3 considers:

    - provider coverage
    - evidence quality
    - cross-provider corroboration
    - conflicting observations
    - independent source count
    - information diversity

    The calculation intentionally avoids treating duplicate
    provider observations as independent malicious signals.
    """

    # ======================================
    # PROVIDER COVERAGE
    # ======================================

    total_providers = len(
        provider_results
    )

    successful_providers = [
        result
        for result in provider_results
        if result.success
    ]

    successful_count = len(
        successful_providers
    )

    if total_providers == 0:
        return 0.0

    coverage = (
        successful_count /
        total_providers
    )

    coverage = _clamp(
        coverage
    )

    # ======================================
    # NO INTELLIGENCE
    # ======================================

    if successful_count == 0 or not evidence:

        return round(
            coverage * 0.25,
            3
        )

    # ======================================
    # EVIDENCE QUALITY
    # ======================================

    quality_values = []

    for item in evidence:

        try:

            quality = float(
                item.get(
                    "confidence",
                    0.0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            quality = 0.0

        quality_values.append(
            _clamp(quality)
        )

    evidence_quality = (
        sum(quality_values) /
        len(quality_values)
        if quality_values
        else 0.0
    )

    # ======================================
    # CORROBORATION
    # ======================================

    corroborated = [
        item
        for item in evidence
        if item.get("corroborated") is True
    ]

    corroboration_ratio = (
        len(corroborated) /
        len(evidence)
        if evidence
        else 0.0
    )

    corroboration_ratio = _clamp(
        corroboration_ratio
    )

    # ======================================
    # CONFLICT DETECTION
    # ======================================

    conflicted = [
        item
        for item in evidence
        if item.get("conflict") is True
    ]

    conflict_ratio = (
        len(conflicted) /
        len(evidence)
        if evidence
        else 0.0
    )

    conflict_ratio = _clamp(
        conflict_ratio
    )

    # ======================================
    # INDEPENDENT SOURCE DIVERSITY
    # ======================================

    sources = set()

    for item in evidence:

        provenance = item.get(
            "provenance"
        )

        if isinstance(
            provenance,
            dict
        ):

            for source in provenance.get(
                "sources",
                []
            ):

                if source:
                    sources.add(
                        str(source)
                    )

        else:

            source = item.get(
                "source"
            )

            if source:
                sources.add(
                    str(source)
                )

    source_diversity = min(
        len(sources) / 4.0,
        1.0
    )

    # ======================================
    # FIELD DIVERSITY
    # ======================================

    fields = {
        str(item.get("field"))
        for item in evidence
        if item.get("field")
    }

    field_diversity = min(
        len(fields) / 7.0,
        1.0
    )

    # ======================================
    # AGREEMENT QUALITY
    # ======================================

    agreement_values = []

    for item in evidence:

        try:

            agreement_count = int(
                item.get(
                    "agreement_count",
                    1
                )
            )

        except (
            TypeError,
            ValueError
        ):

            agreement_count = 1

        # 1 source = neutral baseline.
        # 2+ independent sources = stronger.
        agreement_score = min(
            agreement_count / 3.0,
            1.0
        )

        agreement_values.append(
            agreement_score
        )

    agreement_quality = (
        sum(agreement_values) /
        len(agreement_values)
        if agreement_values
        else 0.0
    )

    # ======================================
    # FINAL MODEL
    # ======================================

    base_confidence = (
        coverage * 0.25
        + evidence_quality * 0.25
        + corroboration_ratio * 0.20
        + source_diversity * 0.10
        + field_diversity * 0.05
        + agreement_quality * 0.15
    )

    # ======================================
    # CONFLICT PENALTY
    # ======================================

    # Conflicting intelligence should reduce
    # certainty, not automatically increase risk.

    conflict_penalty = (
        conflict_ratio * 0.20
    )

    final_confidence = (
        base_confidence -
        conflict_penalty
    )

    # ======================================
    # DATA COMPLETENESS SAFETY
    # ======================================

    # Avoid high confidence when only one tiny
    # signal is available.

    if len(evidence) <= 1:

        final_confidence *= 0.70

    elif len(evidence) <= 3:

        final_confidence *= 0.85

    # ======================================
    # FINAL CLAMP
    # ======================================

    final_confidence = _clamp(
        final_confidence
    )

    return round(
        final_confidence,
        3
    )
