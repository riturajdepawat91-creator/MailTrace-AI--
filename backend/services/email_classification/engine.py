"""
MailTrace-AI
Email Classification Engine

SOC-grade deterministic multi-class classifier.

V1.3 introduces:
- category conflict resolution
- specificity weighting
- benign safeguards
- uncertainty-aware decisions
- calibrated confidence
- explicit insufficient-evidence handling

This module does NOT replace the existing threat scoring engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rules import collect_rule_signals


ANALYSIS_VERSION = "1.3.0"
MODEL_TYPE = "deterministic_rule_engine"

CATEGORIES = (
    "PHISHING",
    "MALWARE",
    "BEC",
    "CREDENTIAL_THEFT",
    "INVOICE_FRAUD",
    "SPAM",
    "SUSPICIOUS",
    "BENIGN",
)

MAX_ALTERNATIVES = 3
MAX_REASONING = 20
MAX_EVIDENCE = 100

HIGH_CONFIDENCE_THRESHOLD = 0.80
MODERATE_CONFIDENCE_THRESHOLD = 0.60
MIN_PRIMARY_SCORE = 20.0
AMBIGUITY_MARGIN = 10.0
SEVERE_AMBIGUITY_MARGIN = 5.0


@dataclass(frozen=True)
class ClassificationEvidence:
    signal_id: str
    category: str
    weight: float
    source: str
    description: str


@dataclass
class ClassificationResult:
    category: str = "BENIGN"
    confidence: float = 0.0
    alternative_categories: list[dict[str, Any]] = field(default_factory=list)
    category_scores: dict[str, float] = field(default_factory=dict)
    reasoning: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    uncertainty: dict[str, Any] = field(default_factory=dict)
    model_type: str = MODEL_TYPE
    analysis_version: str = ANALYSIS_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "confidence": round(float(self.confidence), 4),
            "alternative_categories": self.alternative_categories,
            "category_scores": self.category_scores,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "uncertainty": self.uncertainty,
            "model_type": self.model_type,
            "analysis_version": self.analysis_version,
        }


def _empty_scores() -> dict[str, float]:
    return {
        category: 0.0
        for category in CATEGORIES
    }


def _clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(maximum, float(value)),
    )


def _score_specificity(
    category: str,
    signals: list[dict[str, Any]],
) -> float:
    """
    Reward multiple independent signals while preventing
    repeated generic wording from dominating classification.
    """

    category_signals = [
        signal
        for signal in signals
        if isinstance(signal, dict)
        and str(signal.get("category", "")).upper() == category
    ]

    if not category_signals:
        return 0.0

    unique_sources = {
        str(signal.get("source", "")).lower()
        for signal in category_signals
        if signal.get("source")
    }

    unique_signal_ids = {
        str(signal.get("signal_id", ""))
        for signal in category_signals
        if signal.get("signal_id")
    }

    source_bonus = min(
        10.0,
        max(0, len(unique_sources) - 1) * 5.0,
    )

    diversity_bonus = min(
        10.0,
        max(0, len(unique_signal_ids) - 2) * 3.0,
    )

    return source_bonus + diversity_bonus


def _category_adjustment(
    category: str,
    raw_score: float,
    signals: list[dict[str, Any]],
) -> float:
    """
    Apply category-specific calibration.

    More specific categories receive modest reinforcement only
    when they have supporting evidence. Generic categories do
    not automatically dominate.
    """

    bonus = _score_specificity(
        category,
        signals,
    )

    if category in {
        "CREDENTIAL_THEFT",
        "MALWARE",
        "INVOICE_FRAUD",
    }:
        bonus += min(
            8.0,
            raw_score * 0.08,
        )

    elif category == "BEC":
        bonus += min(
            6.0,
            raw_score * 0.06,
        )

    elif category == "SPAM":
        # Spam receives no specificity amplification.
        bonus = min(
            bonus,
            5.0,
        )

    elif category == "PHISHING":
        # Phishing remains broad and should not overwhelm
        # a more specific classification without evidence.
        bonus = min(
            bonus,
            7.0,
        )

    return _clamp(
        raw_score + bonus,
    )


def _aggregate_scores(
    signals: list[dict[str, Any]],
) -> dict[str, float]:
    raw_scores = _empty_scores()

    for signal in signals[:MAX_EVIDENCE]:
        if not isinstance(signal, dict):
            continue

        category = str(
            signal.get("category", "")
        ).upper()

        if category not in CATEGORIES:
            continue

        try:
            weight = float(
                signal.get("weight", 0.0)
            )
        except (TypeError, ValueError):
            continue

        if weight < 0:
            continue

        raw_scores[category] += weight

    caps = {
        "PHISHING": 68.0,
        "MALWARE": 70.0,
        "BEC": 58.0,
        "CREDENTIAL_THEFT": 66.0,
        "INVOICE_FRAUD": 60.0,
        "SPAM": 22.0,
        "SUSPICIOUS": 40.0,
        "BENIGN": 100.0,
    }

    normalized: dict[str, float] = {}

    for category in CATEGORIES:
        raw_score = raw_scores[category]

        if category == "BENIGN":
            normalized[category] = 0.0
            continue

        divisor = caps.get(
            category,
            50.0,
        )

        base_score = (
            raw_score / divisor
        ) * 100.0

        adjusted = _category_adjustment(
            category,
            base_score,
            signals,
        )

        normalized[category] = round(
            _clamp(adjusted),
            2,
        )

    return normalized


def _apply_specific_conflict_resolution(
    scores: dict[str, float],
    signals: list[dict[str, Any]],
) -> dict[str, float]:
    """
    Resolve common semantic overlaps.

    A specific category can outrank a broad category only when
    its evidence actually supports that distinction.
    """

    adjusted = dict(scores)

    phishing = adjusted.get(
        "PHISHING",
        0.0,
    )

    credential = adjusted.get(
        "CREDENTIAL_THEFT",
        0.0,
    )

    if credential > 0:
        credential_signals = [
            signal
            for signal in signals
            if str(
                signal.get("category", "")
            ).upper() == "CREDENTIAL_THEFT"
        ]

        if len(credential_signals) >= 2:
            adjusted["CREDENTIAL_THEFT"] = _clamp(
                credential + min(
                    8.0,
                    len(credential_signals) * 1.5,
                )
            )

    # A broad phishing score should not receive a free win
    # when a strong credential-theft pattern exists.
    if (
        adjusted.get("CREDENTIAL_THEFT", 0.0) >= 70.0
        and phishing > 0
    ):
        adjusted["PHISHING"] = round(
            _clamp(
                phishing * 0.92
            ),
            2,
        )

    # Invoice fraud is more specific than generic BEC language
    # when invoice/payment-detail evidence is present.
    invoice = adjusted.get(
        "INVOICE_FRAUD",
        0.0,
    )

    bec = adjusted.get(
        "BEC",
        0.0,
    )

    if (
        invoice >= 60.0
        and bec > 0
    ):
        adjusted["BEC"] = round(
            _clamp(
                bec * 0.88
            ),
            2,
        )

    return adjusted


def _build_reasoning(
    signals: list[dict[str, Any]],
    category: str,
    score: float,
) -> list[str]:
    reasoning: list[str] = []

    category_signals = [
        signal
        for signal in signals
        if isinstance(signal, dict)
        and str(
            signal.get("category", "")
        ).upper() == category
    ]

    category_signals.sort(
        key=lambda item: (
            float(item.get("weight", 0.0)),
            str(item.get("signal_id", "")),
        ),
        reverse=True,
    )

    seen_descriptions: set[str] = set()

    for signal in category_signals[:MAX_REASONING]:
        description = str(
            signal.get("description", "")
        ).strip()

        source = str(
            signal.get("source", "")
        ).strip()

        if not description:
            continue

        normalized_description = description.casefold()

        if normalized_description in seen_descriptions:
            continue

        seen_descriptions.add(
            normalized_description
        )

        if source:
            reasoning.append(
                f"{description} Source: {source}."
            )
        else:
            reasoning.append(
                f"{description}."
            )

    if score >= 80:
        reasoning.append(
            f"Strong evidence supports {category} classification."
        )
    elif score >= 50:
        reasoning.append(
            f"Moderate evidence supports {category} classification."
        )
    elif score >= MIN_PRIMARY_SCORE:
        reasoning.append(
            f"Limited evidence supports {category} classification."
        )

    if not reasoning:
        reasoning.append(
            "No sufficiently specific classification evidence was observed."
        )

    return reasoning[:MAX_REASONING]


def _benign_safeguard(
    scores: dict[str, float],
    *,
    evidence_count: int,
    subject: str,
    body: str,
    signals: list[dict],
) -> tuple[dict[str, float], bool]:
    """
    Prevent positive threat scores from being interpreted as
    definitive when the evidence is weak or absent.
    """

    adjusted = dict(scores)

    combined_length = len(
        f"{subject} {body}".strip()
    )

    positive = [
        score
        for category, score in adjusted.items()
        if category != "BENIGN" and score > 0
    ]

    if not positive:
        return adjusted, True

    strongest = max(positive)

    # High-specificity malware indicators are valid classification
    # evidence and must not be suppressed by the generic weak-
    # evidence safeguard. This supports classification only; it
    # does not claim execution, infection, or confirmed malware.
    malware_specific_signals = {
        "MAL_001",
        "MAL_002",
        "MAL_003",
    }

    has_specific_malware_evidence = any(
        isinstance(signal, dict)
        and str(signal.get("signal_id", "")) in malware_specific_signals
        for signal in signals
    )

    if (
        evidence_count <= 1
        and strongest < 35.0
        and not has_specific_malware_evidence
    ):
        for category in CATEGORIES:
            if category != "BENIGN":
                adjusted[category] = round(
                    adjusted.get(category, 0.0) * 0.65,
                    2,
                )

        return adjusted, True

    if (
        combined_length < 8
        and evidence_count <= 2
    ):
        return adjusted, True

    return adjusted, False


def _choose_category(
    scores: dict[str, float],
    *,
    evidence_count: int,
    safeguarded: bool,
) -> str:
    active = [
        (category, score)
        for category, score in scores.items()
        if category != "BENIGN"
        and score >= MIN_PRIMARY_SCORE
    ]

    if not active:
        return "BENIGN"

    active.sort(
        key=lambda item: (
            item[1],
            item[0],
        ),
        reverse=True,
    )

    winner = active[0]

    if safeguarded and winner[1] < 50.0:
        return "SUSPICIOUS" if evidence_count else "BENIGN"

    return winner[0]


def _calculate_confidence(
    scores: dict[str, float],
    primary: str,
    evidence_count: int,
    uncertainty_state: str,
) -> float:
    if primary == "BENIGN":
        if evidence_count == 0:
            return 0.60
        return 0.58

    winner = scores.get(
        primary,
        0.0,
    )

    runners = [
        score
        for category, score in scores.items()
        if category != primary
        and category != "BENIGN"
        and score > 0
    ]

    runner_up = max(
        runners,
        default=0.0,
    )

    margin = max(
        0.0,
        winner - runner_up,
    )

    evidence_factor = min(
        1.0,
        evidence_count / 6.0,
    )

    score_factor = min(
        1.0,
        winner / 100.0,
    )

    margin_factor = min(
        1.0,
        margin / 35.0,
    )

    confidence = (
        0.45 * score_factor
        + 0.30 * evidence_factor
        + 0.25 * margin_factor
    )

    if uncertainty_state == "AMBIGUOUS":
        confidence *= 0.75
    elif uncertainty_state == "LOW_CONFIDENCE":
        confidence *= 0.85

    return round(
        _clamp(
            confidence,
            0.0,
            0.99,
        ),
        4,
    )


def _build_uncertainty(
    scores: dict[str, float],
    primary: str,
    evidence_count: int,
    confidence: float,
) -> dict[str, Any]:
    ordered = sorted(
        (
            (category, score)
            for category, score in scores.items()
            if category != "BENIGN"
        ),
        key=lambda item: (
            item[1],
            item[0],
        ),
        reverse=True,
    )

    winner_score = (
        ordered[0][1]
        if ordered
        else 0.0
    )

    runner_score = (
        ordered[1][1]
        if len(ordered) > 1
        else 0.0
    )

    margin = max(
        0.0,
        winner_score - runner_score,
    )

    if evidence_count == 0:
        state = "INSUFFICIENT_EVIDENCE"
    elif winner_score < MIN_PRIMARY_SCORE:
        state = "INSUFFICIENT_EVIDENCE"
    elif margin <= SEVERE_AMBIGUITY_MARGIN:
        state = "HIGH_AMBIGUITY"
    elif margin < AMBIGUITY_MARGIN:
        state = "AMBIGUOUS"
    elif confidence < MODERATE_CONFIDENCE_THRESHOLD:
        state = "LOW_CONFIDENCE"
    elif confidence < HIGH_CONFIDENCE_THRESHOLD:
        state = "MODERATE_CONFIDENCE"
    else:
        state = "HIGH_CONFIDENCE"

    return {
        "state": state,
        "primary_category": primary,
        "evidence_count": evidence_count,
        "winner_score": round(
            winner_score,
            2,
        ),
        "runner_up_score": round(
            runner_score,
            2,
        ),
        "score_margin": round(
            margin,
            2,
        ),
        "insufficient_evidence": (
            evidence_count == 0
            or winner_score < MIN_PRIMARY_SCORE
        ),
    }


def classify_email(
    *,
    subject: str = "",
    body: str = "",
    sender: str = "",
    reply_to: str = "",
    urls: list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    authentication: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
) -> ClassificationResult:

    urls = urls if isinstance(urls, list) else []
    attachments = (
        attachments
        if isinstance(attachments, list)
        else []
    )

    authentication = (
        authentication
        if isinstance(authentication, dict)
        else {}
    )

    threat_analysis = (
        threat_analysis
        if isinstance(threat_analysis, dict)
        else {}
    )

    signals = collect_rule_signals(
        subject=subject,
        body=body,
        sender=sender,
        reply_to=reply_to,
        urls=urls,
        attachments=attachments,
        authentication=authentication,
        threat_analysis=threat_analysis,
    )[:MAX_EVIDENCE]

    scores = _aggregate_scores(
        signals
    )

    scores = _apply_specific_conflict_resolution(
        scores,
        signals,
    )

    scores, safeguarded = _benign_safeguard(
        scores,
        evidence_count=len(signals),
        subject=str(subject or ""),
        body=str(body or ""),
        signals=signals,
    )

    primary = _choose_category(
        scores,
        evidence_count=len(signals),
        safeguarded=safeguarded,
    )

    uncertainty = _build_uncertainty(
        scores,
        primary,
        len(signals),
        0.0,
    )

    confidence = _calculate_confidence(
        scores,
        primary,
        len(signals),
        uncertainty["state"],
    )

    uncertainty = _build_uncertainty(
        scores,
        primary,
        len(signals),
        confidence,
    )

    # No evidence must never masquerade as a confirmed threat.
    if uncertainty["state"] == "INSUFFICIENT_EVIDENCE":
        primary = (
            "SUSPICIOUS"
            if len(signals) > 0
            else "BENIGN"
        )

        confidence = _calculate_confidence(
            scores,
            primary,
            len(signals),
            uncertainty["state"],
        )

    active_scores = [
        (category, score)
        for category, score in scores.items()
        if category != "BENIGN"
        and score > 0
        and category != primary
    ]

    active_scores.sort(
        key=lambda item: (
            item[1],
            item[0],
        ),
        reverse=True,
    )

    alternatives = []

    for category, score in active_scores[:MAX_ALTERNATIVES]:
        alternatives.append(
            {
                "category": category,
                "confidence": round(
                    _clamp(
                        score / 100.0,
                        0.0,
                        0.99,
                    ),
                    4,
                ),
                "score": round(
                    score,
                    2,
                ),
            }
        )

    evidence = []

    for signal in signals:
        evidence.append(
            {
                "signal_id": str(
                    signal.get("signal_id", "")
                ),
                "category": str(
                    signal.get("category", "")
                ),
                "weight": float(
                    signal.get("weight", 0.0)
                ),
                "source": str(
                    signal.get("source", "")
                ),
                "description": str(
                    signal.get("description", "")
                ),
            }
        )

    reasoning = _build_reasoning(
        signals,
        primary,
        scores.get(
            primary,
            0.0,
        ),
    )

    if safeguarded:
        reasoning.append(
            "Benign safeguard applied because available classification evidence is limited."
        )

    if uncertainty["state"] in {
        "AMBIGUOUS",
        "HIGH_AMBIGUITY",
    }:
        reasoning.append(
            "Classification remains sensitive to competing category evidence."
        )

    result = ClassificationResult(
        category=primary,
        confidence=confidence,
        alternative_categories=alternatives,
        category_scores=scores,
        reasoning=reasoning[:MAX_REASONING],
        evidence=evidence,
        uncertainty=uncertainty,
    )

    return result


def classify_email_to_dict(
    *,
    subject: str = "",
    body: str = "",
    sender: str = "",
    reply_to: str = "",
    urls: list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    authentication: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return classify_email(
        subject=subject,
        body=body,
        sender=sender,
        reply_to=reply_to,
        urls=urls,
        attachments=attachments,
        authentication=authentication,
        threat_analysis=threat_analysis,
    ).to_dict()
