from collections import defaultdict


# ==========================================
# IP RISK ENGINE V5
# Context-Aware Correlation Scoring
# ==========================================


def _clamp(value, minimum=0.0, maximum=100.0):
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = minimum

    return min(max(value, minimum), maximum)


def _number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _sources(item):
    provenance = item.get("provenance")

    if isinstance(provenance, dict):
        sources = provenance.get("sources", [])

        if sources:
            return {
                str(source)
                for source in sources
                if source
            }

    source = item.get("source")

    return {str(source)} if source else set()


def _field_items(evidence, field):
    return [
        item
        for item in evidence
        if item.get("field") == field
    ]


def _has_conflict(items):
    return any(
        item.get("conflict") is True
        for item in items
    )


def _independent_source_count(items):
    sources = set()

    for item in items:
        sources.update(_sources(item))

    return len(sources)


def _unique_numeric_values(items):
    values = set()

    for item in items:
        value = item.get("value")

        if value is None:
            continue

        try:
            values.add(round(float(value), 4))
        except (TypeError, ValueError):
            values.add(str(value).strip().lower())

    return values


def _unique_text_values(items):
    values = set()

    for item in items:
        value = item.get("value")

        if value is not None:
            values.add(
                str(value).strip().lower()
            )

    return values


def calculate_risk(
    profile: dict,
    provider_results: list,
    evidence: list[dict]
) -> dict:
    """
    IP Risk Engine V5.

    Design goals:

    - evidence-based scoring
    - duplicate signal protection
    - context-aware infrastructure scoring
    - independent-source corroboration
    - conflict penalties
    - signal saturation
    - explainable output
    - conservative treatment of hosting/cloud
    """

    reasons = []

    breakdown = {
        "reputation": 0.0,
        "anonymity": 0.0,
        "infrastructure": 0.0,
        "correlation_bonus": 0.0,
        "evidence_quality_bonus": 0.0
    }

    # ======================================
    # SPECIAL ADDRESS HANDLING
    # ======================================

    if profile.get("is_private"):
        return {
            "risk": "PRIVATE",
            "risk_score": 0.0,
            "reasons": [
                "Private/non-routable IP address."
            ],
            "signal_breakdown": breakdown,
            "risk_engine": "v5"
        }

    if profile.get("is_loopback"):
        return {
            "risk": "LOCAL",
            "risk_score": 0.0,
            "reasons": [
                "Loopback address."
            ],
            "signal_breakdown": breakdown,
            "risk_engine": "v5"
        }

    if profile.get("is_documentation"):
        return {
            "risk": "TEST",
            "risk_score": 0.0,
            "reasons": [
                "Documentation/test IP address; not evidence of a real sender."
            ],
            "signal_breakdown": breakdown,
            "risk_engine": "v5"
        }

    score = 0.0

    # ======================================
    # REPUTATION INTELLIGENCE
    # ======================================

    reputation_score = 0.0

    abuse_items = _field_items(
        evidence,
        "abuse_confidence_score"
    )

    report_items = _field_items(
        evidence,
        "total_reports"
    )

    # --------------------------------------
    # Abuse confidence
    # --------------------------------------

    abuse_values = _unique_numeric_values(
        abuse_items
    )

    if abuse_values:

        # Use the strongest observation,
        # but do not stack duplicate providers.
        strongest_abuse = max(
            float(value)
            for value in abuse_values
            if isinstance(value, (int, float))
        )

        if strongest_abuse >= 90:
            reputation_score += 70
            reasons.append(
                f"Very high external abuse confidence ({strongest_abuse:.0f}/100)."
            )

        elif strongest_abuse >= 60:
            reputation_score += 50
            reasons.append(
                f"High external abuse confidence ({strongest_abuse:.0f}/100)."
            )

        elif strongest_abuse >= 30:
            reputation_score += 25
            reasons.append(
                f"Moderate external abuse confidence ({strongest_abuse:.0f}/100)."
            )

    # --------------------------------------
    # Abuse reports
    # --------------------------------------

    report_values = []

    for item in report_items:
        try:
            report_values.append(
                int(_number(item.get("value")))
            )
        except (TypeError, ValueError):
            pass

    if report_values:

        strongest_reports = max(
            report_values
        )

        if strongest_reports >= 100:
            reputation_score += 20
            reasons.append(
                f"High historical abuse-report volume ({strongest_reports})."
            )

        elif strongest_reports >= 20:
            reputation_score += 10
            reasons.append(
                f"Multiple historical abuse reports ({strongest_reports})."
            )

        elif strongest_reports >= 5:
            reputation_score += 5
            reasons.append(
                f"Historical abuse reports observed ({strongest_reports})."
            )

    # --------------------------------------
    # Reputation corroboration
    # --------------------------------------

    reputation_sources = (
        _independent_source_count(abuse_items)
        +
        _independent_source_count(report_items)
    )

    if reputation_sources >= 2 and reputation_score > 0:

        reputation_score += 3

        reasons.append(
            "Reputation intelligence is corroborated across independent sources."
        )

    # --------------------------------------
    # Reputation conflict
    # --------------------------------------

    if (
        _has_conflict(abuse_items)
        or
        _has_conflict(report_items)
    ):

        reputation_score *= 0.75

        reasons.append(
            "Conflicting reputation observations reduced the reputation signal."
        )

    reputation_score = _clamp(
        reputation_score,
        0,
        78
    )

    breakdown["reputation"] = round(
        reputation_score,
        2
    )

    score += reputation_score

    # ======================================
    # ANONYMITY INFRASTRUCTURE
    # ======================================

    anonymity_score = 0.0

    if profile.get("is_tor") is True:

        anonymity_score += 25

        reasons.append(
            "IP is associated with Tor infrastructure."
        )

    if profile.get("is_vpn") is True:

        anonymity_score += 15

        reasons.append(
            "IP is associated with VPN infrastructure."
        )

    if profile.get("is_proxy") is True:

        anonymity_score += 15

        reasons.append(
            "IP is associated with proxy infrastructure."
        )

    anonymity_score = _clamp(
        anonymity_score,
        0,
        40
    )

    breakdown["anonymity"] = round(
        anonymity_score,
        2
    )

    score += anonymity_score

    # ======================================
    # NETWORK / INFRASTRUCTURE
    # ======================================

    infrastructure_score = 0.0

    hosting = profile.get(
        "is_hosting"
    )

    network_items = (
        _field_items(evidence, "asn")
        +
        _field_items(evidence, "organization")
        +
        _field_items(evidence, "hosting_signal")
    )

    network_sources = set()

    for item in network_items:
        network_sources.update(
            _sources(item)
        )

    # Hosting is intentionally weak.
    # Cloud infrastructure alone is NOT
    # treated as strong malicious evidence.

    if hosting is True:

        infrastructure_score += 5

        reasons.append(
            "IP is associated with hosting/cloud infrastructure."
        )

    # Multiple independent sources increase
    # contextual confidence slightly.

    if len(network_sources) >= 2:

        infrastructure_score += 2

        reasons.append(
            "Network intelligence is corroborated by multiple independent sources."
        )

    # Conflicting network data reduces
    # certainty instead of increasing risk.

    if _has_conflict(network_items):

        infrastructure_score *= 0.75

        reasons.append(
            "Network intelligence contains conflicting observations."
        )

    infrastructure_score = _clamp(
        infrastructure_score,
        0,
        10
    )

    breakdown["infrastructure"] = round(
        infrastructure_score,
        2
    )

    score += infrastructure_score

    # ======================================
    # CROSS-SIGNAL CORRELATION
    # ======================================

    correlation_bonus = 0.0

    strong_reputation = (
        reputation_score >= 30
    )

    strong_anonymity = (
        anonymity_score >= 20
    )

    meaningful_infrastructure = (
        infrastructure_score >= 6
    )

    active_signals = sum(
        [
            strong_reputation,
            strong_anonymity,
            meaningful_infrastructure
        ]
    )

    if active_signals >= 2:

        correlation_bonus += 8

        reasons.append(
            "Multiple independent threat-context signals reinforce each other."
        )

    # Strong reputation + anonymity is
    # particularly meaningful.

    if (
        strong_reputation
        and
        strong_anonymity
    ):

        correlation_bonus += 5

        reasons.append(
            "Abuse reputation and anonymity infrastructure are jointly observed."
        )

    correlation_bonus = _clamp(
        correlation_bonus,
        0,
        13
    )

    breakdown["correlation_bonus"] = round(
        correlation_bonus,
        2
    )

    score += correlation_bonus

    # ======================================
    # EVIDENCE QUALITY
    # ======================================

    evidence_confidences = []

    for item in evidence:

        confidence = _number(
            item.get("confidence"),
            0.0
        )

        evidence_confidences.append(
            _clamp(
                confidence,
                0,
                1
            )
        )

    if evidence_confidences:

        average_quality = (
            sum(evidence_confidences)
            /
            len(evidence_confidences)
        )

        # Quality bonus is deliberately small.
        quality_bonus = (
            max(
                average_quality - 0.75,
                0
            )
            * 4
        )

        breakdown["evidence_quality_bonus"] = round(
            quality_bonus,
            2
        )

        score += quality_bonus

    # ======================================
    # SIGNAL SATURATION
    # ======================================
    #
    # Prevent excessive duplicate evidence
    # from pushing the score unrealistically.
    #

    if len(evidence) > 12:

        excess = len(evidence) - 12

        score -= min(
            excess * 0.25,
            3
        )

    # ======================================
    # RESERVED ADDRESS
    # ======================================

    if profile.get("is_reserved"):

        reasons.append(
            "Reserved address space detected."
        )

    # ======================================
    # FINAL SCORE
    # ======================================

    score = round(
        _clamp(
            score,
            0,
            100
        ),
        2
    )

    # ======================================
    # CLASSIFICATION
    # ======================================

    if score >= 80:
        risk = "CRITICAL"

    elif score >= 60:
        risk = "HIGH"

    elif score >= 30:
        risk = "MEDIUM"

    elif score > 0:
        risk = "LOW"

    else:
        risk = "PUBLIC"

    # ======================================
    # FALLBACK
    # ======================================

    if not reasons:

        reasons.append(
            "No significant threat indicators were observed."
        )

    return {
        "risk": risk,
        "risk_score": score,
        "reasons": reasons,
        "signal_breakdown": breakdown,
        "risk_engine": "v5"
    }
