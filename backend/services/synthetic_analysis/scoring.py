"""Versioned prototype-only scoring policy; scores are not probabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


DEFAULT_FINDING_WEIGHTS = {
    "SENDER_DISPLAY_DOMAIN_MISMATCH": 25,
    "CREDENTIAL_REQUEST_LANGUAGE": 25,
    "PAYMENT_MANIPULATION_LANGUAGE": 20,
    "URGENCY_LANGUAGE": 10,
    "DECEPTIVE_LINK": 35,
    "IP-LITERAL-URL": 20,
    "URL-USERINFO": 20,
    "URL-SUSPICIOUS-ENCODING": 10,
    "AUTH-SPF-FAIL": 20,
    "AUTH-DKIM-FAIL": 20,
    "AUTH-DMARC-FAIL": 30,
}
DEFAULT_SCORE_THRESHOLDS = {"SUSPICIOUS": 25, "HIGH": 60, "CRITICAL": 85}
MANDATORY_CHECKS = (
    "parser", "sender_analysis", "sender_alignment", "phishing_rules", "url_extraction", "ioc_extraction",
    "spf", "dkim", "dmarc",
)


@dataclass(frozen=True)
class PrototypeScoringPolicy:
    version: str = "synthetic-demo-policy-1"
    finding_weights: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_FINDING_WEIGHTS))
    thresholds: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_SCORE_THRESHOLDS))

    def __post_init__(self) -> None:
        ordered = (self.thresholds.get("SUSPICIOUS"), self.thresholds.get("HIGH"), self.thresholds.get("CRITICAL"))
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100 for value in ordered):
            raise ValueError("Scoring thresholds must be integer values from 0 to 100.")
        if not ordered[0] <= ordered[1] <= ordered[2]:
            raise ValueError("Scoring thresholds must be ordered SUSPICIOUS <= HIGH <= CRITICAL.")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in self.finding_weights.values()):
            raise ValueError("Finding weights must be non-negative integers.")


DEFAULT_POLICY = PrototypeScoringPolicy()


def score_findings(
    findings: list[dict],
    check_states: dict[str, str],
    *,
    policy: PrototypeScoringPolicy = DEFAULT_POLICY,
) -> dict:
    """Deduplicate evidence, apply explicit demo weights, and fail incomplete checks closed."""
    unique = {}
    for finding in findings:
        unique.setdefault((finding["id"], finding["evidence_ref"]), finding)
    deduplicated = list(unique.values())
    score_breakdown = []
    score = 0
    for finding in deduplicated:
        code = finding["id"].removeprefix("MT-SYN-")
        weight = policy.finding_weights.get(code, 0)
        score += weight
        if weight:
            score_breakdown.append({
                "finding_id": finding["id"],
                "points": weight,
                "evidence_ref": finding["evidence_ref"],
            })
    score = min(100, score)
    if score >= policy.thresholds["CRITICAL"]:
        verdict = "CRITICAL"
        explanation = "Prototype heuristics accumulated a critical demo score; this is not a calibrated probability."
    elif score >= policy.thresholds["HIGH"]:
        verdict = "HIGH"
        explanation = "Prototype heuristic score reached the configured high tier; analyst review is required."
    elif score >= policy.thresholds["SUSPICIOUS"]:
        verdict = "SUSPICIOUS"
        explanation = "Prototype heuristic score reached the configured review tier."
    elif any(check_states.get(name) != "PASS" for name in MANDATORY_CHECKS):
        verdict = "INDETERMINATE / ANALYSIS_INCOMPLETE"
        explanation = "At least one mandatory check is unavailable or incomplete; a SAFE outcome is not supported."
    else:
        verdict = "SAFE"
        explanation = "All mandatory prototype checks completed and no configured finding was produced."
    return {
        "score": score,
        "verdict": verdict,
        "policy_version": policy.version,
        "thresholds": dict(policy.thresholds),
        "explanation": explanation,
        "score_breakdown": score_breakdown,
        "findings": deduplicated,
        "analysis_complete": all(check_states.get(name) == "PASS" for name in MANDATORY_CHECKS),
    }
