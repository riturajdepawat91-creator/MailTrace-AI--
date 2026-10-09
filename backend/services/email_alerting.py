"""Policy decisions and alert classification for the mail gateway workflow.

MailTrace returns a decision to a trusted gateway adapter. It does not move or
quarantine mail by itself; the adapter must apply the returned delivery action.
"""

from __future__ import annotations

import os
from typing import Any


def build_mail_flow_decision(analysis: dict[str, Any]) -> dict[str, Any]:
    threat = analysis.get("threat_analysis", {})
    if not isinstance(threat, dict):
        threat = {}

    try:
        score = max(0, min(100, int(threat.get("score", 0) or 0)))
    except (TypeError, ValueError):
        score = 0
    verdict = str(threat.get("verdict", "UNKNOWN") or "UNKNOWN").strip().upper()
    confidence = str(threat.get("confidence", "UNKNOWN") or "UNKNOWN").strip().upper()

    mode = os.getenv("MAILTRACE_GATEWAY_ENFORCEMENT_MODE", "monitor_only").strip().lower()
    if mode not in {"monitor_only", "enforce"}:
        raise RuntimeError(
            "MAILTRACE_GATEWAY_ENFORCEMENT_MODE must be monitor_only or enforce."
        )
    try:
        quarantine_threshold = int(
            os.getenv("MAILTRACE_QUARANTINE_THRESHOLD", "85")
        )
    except ValueError as error:
        raise RuntimeError("MAILTRACE_QUARANTINE_THRESHOLD must be an integer from 50 to 100.") from error
    if not 50 <= quarantine_threshold <= 100:
        raise RuntimeError("MAILTRACE_QUARANTINE_THRESHOLD must be an integer from 50 to 100.")

    if score >= 90 or verdict == "CRITICAL":
        severity = "CRITICAL"
    elif score >= 70 or verdict in {"HIGH", "HIGH RISK"}:
        severity = "HIGH"
    elif score >= 40 or verdict == "SUSPICIOUS":
        severity = "MEDIUM"
    else:
        severity = "LOW"

    quarantine_recommended = confidence == "HIGH" and (
        verdict == "CRITICAL" or score >= quarantine_threshold
    )
    if quarantine_recommended:
        recommended_action = "QUARANTINE"
        rationale = "High-risk threshold or critical verdict met with high confidence."
    else:
        recommended_action = "ALLOW"
        rationale = "Automatic quarantine threshold was not met; SOC review starts if the recipient reports the message."

    fusion = analysis.get("intelligence_fusion", {})
    evidence = fusion.get("evidence", []) if isinstance(fusion, dict) else []
    category_labels = {
        "url": "A link is present; check its destination carefully before opening it.",
        "attachment": "An attachment is present; do not open it if you were not expecting it.",
        "malware_delivery": "The attachment has a potentially dangerous file type; do not open it.",
        "credential_theft": "The message may be trying to collect passwords or sign-in details.",
        "impersonation": "The sender or identity may be impersonating a person or organization.",
        "identity": "Sender identity indicators do not fully line up.",
        "fraud": "The message contains possible payment or invoice fraud indicators.",
        "social_engineering": "The message uses pressure or persuasion patterns commonly seen in scams.",
        "header_forensics": "Email routing or authentication headers contain anomalies.",
        "threat_intelligence": "An indicator matched available threat-intelligence data.",
        "infrastructure": "The sending infrastructure has elevated reputation risk.",
        "forensics": "Forensic checks raised a message-structure risk signal.",
        "ml": "Automated message classification raised a risk signal; review the supporting evidence.",
    }
    risk_indicators: list[str] = []
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            label = category_labels.get(str(item.get("category", "")).lower())
            if label and label not in risk_indicators:
                risk_indicators.append(label)
            if len(risk_indicators) >= 5:
                break
    if severity in {"HIGH", "CRITICAL"} and not risk_indicators:
        risk_indicators.append("The combined email risk assessment is high; analyst review is recommended.")

    is_risky = quarantine_recommended
    user_notification = None
    if is_risky:
        user_notification = {
            "title": "Suspicious email â€” do not interact",
            "summary": "MailTrace found indicators that may be associated with phishing, impersonation, or fraud. This automated assessment is a warning, not proof of malicious intent.",
            "why_risky": risk_indicators or ["The message needs security review before you act on it."],
            "next_steps": [
                "Do not click links, open attachments, reply, or send money or credentials.",
                "Verify the request with the sender using a separate, trusted contact method.",
                "Contact your security team if you already interacted with the message.",
            ],
        }

    return {
        "policy_version": "mailtrace-gateway-policy-v2",
        "severity": severity,
        "threat_score": score,
        "confidence": confidence,
        "recommended_action": recommended_action,
        "delivery_action": (
            recommended_action if mode == "enforce" else "MONITOR_ONLY"
        ),
        "enforcement_mode": mode.upper(),
        "gateway_must_apply_action": mode == "enforce",
        "quarantine_threshold": quarantine_threshold,
        "rationale": rationale,
        "user_notification": user_notification,
    }


def should_create_alert(decision: dict[str, Any]) -> bool:
    """Only automatic high-risk quarantine decisions page the SOC."""
    return decision.get("recommended_action") == "QUARANTINE"
