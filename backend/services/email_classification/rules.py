"""
MailTrace-AI
Email Classification Rules

Deterministic, explainable and bounded classification signals.
No network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


MAX_TEXT_CHARS = 2 * 1024 * 1024
MAX_FINDINGS = 100


@dataclass(frozen=True)
class RuleSignal:
    signal_id: str
    category: str
    weight: float
    source: str
    description: str
    pattern: str


RULES = (
    # ------------------------------------------------------------
    # PHISHING
    # ------------------------------------------------------------
    RuleSignal(
        "PHISH_001",
        "PHISHING",
        18,
        "subject/body",
        "Urgent account verification language.",
        r"\b(verify|verification|confirm|validate)\b.*\b(account|identity|security)\b",
    ),
    RuleSignal(
        "PHISH_002",
        "PHISHING",
        16,
        "subject/body",
        "Threat of account suspension or closure.",
        r"\b(account|access|service)\b.*\b(suspend|suspension|close|closed|disabled)\b",
    ),
    RuleSignal(
        "PHISH_003",
        "PHISHING",
        14,
        "subject/body",
        "Immediate-action pressure.",
        r"\b(urgent|immediately|right away|act now|action required|within \d+\s*(hour|hours|day|days))\b",
    ),
    RuleSignal(
        "PHISH_004",
        "PHISHING",
        20,
        "subject/body",
        "Credential/login lure language.",
        r"\b(login|log in|sign in|password|credential|credentials)\b.*\b(verify|confirm|update|unlock|secure)\b",
    ),

    # ------------------------------------------------------------
    # CREDENTIAL THEFT
    # ------------------------------------------------------------
    RuleSignal(
        "CRED_001",
        "CREDENTIAL_THEFT",
        22,
        "subject/body",
        "Password harvesting language.",
        r"\b(password|passcode|credential|credentials|one[- ]time password|otp)\b",
    ),
    RuleSignal(
        "CRED_002",
        "CREDENTIAL_THEFT",
        20,
        "subject/body",
        "Fake sign-in or account recovery request.",
        r"\b(sign in|login|log in|account recovery|recover your account|unlock your account)\b",
    ),
    RuleSignal(
        "CRED_003",
        "CREDENTIAL_THEFT",
        24,
        "subject/body",
        "Request to submit authentication secrets.",
        r"\b(enter|submit|provide)\b.*\b(password|otp|passcode|security code|credentials)\b",
    ),

    # ------------------------------------------------------------
    # BEC
    # ------------------------------------------------------------
    RuleSignal(
        "BEC_001",
        "BEC",
        18,
        "subject/body",
        "Executive/authority impersonation language.",
        r"\b(ceo|cfo|director|executive|president|manager|boss)\b.*\b(urgent|confidential|immediately|discreet)\b",
    ),
    RuleSignal(
        "BEC_002",
        "BEC",
        22,
        "subject/body",
        "Payment or transfer request.",
        r"\b(wire transfer|bank transfer|transfer funds|send payment|make payment|remit payment)\b",
    ),
    RuleSignal(
        "BEC_003",
        "BEC",
        18,
        "subject/body",
        "Business impersonation/payment secrecy language.",
        r"\b(confidential|keep this private|do not share|discreet)\b.*\b(payment|transfer|invoice|bank)\b",
    ),

    # ------------------------------------------------------------
    # INVOICE FRAUD
    # ------------------------------------------------------------
    RuleSignal(
        "INV_001",
        "INVOICE_FRAUD",
        22,
        "subject/body",
        "Invoice/payment terminology.",
        r"\b(invoice|invoice number|billing|payment due|amount due|remittance)\b",
    ),
    RuleSignal(
        "INV_002",
        "INVOICE_FRAUD",
        22,
        "subject/body",
        "Bank-account/payment detail change request.",
        r"\b(change|update|new)\b.*\b(bank account|account number|beneficiary|payment details)\b",
    ),
    RuleSignal(
        "INV_003",
        "INVOICE_FRAUD",
        16,
        "subject/body",
        "Payment deadline pressure.",
        r"\b(invoice|payment)\b.*\b(overdue|past due|due today|due immediately|deadline)\b",
    ),

    # ------------------------------------------------------------
    # MALWARE
    # ------------------------------------------------------------
    RuleSignal(
        "MAL_001",
        "MALWARE",
        22,
        "attachment",
        "Potentially executable attachment metadata.",
        r"\.(exe|scr|com|bat|cmd|ps1|vbs|js|jse|msi|dll|hta|jar|lnk)\b",
    ),
    RuleSignal(
        "MAL_002",
        "MALWARE",
        24,
        "attachment",
        "Suspicious script or executable delivery language.",
        r"\b(run|execute|open|launch|install)\b.*\b(script|program|application|installer|executable)\b",
    ),
    RuleSignal(
        "MAL_003",
        "MALWARE",
        20,
        "subject/body",
        "Document macro enablement lure.",
        r"\b(enable|allow|activate)\b.*\b(macros?|content)\b",
    ),

    # ------------------------------------------------------------
    # SPAM
    # ------------------------------------------------------------
    RuleSignal(
        "SPAM_001",
        "SPAM",
        12,
        "subject/body",
        "Promotional or bulk-message language.",
        r"\b(unsubscribe|special offer|limited time|promotion|discount|sale|newsletter)\b",
    ),
    RuleSignal(
        "SPAM_002",
        "SPAM",
        10,
        "subject/body",
        "Marketing-oriented message language.",
        r"\b(buy now|free trial|exclusive offer|save \d+%|deal of the day)\b",
    ),
)


def _bounded_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)[:MAX_TEXT_CHARS]
    except Exception:
        return ""


def _search(rule: RuleSignal, text: str) -> bool:
    if not text:
        return False

    try:
        return re.search(
            rule.pattern,
            text,
            flags=re.IGNORECASE | re.DOTALL,
        ) is not None
    except re.error:
        return False


def collect_rule_signals(
    *,
    subject: Any = "",
    body: Any = "",
    sender: Any = "",
    reply_to: Any = "",
    urls: list[Any] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    authentication: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Collect bounded deterministic classification evidence.

    This function only creates evidence.
    It does not calculate the final classification.
    """

    subject_text = _bounded_text(subject)
    body_text = _bounded_text(body)
    sender_text = _bounded_text(sender)
    reply_text = _bounded_text(reply_to)

    urls = urls if isinstance(urls, list) else []
    attachments = attachments if isinstance(attachments, list) else []
    authentication = authentication if isinstance(authentication, dict) else {}
    threat_analysis = threat_analysis if isinstance(threat_analysis, dict) else {}

    combined_text = "\n".join(
        [
            subject_text,
            body_text,
            sender_text,
            reply_text,
        ]
    )

    attachment_text_parts: list[str] = []

    for attachment in attachments[:100]:
        if not isinstance(attachment, dict):
            continue

        for key in (
            "filename",
            "name",
            "content_type",
            "mime_type",
            "extension",
            "type",
        ):
            value = attachment.get(key)
            if value is not None:
                attachment_text_parts.append(_bounded_text(value))

    attachment_text = "\n".join(attachment_text_parts)[:MAX_TEXT_CHARS]

    url_text = "\n".join(
        _bounded_text(url)
        for url in urls[:500]
    )

    searchable_by_source = {
        "subject/body": combined_text,
        "attachment": attachment_text,
    }

    signals: list[dict[str, Any]] = []

    for rule in RULES:
        source_text = searchable_by_source.get(
            rule.source,
            combined_text,
        )

        if not _search(rule, source_text):
            continue

        signals.append(
            {
                "signal_id": rule.signal_id,
                "category": rule.category,
                "weight": float(rule.weight),
                "source": rule.source,
                "description": rule.description,
            }
        )

        if len(signals) >= MAX_FINDINGS:
            break

    # ------------------------------------------------------------
    # Structured intelligence signals
    # ------------------------------------------------------------

    auth_failure = False

    for key, value in authentication.items():
        key_text = str(key).lower()
        value_text = str(value).lower()

        if any(
            token in key_text
            for token in (
                "spf",
                "dkim",
                "dmarc",
            )
        ) and any(
            token in value_text
            for token in (
                "fail",
                "failed",
                "softfail",
                "none",
            )
        ):
            auth_failure = True
            break

    if auth_failure:
        signals.append(
            {
                "signal_id": "AUTH_001",
                "category": "PHISHING",
                "weight": 14.0,
                "source": "authentication",
                "description": (
                    "Authentication evidence contains a "
                    "negative SPF/DKIM/DMARC result."
                ),
            }
        )

    if reply_text and sender_text:
        sender_domain = sender_text.split("@")[-1].lower()
        reply_domain = reply_text.split("@")[-1].lower()

        if (
            "@" in sender_text
            and "@" in reply_text
            and sender_domain
            and reply_domain
            and sender_domain != reply_domain
        ):
            signals.append(
                {
                    "signal_id": "ID_001",
                    "category": "PHISHING",
                    "weight": 12.0,
                    "source": "identity",
                    "description": (
                        "Sender and Reply-To domains differ."
                    ),
                }
            )

    # Preserve context for future classification layers.
    _ = url_text
    _ = threat_analysis

    return signals
