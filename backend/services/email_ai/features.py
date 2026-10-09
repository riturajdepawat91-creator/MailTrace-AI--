from __future__ import annotations

import math
import re
from collections import Counter
from html import unescape
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse


MAX_FIELD_CHARS = 30000


# =========================================================
# NORMALIZATION
# =========================================================

def _clean(value: Any) -> str:

    if value is None:
        return ""

    text = str(value)

    text = unescape(text)

    text = re.sub(
        r"<style[\s\S]*?</style>",
        " ",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<script[\s\S]*?</script>",
        " ",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()[:MAX_FIELD_CHARS]


def _join(values: Iterable[Any]) -> str:

    parts = []

    for value in values:

        cleaned = _clean(value)

        if cleaned:
            parts.append(cleaned)

    return " ".join(parts)


def _safe_list(value: Any) -> List[Any]:

    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return list(value)

    return [value]


def _domain_from_email(value: str) -> str:

    if not value:
        return ""

    value = str(value).strip()

    # Extract domain from a normal email address or
    # display-name format such as:
    # Microsoft Security <security@example.com>
    email_matches = re.findall(
        r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        value,
    )

    if email_matches:
        return email_matches[-1].lower()

    # Fallback extraction.
    match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        value,
    )

    if match:
        return match.group(1).lower()

    return ""
# =========================================================
# EMAIL TEXT FOR EXISTING ML MODEL
# =========================================================

def build_email_text(
    email: Dict[str, Any]
) -> str:

    sender = email.get(
        "sender",
        email.get(
            "from",
            email.get(
                "from_address",
                "",
            ),
        ),
    )

    reply_to = email.get(
        "reply_to",
        email.get(
            "reply-to",
            "",
        ),
    )

    subject = email.get(
        "subject",
        "",
    )

    body = email.get(
        "body",
        email.get(
            "text",
            email.get(
                "body_text",
                "",
            ),
        ),
    )

    headers = email.get(
        "headers",
        {},
    )

    if isinstance(headers, dict):

        header_text = _join(
            [
                headers.get("return_path"),
                headers.get("message_id"),
                headers.get("received"),
                headers.get("authentication_results"),
                headers.get("dkim"),
                headers.get("spf"),
                headers.get("dmarc"),
            ]
        )

    else:

        header_text = _clean(
            headers
        )

    urls = email.get(
        "urls",
        email.get(
            "links",
            [],
        ),
    )

    url_text = _join(
        _safe_list(urls)
    )

    attachments = email.get(
        "attachments",
        email.get(
            "attachment_names",
            [],
        ),
    )

    attachment_text = _join(
        _safe_list(attachments)
    )

    parts = [

        "SENDER " + _clean(sender),

        "REPLY_TO " + _clean(reply_to),

        "SUBJECT " + _clean(subject),

        "BODY " + _clean(body),

        "HEADERS " + header_text,

        "URLS " + url_text,

        "ATTACHMENTS " + attachment_text,

    ]

    return "\n".join(
        part
        for part in parts
        if part.strip()
    )


# =========================================================
# ADVANCED FEATURE EXTRACTION
# =========================================================

def extract_advanced_features(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    subject = _clean(
        email.get(
            "subject",
            "",
        )
    )

    body = _clean(
        email.get(
            "body",
            email.get(
                "text",
                email.get(
                    "body_text",
                    "",
                ),
            ),
        )
    )

    # IMPORTANT:
    # Do not use _clean() for email addresses because
    # display-name email formats such as:
    # Microsoft <security@example.com>
    # would lose the address when angle brackets are
    # interpreted as HTML tags.

    sender = str(
        email.get(
            "sender",
            email.get(
                "from",
                email.get(
                    "from_address",
                    "",
                ),
            ),
        )
        or ""
    ).strip()

    reply_to = str(
        email.get(
            "reply_to",
            email.get(
                "reply-to",
                "",
            ),
        )
        or ""
    ).strip()

    raw_body = str(
        email.get(
            "body",
            email.get(
                "text",
                "",
            ),
        )
    )

    urls = _safe_list(
        email.get(
            "urls",
            email.get(
                "links",
                [],
            ),
        )
    )

    attachments = _safe_list(
        email.get(
            "attachments",
            email.get(
                "attachment_names",
                [],
            ),
        )
    )

    combined_text = (
        f"{subject} {body}"
    ).lower()


    # -----------------------------------------------------
    # TEXT STRUCTURE
    # -----------------------------------------------------

    word_list = re.findall(
        r"\b[\w'-]+\b",
        combined_text,
    )

    uppercase_count = sum(
        1
        for char in f"{subject} {body}"
        if char.isupper()
    )

    alphabetic_count = sum(
        1
        for char in f"{subject} {body}"
        if char.isalpha()
    )

    uppercase_ratio = (
        uppercase_count / alphabetic_count
        if alphabetic_count
        else 0.0
    )

    exclamation_count = (
        subject.count("!")
        + body.count("!")
    )

    question_count = (
        subject.count("?")
        + body.count("?")
    )


    # -----------------------------------------------------
    # URL INTELLIGENCE
    # -----------------------------------------------------

    suspicious_tlds = {

        "zip",
        "mov",
        "country",
        "stream",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "top",
        "xyz",
        "click",
        "link",
        "work",

    }

    ip_url_count = 0
    punycode_count = 0
    suspicious_tld_count = 0
    encoded_url_count = 0
    long_url_count = 0

    url_domains = []

    for value in urls:

        url = str(value).strip()

        if not url:
            continue

        parsed = urlparse(url)

        hostname = (
            parsed.hostname
            or ""
        ).lower()

        if hostname:
            url_domains.append(
                hostname
            )

        if re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}",
            hostname,
        ):
            ip_url_count += 1

        if "xn--" in hostname:
            punycode_count += 1

        if hostname:

            parts = hostname.split(".")

            if parts:

                tld = parts[-1]

                if tld in suspicious_tlds:
                    suspicious_tld_count += 1

        if (
            "%" in url
            or re.search(
                r"%[0-9a-fA-F]{2}",
                url,
            )
        ):
            encoded_url_count += 1

        if len(url) > 150:
            long_url_count += 1


    # -----------------------------------------------------
    # ATTACHMENT INTELLIGENCE
    # -----------------------------------------------------

    dangerous_extensions = {

        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".msi",
        ".dll",
        ".jar",
        ".hta",

    }

    archive_extensions = {

        ".zip",
        ".rar",
        ".7z",
        ".gz",
        ".tar",

    }

    macro_extensions = {

        ".docm",
        ".xlsm",
        ".pptm",

    }

    dangerous_attachment_count = 0
    archive_attachment_count = 0
    macro_attachment_count = 0
    double_extension_count = 0

    for attachment in attachments:

        name = str(
            attachment
        ).lower().strip()

        if not name:
            continue

        if any(
            name.endswith(ext)
            for ext in dangerous_extensions
        ):
            dangerous_attachment_count += 1

        if any(
            name.endswith(ext)
            for ext in archive_extensions
        ):
            archive_attachment_count += 1

        if any(
            name.endswith(ext)
            for ext in macro_extensions
        ):
            macro_attachment_count += 1

        if re.search(
            r"\.[a-z0-9]{2,5}\.(exe|scr|js|vbs|bat|cmd)$",
            name,
            flags=re.I,
        ):
            double_extension_count += 1


    # -----------------------------------------------------
    # IDENTITY INTELLIGENCE
    # -----------------------------------------------------

    sender_domain = _domain_from_email(
        sender
    )

    reply_domain = _domain_from_email(
        reply_to
    )

    sender_reply_mismatch = bool(
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    )


    # -----------------------------------------------------
    # HTML / OBFUSCATION
    # -----------------------------------------------------

    script_tag_count = len(
        re.findall(
            r"<script\b",
            raw_body,
            flags=re.I,
        )
    )

    iframe_count = len(
        re.findall(
            r"<iframe\b",
            raw_body,
            flags=re.I,
        )
    )

    html_tag_count = len(
        re.findall(
            r"<[^>]+>",
            raw_body,
        )
    )

    encoded_entity_count = len(
        re.findall(
            r"&#(?:x[0-9a-fA-F]+|\d+);",
            raw_body,
        )
    )


    # -----------------------------------------------------
    # CHARACTER ANOMALY
    # -----------------------------------------------------

    unusual_unicode_count = sum(
        1
        for char in f"{subject} {body}"
        if ord(char) > 127
    )


    # -----------------------------------------------------
    # ENTROPY
    # -----------------------------------------------------

    entropy = 0.0

    sample = (
        f"{subject} {body}"
    )[:5000]

    if sample:

        counts = Counter(
            sample
        )

        length = len(
            sample
        )

        entropy = -sum(
            (
                count / length
            )
            * math.log2(
                count / length
            )
            for count in counts.values()
        )


    return {

        # Text

        "text_length": len(
            f"{subject} {body}"
        ),

        "word_count": len(
            word_list
        ),

        "uppercase_ratio": round(
            uppercase_ratio,
            4,
        ),

        "exclamation_count": exclamation_count,

        "question_count": question_count,

        "character_entropy": round(
            entropy,
            4,
        ),


        # Identity

        "sender_domain": sender_domain,

        "reply_to_domain": reply_domain,

        "sender_reply_to_mismatch": (
            sender_reply_mismatch
        ),


        # URLs

        "url_count": len(
            urls
        ),

        "unique_url_domains": len(
            set(url_domains)
        ),

        "ip_url_count": ip_url_count,

        "punycode_url_count": punycode_count,

        "suspicious_tld_count": (
            suspicious_tld_count
        ),

        "encoded_url_count": (
            encoded_url_count
        ),

        "long_url_count": long_url_count,


        # Attachments

        "attachment_count": len(
            attachments
        ),

        "dangerous_attachment_count": (
            dangerous_attachment_count
        ),

        "archive_attachment_count": (
            archive_attachment_count
        ),

        "macro_attachment_count": (
            macro_attachment_count
        ),

        "double_extension_count": (
            double_extension_count
        ),


        # HTML

        "script_tag_count": script_tag_count,

        "iframe_count": iframe_count,

        "html_tag_count": html_tag_count,

        "encoded_entity_count": (
            encoded_entity_count
        ),


        # Character anomalies

        "unusual_unicode_count": (
            unusual_unicode_count
        ),

    }


# =========================================================
# BEHAVIORAL / SOCIAL ENGINEERING INTELLIGENCE
# =========================================================

def analyze_email_behavior(
    email: Dict[str, Any]
) -> Dict[str, List[str]]:

    subject = _clean(
        email.get(
            "subject",
            "",
        )
    )

    body = _clean(
        email.get(
            "body",
            email.get(
                "text",
                "",
            ),
        )
    )

    text = (
        f"{subject} {body}"
    ).lower()


    categories = {

        "urgency_pressure": [

            "urgent",
            "immediately",
            "asap",
            "action required",
            "final notice",
            "verify now",
            "respond immediately",
            "within 24 hours",
            "account will be suspended",

        ],

        "credential_harvesting": [

            "verify your password",
            "confirm your password",
            "login to your account",
            "verify your account",
            "credential",
            "sign in now",
            "reset your password",
            "validate your account",

        ],

        "financial_fraud": [

            "wire transfer",
            "bank account",
            "payment due",
            "invoice attached",
            "change bank details",
            "payment instructions",
            "transfer funds",
            "banking information",

        ],

        "impersonation": [

            "ceo",
            "chief executive",
            "human resources",
            "it support",
            "security team",
            "microsoft support",
            "administrative department",

        ],

        "account_takeover": [

            "unusual activity",
            "unauthorized login",
            "account locked",
            "security alert",
            "suspicious login",
            "confirm identity",

        ],

        "business_email_compromise": [

            "confidential request",
            "do not call",
            "keep this confidential",
            "are you available",
            "need you to handle",
            "purchase gift cards",
            "send gift cards",

        ],

    }


    results: Dict[str, List[str]] = {}


    for category, patterns in categories.items():

        matches = [

            pattern

            for pattern in patterns

            if pattern in text

        ]

        if matches:

            results[
                category
            ] = matches[:20]


    return results


# =========================================================
# SOC FEATURE EVIDENCE
# =========================================================

def build_feature_evidence(
    email: Dict[str, Any]
) -> List[Dict[str, Any]]:

    evidence: List[
        Dict[str, Any]
    ] = []


    features = extract_advanced_features(
        email
    )

    behavior = analyze_email_behavior(
        email
    )


    # -----------------------------------------------------
    # BEHAVIOR
    # -----------------------------------------------------

    for category, matches in behavior.items():

        evidence.append(
            {
                "type": "behavioral_signal",
                "name": category,
                "matches": matches,
                "severity": (
                    "HIGH"
                    if category in {
                        "credential_harvesting",
                        "financial_fraud",
                        "business_email_compromise",
                    }
                    else "MEDIUM"
                ),
            }
        )


    # -----------------------------------------------------
    # IDENTITY
    # -----------------------------------------------------

    if features[
        "sender_reply_to_mismatch"
    ]:

        evidence.append(
            {
                "type": "identity_signal",
                "name": "sender_reply_to_domain_mismatch",
                "sender_domain": features[
                    "sender_domain"
                ],
                "reply_to_domain": features[
                    "reply_to_domain"
                ],
                "severity": "HIGH",
            }
        )


    # -----------------------------------------------------
    # URL
    # -----------------------------------------------------

    if features[
        "ip_url_count"
    ]:

        evidence.append(
            {
                "type": "url_signal",
                "name": "ip_address_based_url",
                "count": features[
                    "ip_url_count"
                ],
                "severity": "HIGH",
            }
        )


    if features[
        "punycode_url_count"
    ]:

        evidence.append(
            {
                "type": "url_signal",
                "name": "punycode_domain_detected",
                "count": features[
                    "punycode_url_count"
                ],
                "severity": "HIGH",
            }
        )


    if features[
        "suspicious_tld_count"
    ]:

        evidence.append(
            {
                "type": "url_signal",
                "name": "suspicious_top_level_domain",
                "count": features[
                    "suspicious_tld_count"
                ],
                "severity": "MEDIUM",
            }
        )


    if features[
        "encoded_url_count"
    ]:

        evidence.append(
            {
                "type": "url_signal",
                "name": "encoded_url_detected",
                "count": features[
                    "encoded_url_count"
                ],
                "severity": "MEDIUM",
            }
        )


    # -----------------------------------------------------
    # ATTACHMENTS
    # -----------------------------------------------------

    if features[
        "dangerous_attachment_count"
    ]:

        evidence.append(
            {
                "type": "attachment_signal",
                "name": "dangerous_attachment_type",
                "count": features[
                    "dangerous_attachment_count"
                ],
                "severity": "CRITICAL",
            }
        )


    if features[
        "double_extension_count"
    ]:

        evidence.append(
            {
                "type": "attachment_signal",
                "name": "double_extension_attachment",
                "count": features[
                    "double_extension_count"
                ],
                "severity": "HIGH",
            }
        )


    if features[
        "macro_attachment_count"
    ]:

        evidence.append(
            {
                "type": "attachment_signal",
                "name": "macro_enabled_document",
                "count": features[
                    "macro_attachment_count"
                ],
                "severity": "HIGH",
            }
        )


    if features[
        "archive_attachment_count"
    ]:

        evidence.append(
            {
                "type": "attachment_signal",
                "name": "archive_attachment",
                "count": features[
                    "archive_attachment_count"
                ],
                "severity": "MEDIUM",
            }
        )


    # -----------------------------------------------------
    # HTML / OBFUSCATION
    # -----------------------------------------------------

    if features[
        "script_tag_count"
    ]:

        evidence.append(
            {
                "type": "structure_signal",
                "name": "embedded_script_detected",
                "count": features[
                    "script_tag_count"
                ],
                "severity": "HIGH",
            }
        )


    if features[
        "iframe_count"
    ]:

        evidence.append(
            {
                "type": "structure_signal",
                "name": "embedded_iframe_detected",
                "count": features[
                    "iframe_count"
                ],
                "severity": "MEDIUM",
            }
        )


    if features[
        "encoded_entity_count"
    ]:

        evidence.append(
            {
                "type": "obfuscation_signal",
                "name": "encoded_html_entities",
                "count": features[
                    "encoded_entity_count"
                ],
                "severity": "MEDIUM",
            }
        )


    # -----------------------------------------------------
    # TEXT ANOMALIES
    # -----------------------------------------------------

    if features[
        "uppercase_ratio"
    ] > 0.45:

        evidence.append(
            {
                "type": "linguistic_signal",
                "name": "excessive_uppercase_language",
                "ratio": features[
                    "uppercase_ratio"
                ],
                "severity": "LOW",
            }
        )


    if features[
        "exclamation_count"
    ] >= 5:

        evidence.append(
            {
                "type": "linguistic_signal",
                "name": "excessive_exclamation_usage",
                "count": features[
                    "exclamation_count"
                ],
                "severity": "LOW",
            }
        )


    # -----------------------------------------------------
    # ADVANCED IDENTITY INTELLIGENCE
    # -----------------------------------------------------

    identity = analyze_identity_intelligence(
        email
    )

    identity_risk_score = identity.get(
        "identity_risk_score",
        0,
    )

    identity_risk_level = identity.get(
        "identity_risk_level",
        "LOW",
    )

    if identity.get(
        "claimed_brands"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "brand_claim_detected",
                "brands": identity.get(
                    "claimed_brands"
                ),
                "severity": "MEDIUM",
            }
        )


    if identity.get(
        "identity_conflicts"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "brand_identity_conflict",
                "conflicts": identity.get(
                    "identity_conflicts"
                ),
                "severity": (
                    "CRITICAL"
                    if identity_risk_score >= 70
                    else "HIGH"
                ),
            }
        )


    if identity.get(
        "typosquatting_findings"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "sender_typosquatting_detected",
                "findings": identity.get(
                    "typosquatting_findings"
                ),
                "severity": "CRITICAL",
            }
        )


    if identity.get(
        "reply_to_typosquatting_findings"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "reply_to_typosquatting_detected",
                "findings": identity.get(
                    "reply_to_typosquatting_findings"
                ),
                "severity": "HIGH",
            }
        )


    if identity.get(
        "sender_is_free_email_provider"
    ) and identity.get(
        "claimed_brands"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "brand_claim_from_free_email_provider",
                "sender_domain": identity.get(
                    "sender_domain"
                ),
                "severity": "HIGH",
            }
        )


    if identity.get(
        "reply_is_free_email_provider"
    ) and identity.get(
        "claimed_brands"
    ):

        evidence.append(
            {
                "type": "identity_intelligence",
                "name": "brand_claim_reply_to_free_provider",
                "reply_to_domain": identity.get(
                    "reply_to_domain"
                ),
                "severity": "HIGH",
            }
        )


    if identity_risk_score >= 70:

        evidence.append(
            {
                "type": "identity_risk",
                "name": "critical_identity_risk",
                "risk_score": identity_risk_score,
                "risk_level": identity_risk_level,
                "severity": "CRITICAL",
            }
        )

    elif identity_risk_score >= 50:

        evidence.append(
            {
                "type": "identity_risk",
                "name": "high_identity_risk",
                "risk_score": identity_risk_score,
                "risk_level": identity_risk_level,
                "severity": "HIGH",
            }
        )

    elif identity_risk_score >= 25:

        evidence.append(
            {
                "type": "identity_risk",
                "name": "elevated_identity_risk",
                "risk_score": identity_risk_score,
                "risk_level": identity_risk_level,
                "severity": "MEDIUM",
            }
        )


    return evidence


# =========================================================
# SOC SUMMARY
# =========================================================

def build_feature_summary(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    features = extract_advanced_features(
        email
    )

    behavior = analyze_email_behavior(
        email
    )

    evidence = build_feature_evidence(
        email
    )

    severity_counts = Counter(
        item.get(
            "severity",
            "UNKNOWN",
        )
        for item in evidence
    )

    return {

        "features": features,

        "behavior": behavior,

        "evidence_count": len(
            evidence
        ),

        "severity_distribution": dict(
            severity_counts
        ),

        "evidence": evidence,

    }

# =========================================================
# ENTERPRISE IDENTITY INTELLIGENCE
# =========================================================

FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "yandex.com",
    "zoho.com",
}


KNOWN_BRANDS: Dict[str, Set[str]] = {

    "microsoft": {
        "microsoft",
        "office365",
        "office",
        "outlook",
        "azure",
        "windows",
    },

    "google": {
        "google",
        "gmail",
        "googleworkspace",
        "youtube",
    },

    "amazon": {
        "amazon",
        "aws",
        "amazonpay",
    },

    "paypal": {
        "paypal",
    },

    "apple": {
        "apple",
        "icloud",
    },

    "meta": {
        "facebook",
        "instagram",
        "whatsapp",
        "meta",
    },

    "linkedin": {
        "linkedin",
    },

    "netflix": {
        "netflix",
    },

    "banking": {
        "bank",
        "banking",
        "payment",
        "securebank",
    },

}


def _extract_display_name(
    sender: str
) -> str:

    if not sender:
        return ""

    match = re.match(
        r"\s*([^<]+?)\s*<[^>]+>",
        sender,
    )

    if match:
        return match.group(1).strip()

    if "@" in sender:
        return ""

    return sender.strip()


def _normalize_identity_text(
    value: str
) -> str:

    value = value.lower()

    value = re.sub(
        r"[^a-z0-9]",
        "",
        value,
    )

    return value


def _domain_root(
    domain: str
) -> str:

    if not domain:
        return ""

    parts = domain.lower().split(".")

    if len(parts) < 2:
        return domain.lower()

    return parts[-2]


def _levenshtein_distance(
    left: str,
    right: str,
) -> int:

    if left == right:
        return 0

    if not left:
        return len(right)

    if not right:
        return len(left)

    previous_row = list(
        range(len(right) + 1)
    )

    for i, left_char in enumerate(
        left,
        start=1,
    ):

        current_row = [i]

        for j, right_char in enumerate(
            right,
            start=1,
        ):

            insert_cost = (
                current_row[-1] + 1
            )

            delete_cost = (
                previous_row[j] + 1
            )

            replace_cost = (
                previous_row[j - 1]
                + (
                    0
                    if left_char == right_char
                    else 1
                )
            )

            current_row.append(
                min(
                    insert_cost,
                    delete_cost,
                    replace_cost,
                )
            )

        previous_row = current_row

    return previous_row[-1]


def _string_similarity(
    left: str,
    right: str,
) -> float:

    left = _normalize_identity_text(
        left
    )

    right = _normalize_identity_text(
        right
    )

    if not left or not right:
        return 0.0

    distance = _levenshtein_distance(
        left,
        right,
    )

    maximum_length = max(
        len(left),
        len(right),
    )

    if maximum_length == 0:
        return 1.0

    similarity = (
        1.0
        - (
            distance
            / maximum_length
        )
    )

    return round(
        max(
            0.0,
            similarity,
        ),
        4,
    )


def _detect_claimed_brands(
    value: str
) -> List[str]:

    normalized = (
        _normalize_identity_text(value)
    )

    detected: List[str] = []

    if not normalized:
        return detected

    for brand, aliases in KNOWN_BRANDS.items():

        for alias in aliases:

            normalized_alias = (
                _normalize_identity_text(alias)
            )

            if (
                normalized_alias
                and normalized_alias
                in normalized
            ):

                detected.append(
                    brand
                )

                break

    return sorted(
        set(detected)
    )


def _detect_typosquatting(
    domain: str
) -> List[Dict[str, Any]]:

    findings: List[
        Dict[str, Any]
    ] = []

    root = _domain_root(
        domain
    )

    if not root:
        return findings

    normalized_root = (
        _normalize_identity_text(root)
    )

    for brand, aliases in KNOWN_BRANDS.items():

        for alias in aliases:

            normalized_alias = (
                _normalize_identity_text(alias)
            )

            if not normalized_alias:
                continue

            similarity = (
                _string_similarity(
                    normalized_root,
                    normalized_alias,
                )
            )

            distance = (
                _levenshtein_distance(
                    normalized_root,
                    normalized_alias,
                )
            )

            if (
                normalized_root
                != normalized_alias
                and len(normalized_alias) >= 4
                and similarity >= 0.75
            ):

                findings.append(
                    {
                        "brand": brand,
                        "alias": alias,
                        "domain_root": root,
                        "similarity": similarity,
                        "edit_distance": distance,
                    }
                )

    findings.sort(
        key=lambda item: (
            item["similarity"],
            -item["edit_distance"],
        ),
        reverse=True,
    )

    return findings[:10]


def analyze_identity_intelligence(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    # IMPORTANT:
    # Do not use _clean() for email addresses because
    # display-name email formats such as:
    # Microsoft <security@example.com>
    # would lose the address when angle brackets are
    # interpreted as HTML tags.

    sender = str(
        email.get(
            "sender",
            email.get(
                "from",
                email.get(
                    "from_address",
                    "",
                ),
            ),
        )
        or ""
    ).strip()

    reply_to = str(
        email.get(
            "reply_to",
            email.get(
                "reply-to",
                "",
            ),
        )
        or ""
    ).strip()

    display_name = (
        _extract_display_name(
            sender
        )
    )

    sender_domain = (
        _domain_from_email(
            sender
        )
    )

    reply_domain = (
        _domain_from_email(
            reply_to
        )
    )

    sender_root = (
        _domain_root(
            sender_domain
        )
    )

    reply_root = (
        _domain_root(
            reply_domain
        )
    )

    sender_is_free_provider = (
        sender_domain
        in FREE_EMAIL_PROVIDERS
    )

    reply_is_free_provider = (
        reply_domain
        in FREE_EMAIL_PROVIDERS
    )

    claimed_brands = (
        _detect_claimed_brands(
            display_name
        )
    )

    sender_domain_brands = (
        _detect_claimed_brands(
            sender_domain
        )
    )

    reply_domain_brands = (
        _detect_claimed_brands(
            reply_domain
        )
    )

    typosquatting = (
        _detect_typosquatting(
            sender_domain
        )
    )

    reply_typosquatting = (
        _detect_typosquatting(
            reply_domain
        )
        if reply_domain
        else []
    )

    identity_conflicts: List[
        Dict[str, Any]
    ] = []

    for brand in claimed_brands:

        sender_matches_brand = (
            brand
            in sender_domain_brands
        )

        reply_matches_brand = (
            brand
            in reply_domain_brands
        )

        if (
            not sender_matches_brand
            and sender_domain
        ):

            identity_conflicts.append(
                {
                    "brand": brand,
                    "claimed_via": "display_name",
                    "actual_sender_domain": sender_domain,
                    "sender_domain_matches_brand": False,
                }
            )

        if (
            reply_domain
            and not reply_matches_brand
        ):

            identity_conflicts.append(
                {
                    "brand": brand,
                    "claimed_via": "display_name",
                    "actual_reply_domain": reply_domain,
                    "reply_domain_matches_brand": False,
                }
            )

    sender_reply_similarity = (
        _string_similarity(
            sender_root,
            reply_root,
        )
        if sender_root
        and reply_root
        else None
    )

    risk_score = 0

    if identity_conflicts:
        risk_score += 35

    if sender_is_free_provider and claimed_brands:
        risk_score += 25

    if reply_is_free_provider and claimed_brands:
        risk_score += 15

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:
            risk_score += 20

    if typosquatting:
        risk_score += 30

    if reply_typosquatting:
        risk_score += 20

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score >= 70:
        risk_level = "CRITICAL"

    elif risk_score >= 50:
        risk_level = "HIGH"

    elif risk_score >= 25:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"


    return {

        "display_name": display_name,

        "sender_domain": sender_domain,

        "reply_to_domain": reply_domain,

        "sender_domain_root": sender_root,

        "reply_to_domain_root": reply_root,

        "claimed_brands": claimed_brands,

        "sender_domain_brands": (
            sender_domain_brands
        ),

        "reply_domain_brands": (
            reply_domain_brands
        ),

        "sender_is_free_email_provider": (
            sender_is_free_provider
        ),

        "reply_is_free_email_provider": (
            reply_is_free_provider
        ),

        "sender_reply_domain_similarity": (
            sender_reply_similarity
        ),

        "identity_conflicts": (
            identity_conflicts
        ),

        "typosquatting_findings": (
            typosquatting
        ),

        "reply_to_typosquatting_findings": (
            reply_typosquatting
        ),

        "identity_risk_score": risk_score,

        "identity_risk_level": risk_level,

    }







# =========================================================
# ATTACK CHAIN INTELLIGENCE ENGINE
# =========================================================

def analyze_attack_chain(
    email: Dict[str, Any],
    features: Optional[Dict[str, Any]] = None,
    behavior: Optional[Dict[str, Any]] = None,
    identity: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    if features is None:

        features = extract_advanced_features(
            email
        )

    if behavior is None:

        behavior = analyze_email_behavior(
            email
        )

    if identity is None:

        identity = analyze_identity_intelligence(
            email
        )


    attack_stages: List[str] = []

    indicators: List[Dict[str, Any]] = []

    objectives: List[str] = []


    # -----------------------------------------------------
    # STAGE 1: IDENTITY IMPERSONATION
    # -----------------------------------------------------

    if identity.get(
        "claimed_brands"
    ):

        attack_stages.append(
            "Identity Impersonation"
        )

        indicators.append(
            {
                "stage": "Identity Impersonation",
                "indicator": "brand_claim",
                "details": identity.get(
                    "claimed_brands"
                ),
            }
        )


    if identity.get(
        "identity_conflicts"
    ):

        if "Identity Impersonation" not in attack_stages:

            attack_stages.append(
                "Identity Impersonation"
            )

        indicators.append(
            {
                "stage": "Identity Impersonation",
                "indicator": "identity_conflict",
                "details": identity.get(
                    "identity_conflicts"
                ),
            }
        )


    if identity.get(
        "typosquatting_findings"
    ):

        attack_stages.append(
            "Typosquatted Infrastructure"
        )

        indicators.append(
            {
                "stage": "Typosquatted Infrastructure",
                "indicator": "sender_typosquatting",
                "details": identity.get(
                    "typosquatting_findings"
                ),
            }
        )


    if identity.get(
        "reply_to_typosquatting_findings"
    ):

        attack_stages.append(
            "Typosquatted Infrastructure"
        )

        indicators.append(
            {
                "stage": "Typosquatted Infrastructure",
                "indicator": "reply_to_typosquatting",
                "details": identity.get(
                    "reply_to_typosquatting_findings"
                ),
            }
        )


    # -----------------------------------------------------
    # STAGE 2: SOCIAL ENGINEERING
    # -----------------------------------------------------

    urgency = behavior.get(
        "urgency_pressure",
        []
    )

    if urgency:

        attack_stages.append(
            "Social Engineering"
        )

        indicators.append(
            {
                "stage": "Social Engineering",
                "indicator": "urgency_pressure",
                "details": urgency,
            }
        )


    # -----------------------------------------------------
    # STAGE 3: CREDENTIAL HARVESTING
    # -----------------------------------------------------

    credential_signals = behavior.get(
        "credential_harvesting",
        []
    )

    if credential_signals:

        attack_stages.append(
            "Credential Harvesting"
        )

        indicators.append(
            {
                "stage": "Credential Harvesting",
                "indicator": "credential_request",
                "details": credential_signals,
            }
        )

        objectives.append(
            "Credential Theft"
        )


    # -----------------------------------------------------
    # STAGE 4: ACCOUNT TAKEOVER
    # -----------------------------------------------------

    account_takeover = behavior.get(
        "account_takeover",
        []
    )

    if account_takeover:

        attack_stages.append(
            "Account Takeover"
        )

        indicators.append(
            {
                "stage": "Account Takeover",
                "indicator": "account_security_theme",
                "details": account_takeover,
            }
        )

        objectives.append(
            "Account Takeover"
        )


    # -----------------------------------------------------
    # STAGE 5: MALICIOUS URL INFRASTRUCTURE
    # -----------------------------------------------------

    url_indicators = []


    if features.get(
        "ip_url_count",
        0
    ) > 0:

        url_indicators.append(
            "IP Address URL"
        )


    if features.get(
        "punycode_url_count",
        0
    ) > 0:

        url_indicators.append(
            "Punycode Domain"
        )


    if features.get(
        "suspicious_tld_count",
        0
    ) > 0:

        url_indicators.append(
            "Suspicious TLD"
        )


    if features.get(
        "encoded_url_count",
        0
    ) > 0:

        url_indicators.append(
            "Encoded URL"
        )


    if url_indicators:

        attack_stages.append(
            "Malicious Infrastructure"
        )

        indicators.append(
            {
                "stage": "Malicious Infrastructure",
                "indicator": "suspicious_url_infrastructure",
                "details": url_indicators,
            }
        )


    # -----------------------------------------------------
    # STAGE 6: MALICIOUS ATTACHMENT DELIVERY
    # -----------------------------------------------------

    attachment_indicators = []


    if features.get(
        "dangerous_attachment_count",
        0
    ) > 0:

        attachment_indicators.append(
            "Dangerous File Type"
        )


    if features.get(
        "macro_attachment_count",
        0
    ) > 0:

        attachment_indicators.append(
            "Macro Enabled Document"
        )


    if features.get(
        "double_extension_count",
        0
    ) > 0:

        attachment_indicators.append(
            "Double Extension"
        )


    if attachment_indicators:

        attack_stages.append(
            "Malware Delivery"
        )

        indicators.append(
            {
                "stage": "Malware Delivery",
                "indicator": "malicious_attachment",
                "details": attachment_indicators,
            }
        )

        objectives.append(
            "Malware Execution"
        )


    # -----------------------------------------------------
    # DETERMINE PRIMARY ATTACK TYPE
    # -----------------------------------------------------

    attack_type = "Unknown"


    has_credential = (
        "Credential Harvesting"
        in attack_stages
    )


    has_impersonation = (
        "Identity Impersonation"
        in attack_stages
    )


    has_malware = (
        "Malware Delivery"
        in attack_stages
    )


    has_malicious_infrastructure = (
        "Malicious Infrastructure"
        in attack_stages
    )


    if (
        has_credential
        and has_impersonation
    ):

        attack_type = (
            "Credential Phishing"
        )


    elif (
        has_malware
        and has_impersonation
    ):

        attack_type = (
            "Malware Delivery via Impersonation"
        )


    elif has_malware:

        attack_type = (
            "Malware Delivery"
        )


    elif (
        has_credential
        and has_malicious_infrastructure
    ):

        attack_type = (
            "Credential Phishing"
        )


    elif has_impersonation:

        attack_type = (
            "Brand Impersonation"
        )


    elif has_malicious_infrastructure:

        attack_type = (
            "Suspicious Infrastructure Abuse"
        )


    # -----------------------------------------------------
    # CONFIDENCE SCORING
    # -----------------------------------------------------

    confidence = 0


    stage_weights = {

        "Identity Impersonation": 18,

        "Typosquatted Infrastructure": 20,

        "Social Engineering": 12,

        "Credential Harvesting": 22,

        "Account Takeover": 15,

        "Malicious Infrastructure": 18,

        "Malware Delivery": 25,

    }


    unique_stages = list(
        dict.fromkeys(
            attack_stages
        )
    )


    for stage in unique_stages:

        confidence += stage_weights.get(
            stage,
            0,
        )


    confidence = min(
        confidence,
        100,
    )


    # -----------------------------------------------------
    # ATTACK COMPLEXITY
    # -----------------------------------------------------

    stage_count = len(
        unique_stages
    )


    if stage_count >= 5:

        attack_complexity = "ADVANCED"

    elif stage_count >= 3:

        attack_complexity = "HIGH"

    elif stage_count >= 2:

        attack_complexity = "MEDIUM"

    else:

        attack_complexity = "LOW"


    # -----------------------------------------------------
    # LIKELY OBJECTIVE
    # -----------------------------------------------------

    unique_objectives = list(
        dict.fromkeys(
            objectives
        )
    )


    if not unique_objectives:

        likely_objective = (
            "Unknown"
        )

    elif len(unique_objectives) == 1:

        likely_objective = (
            unique_objectives[0]
        )

    else:

        likely_objective = (
            "Multiple Objectives"
        )


    return {

        "attack_chain_detected": (
            len(unique_stages) > 0
        ),

        "attack_type": attack_type,

        "attack_stages": unique_stages,

        "stage_count": stage_count,

        "indicators": indicators,

        "confidence": confidence,

        "attack_complexity": (
            attack_complexity
        ),

        "likely_objective": (
            likely_objective
        ),

        "objectives": (
            unique_objectives
        ),

    }




# =========================================================
# THREAT INTELLIGENCE CORRELATION ENGINE
# =========================================================

def analyze_threat_intelligence(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Correlates signals from multiple MailTrace AI engines.

    Sources:
    - Advanced feature extraction
    - Behavioral analysis
    - Identity intelligence
    - Attack chain analysis
    """

    if not isinstance(email, dict):
        email = {}

    features = extract_advanced_features(
        email
    )

    behavior = analyze_email_behavior(
        email
    )

    identity = analyze_identity_intelligence(
        email
    )

    attack_chain = analyze_attack_chain(
        email
    )


    # -----------------------------------------------------
    # CORRELATED INDICATORS
    # -----------------------------------------------------

    correlated_indicators = []

    threat_clusters = []

    risk_score = 0


    # -----------------------------------------------------
    # IDENTITY CORRELATION
    # -----------------------------------------------------

    identity_stages = attack_chain.get(
        "attack_stages",
        []
    )

    if "Identity Impersonation" in identity_stages:

        correlated_indicators.append(
            "Identity Impersonation"
        )

        risk_score += 18


    if "Typosquatted Infrastructure" in identity_stages:

        correlated_indicators.append(
            "Typosquatted Infrastructure"
        )

        risk_score += 20


    # -----------------------------------------------------
    # SOCIAL ENGINEERING
    # -----------------------------------------------------

    if "Social Engineering" in identity_stages:

        correlated_indicators.append(
            "Social Engineering"
        )

        risk_score += 12


    # -----------------------------------------------------
    # CREDENTIAL PHISHING
    # -----------------------------------------------------

    credential_signals = []

    if "Credential Harvesting" in identity_stages:

        credential_signals.append(
            "Credential Harvesting"
        )

        correlated_indicators.append(
            "Credential Harvesting"
        )

        risk_score += 22


    if "Account Takeover" in identity_stages:

        credential_signals.append(
            "Account Takeover"
        )

        correlated_indicators.append(
            "Account Takeover"
        )

        risk_score += 15


    if credential_signals:

        threat_clusters.append(
            {
                "name": (
                    "Credential Phishing Campaign"
                ),
                "confidence": min(
                    70 + len(credential_signals) * 15,
                    100,
                ),
                "signals": credential_signals,
            }
        )


    # -----------------------------------------------------
    # MALICIOUS INFRASTRUCTURE
    # -----------------------------------------------------

    infrastructure_signals = []

    if "Malicious Infrastructure" in identity_stages:

        infrastructure_signals.append(
            "Suspicious URL Infrastructure"
        )

        correlated_indicators.append(
            "Malicious Infrastructure"
        )

        risk_score += 18


    if "Typosquatted Infrastructure" in identity_stages:

        infrastructure_signals.append(
            "Typosquatted Domain"
        )


    if infrastructure_signals:

        threat_clusters.append(
            {
                "name": (
                    "Suspicious Infrastructure Cluster"
                ),
                "confidence": min(
                    65 +
                    len(infrastructure_signals) * 15,
                    100,
                ),
                "signals": infrastructure_signals,
            }
        )


    # -----------------------------------------------------
    # MALWARE DELIVERY
    # -----------------------------------------------------

    if "Malware Delivery" in identity_stages:

        correlated_indicators.append(
            "Malware Delivery"
        )

        risk_score += 25

        threat_clusters.append(
            {
                "name": "Malware Delivery Campaign",
                "confidence": 90,
                "signals": [
                    "Dangerous Attachment"
                ],
            }
        )


    # -----------------------------------------------------
    # MULTI-STAGE ATTACK CORRELATION
    # -----------------------------------------------------

    stage_count = attack_chain.get(
        "stage_count",
        0,
    )

    if stage_count >= 4:

        threat_clusters.append(
            {
                "name": "Multi-Stage Coordinated Attack",
                "confidence": min(
                    75 + stage_count * 4,
                    100,
                ),
                "signals": attack_chain.get(
                    "attack_stages",
                    [],
                ),
            }
        )

        risk_score += 15


    # -----------------------------------------------------
    # FEATURE-LEVEL SIGNAL BOOST
    # -----------------------------------------------------

    if isinstance(features, dict):

        suspicious_url_count = len(
            features.get(
                "suspicious_url_features",
                [],
            )
            if isinstance(
                features.get(
                    "suspicious_url_features",
                    [],
                ),
                list,
            )
            else []
        )

        if suspicious_url_count > 0:

            risk_score += min(
                suspicious_url_count * 5,
                15,
            )


    # -----------------------------------------------------
    # BEHAVIOR SIGNAL BOOST
    # -----------------------------------------------------

    if isinstance(behavior, dict):

        behavior_score = behavior.get(
            "behavior_score",
            0,
        )

        if isinstance(
            behavior_score,
            (int, float),
        ):

            risk_score += min(
                int(behavior_score),
                10,
            )


    # -----------------------------------------------------
    # FINAL RISK SCORE
    # -----------------------------------------------------

    risk_score = min(
        int(risk_score),
        100,
    )


    # -----------------------------------------------------
    # THREAT LEVEL
    # -----------------------------------------------------

    if risk_score >= 85:

        threat_level = "CRITICAL"

    elif risk_score >= 65:

        threat_level = "HIGH"

    elif risk_score >= 35:

        threat_level = "MEDIUM"

    elif risk_score > 0:

        threat_level = "LOW"

    else:

        threat_level = "NONE"


    # -----------------------------------------------------
    # RECOMMENDED ACTION
    # -----------------------------------------------------

    if threat_level == "CRITICAL":

        recommended_action = (
            "BLOCK_AND_QUARANTINE"
        )

    elif threat_level == "HIGH":

        recommended_action = (
            "QUARANTINE_AND_INVESTIGATE"
        )

    elif threat_level == "MEDIUM":

        recommended_action = (
            "FLAG_FOR_REVIEW"
        )

    elif threat_level == "LOW":

        recommended_action = (
            "MONITOR"
        )

    else:

        recommended_action = (
            "ALLOW"
        )


    # -----------------------------------------------------
    # UNIQUE INDICATORS
    # -----------------------------------------------------

    correlated_indicators = list(
        dict.fromkeys(
            correlated_indicators
        )
    )


    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {

        "threat_detected": (
            risk_score > 0
        ),

        "threat_level": threat_level,

        "risk_score": risk_score,

        "correlated_indicators": (
            correlated_indicators
        ),

        "indicator_count": len(
            correlated_indicators
        ),

        "threat_clusters": threat_clusters,

        "cluster_count": len(
            threat_clusters
        ),

        "attack_chain_detected": (
            attack_chain.get(
                "attack_chain_detected",
                False,
            )
        ),

        "attack_complexity": (
            attack_chain.get(
                "attack_complexity",
                "LOW",
            )
        ),

        "likely_objective": (
            attack_chain.get(
                "likely_objective",
                "Unknown",
            )
        ),

        "recommended_action": (
            recommended_action
        ),

    }


# ==========================================================
# MITRE ATT&CK INTELLIGENCE
# ==========================================================

def analyze_mitre_attack(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Maps detected MailTrace AI attack signals to
    MITRE ATT&CK Enterprise tactics and techniques.

    The mapping is evidence-based and uses existing
    MailTrace analysis engines instead of relying on
    a single keyword or isolated signal.
    """

    if not isinstance(email, dict):
        email = {}


    # -----------------------------------------------------
    # COLLECT INTELLIGENCE
    # -----------------------------------------------------

    attack_chain = analyze_attack_chain(email)

    identity = analyze_identity_intelligence(email)

    behavior = analyze_email_behavior(email)


    # -----------------------------------------------------
    # SAFE VALUES
    # -----------------------------------------------------

    attack_stages = attack_chain.get(
        "attack_stages",
        []
    )

    if not isinstance(attack_stages, list):
        attack_stages = []


    chain_details = attack_chain.get(
        "chain_details",
        []
    )

    if not isinstance(chain_details, list):
        chain_details = []


    # -----------------------------------------------------
    # RESULT COLLECTION
    # -----------------------------------------------------

    tactics = []

    techniques = []


    def add_tactic(name: str):

        if name not in tactics:
            tactics.append(name)


    def add_technique(
        technique_id: str,
        name: str,
        tactic: str,
        confidence: int,
        evidence: List[str],
    ):

        techniques.append(
            {
                "id": technique_id,
                "name": name,
                "tactic": tactic,
                "confidence": confidence,
                "evidence": evidence,
            }
        )


    # =====================================================
    # T1566 - PHISHING
    # =====================================================

    phishing_evidence = []

    if (
        "Social Engineering"
        in attack_stages
    ):

        phishing_evidence.append(
            "Social engineering indicators detected"
        )


    if (
        "Credential Harvesting"
        in attack_stages
    ):

        phishing_evidence.append(
            "Credential harvesting behavior detected"
        )


    if phishing_evidence:

        add_tactic(
            "Initial Access"
        )

        add_technique(
            "T1566",
            "Phishing",
            "Initial Access",
            min(
                100,
                70 + (
                    len(phishing_evidence) * 15
                ),
            ),
            phishing_evidence,
        )


    # =====================================================
    # T1566.002 - SPEARPHISHING LINK
    # =====================================================

    urls = _safe_list(
        email.get("urls", [])
    )

    suspicious_link_evidence = []

    if urls:

        if (
            "Malicious Infrastructure"
            in attack_stages
        ):

            suspicious_link_evidence.append(
                "Suspicious URL infrastructure detected"
            )


        if (
            "Credential Harvesting"
            in attack_stages
        ):

            suspicious_link_evidence.append(
                "Credential request combined with URL"
            )


    if suspicious_link_evidence:

        add_tactic(
            "Initial Access"
        )

        add_technique(
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Initial Access",
            min(
                100,
                75 + (
                    len(suspicious_link_evidence)
                    * 10
                ),
            ),
            suspicious_link_evidence,
        )


    # =====================================================
    # T1566.001 - SPEARPHISHING ATTACHMENT
    # =====================================================

    attachments = _safe_list(
        email.get("attachments", [])
    )

    attachment_evidence = []

    if attachments:

        if (
            "Malware Delivery"
            in attack_stages
        ):

            attachment_evidence.append(
                "Suspicious or malicious attachment detected"
            )


    if attachment_evidence:

        add_tactic(
            "Initial Access"
        )

        add_technique(
            "T1566.001",
            "Phishing: Spearphishing Attachment",
            "Initial Access",
            90,
            attachment_evidence,
        )


    # =====================================================
    # T1036 - MASQUERADING
    # =====================================================

    masquerading_evidence = []

    if (
        "Identity Impersonation"
        in attack_stages
    ):

        masquerading_evidence.append(
            "Identity impersonation detected"
        )


    if (
        "Typosquatted Infrastructure"
        in attack_stages
    ):

        masquerading_evidence.append(
            "Typosquatted infrastructure detected"
        )


    if masquerading_evidence:

        add_tactic(
            "Defense Evasion"
        )

        add_technique(
            "T1036",
            "Masquerading",
            "Defense Evasion",
            min(
                100,
                75 + (
                    len(masquerading_evidence)
                    * 10
                ),
            ),
            masquerading_evidence,
        )


    # =====================================================
    # T1056 - INPUT CAPTURE
    # =====================================================

    credential_evidence = []

    if (
        "Credential Harvesting"
        in attack_stages
    ):

        credential_evidence.append(
            "Credential harvesting indicators detected"
        )


    if credential_evidence:

        add_tactic(
            "Credential Access"
        )

        add_technique(
            "T1056",
            "Input Capture",
            "Credential Access",
            95,
            credential_evidence,
        )


    # =====================================================
    # T1078 - VALID ACCOUNTS
    # =====================================================

    account_evidence = []

    if (
        "Account Takeover"
        in attack_stages
    ):

        account_evidence.append(
            "Account takeover indicators detected"
        )


    if account_evidence:


        add_tactic(
            "Defense Evasion"
        )

        add_tactic(
            "Initial Access"
        )

        add_technique(
            "T1078",
            "Valid Accounts",
            "Credential Access",
            90,
            account_evidence,
        )


    # =====================================================
    # T1204 - USER EXECUTION
    # =====================================================

    execution_evidence = []

    if (
        "Malware Delivery"
        in attack_stages
    ):

        execution_evidence.append(
            "Malicious attachment may require user execution"
        )


    if execution_evidence:

        add_tactic(
            "Execution"
        )

        add_technique(
            "T1204",
            "User Execution",
            "Execution",
            85,
            execution_evidence,
        )


    # =====================================================
    # T1204.002 - MALICIOUS FILE
    # =====================================================

    malicious_file_evidence = []

    if attachments and (
        "Malware Delivery"
        in attack_stages
    ):

        malicious_file_evidence.append(
            "Suspicious file delivered through email"
        )


    if malicious_file_evidence:

        add_tactic(
            "Execution"
        )

        add_technique(
            "T1204.002",
            "User Execution: Malicious File",
            "Execution",
            90,
            malicious_file_evidence,
        )


    # =====================================================
    # T1583 - ACQUIRE INFRASTRUCTURE
    # =====================================================

    infrastructure_evidence = []

    if (
        "Malicious Infrastructure"
        in attack_stages
    ):

        infrastructure_evidence.append(
            "Suspicious attacker-controlled infrastructure detected"
        )


    if (
        "Typosquatted Infrastructure"
        in attack_stages
    ):

        infrastructure_evidence.append(
            "Deceptive domain infrastructure detected"
        )


    if infrastructure_evidence:

        add_tactic(
            "Resource Development"
        )

        add_technique(
            "T1583",
            "Acquire Infrastructure",
            "Resource Development",
            min(
                100,
                75 + (
                    len(infrastructure_evidence)
                    * 10
                ),
            ),
            infrastructure_evidence,
        )


    # =====================================================
    # REMOVE DUPLICATE TECHNIQUES
    # =====================================================

    unique_techniques = []

    seen_techniques = set()


    for technique in techniques:

        technique_id = technique.get(
            "id"
        )

        if technique_id in seen_techniques:
            continue

        seen_techniques.add(
            technique_id
        )

        unique_techniques.append(
            technique
        )


    techniques = unique_techniques


    # =====================================================
    # ATTACK COVERAGE SCORE
    # =====================================================

    technique_count = len(
        techniques
    )

    tactic_count = len(
        tactics
    )


    coverage_score = min(
        100,
        (
            technique_count * 10
        )
        +
        (
            tactic_count * 5
        ),
    )


    # =====================================================
    # RESULT
    # =====================================================

    return {

        "mitre_detected": (
            technique_count > 0
        ),

        "tactics": tactics,

        "tactic_count": tactic_count,

        "techniques": techniques,

        "technique_count": technique_count,

        "coverage_score": coverage_score,

        "attack_complexity": (
            attack_chain.get(
                "attack_complexity",
                "LOW",
            )
        ),

        "likely_objective": (
            attack_chain.get(
                "likely_objective",
                "Unknown",
            )
        ),

    }



# ==========================================================
# ATTACK CHAIN RECONSTRUCTION ENGINE
# ==========================================================

def reconstruct_attack_chain(
    email: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Reconstructs the likely adversarial attack progression
    from detected MITRE ATT&CK techniques.

    This engine does not replace MITRE detection.

    Instead, it transforms individual MITRE techniques into
    an ordered attack narrative suitable for SOC investigation.
    """

    # ------------------------------------------------------
    # INPUT SAFETY
    # ------------------------------------------------------

    if not isinstance(email, dict):

        email = {}


    # ------------------------------------------------------
    # MITRE INTELLIGENCE
    # ------------------------------------------------------

    mitre_result = analyze_mitre_attack(email)

    techniques = (
        mitre_result.get(
            "techniques",
            []
        )
        if isinstance(mitre_result, dict)
        else []
    )


    # ------------------------------------------------------
    # ATTACK STAGE DEFINITIONS
    # ------------------------------------------------------

    stage_definitions = [

        {
            "id": "initial_access",
            "name": "Initial Access",
            "order": 1,
            "techniques": {
                "T1566",
                "T1566.001",
                "T1566.002",
            },
        },

        {
            "id": "defense_evasion",
            "name": "Defense Evasion",
            "order": 2,
            "techniques": {
                "T1036",
            },
        },

        {
            "id": "credential_access",
            "name": "Credential Access",
            "order": 3,
            "techniques": {
                "T1056",
                "T1078",
            },
        },

        {
            "id": "execution",
            "name": "Execution",
            "order": 4,
            "techniques": {
                "T1204",
                "T1204.002",
            },
        },

        {
            "id": "resource_development",
            "name": "Resource Development",
            "order": 5,
            "techniques": {
                "T1583",
            },
        },

    ]


    # ------------------------------------------------------
    # TECHNIQUE LOOKUP
    # ------------------------------------------------------

    technique_map = {}

    for technique in techniques:

        if not isinstance(
            technique,
            dict
        ):

            continue

        technique_id = technique.get("id")

        if isinstance(
            technique_id,
            str
        ):

            technique_map[
                technique_id
            ] = technique


    # ------------------------------------------------------
    # STAGE RECONSTRUCTION
    # ------------------------------------------------------

    stages = []

    for definition in stage_definitions:

        matched_techniques = []

        stage_evidence = []

        confidences = []


        for technique_id in definition["techniques"]:

            technique = technique_map.get(
                technique_id
            )

            if not technique:

                continue


            matched_techniques.append(
                technique_id
            )


            confidence = technique.get(
                "confidence",
                0
            )

            if isinstance(
                confidence,
                (int, float)
            ):

                confidences.append(
                    confidence
                )


            evidence = technique.get(
                "evidence",
                []
            )

            if isinstance(
                evidence,
                list
            ):

                for item in evidence:

                    if (
                        isinstance(item, str)
                        and item not in stage_evidence
                    ):

                        stage_evidence.append(
                            item
                        )


        if matched_techniques:

            stage_confidence = round(

                sum(confidences)
                / len(confidences)

            ) if confidences else 0


            stages.append(

                {
                    "id": definition["id"],

                    "name": definition["name"],

                    "order": definition["order"],

                    "detected": True,

                    "confidence": stage_confidence,

                    "techniques": matched_techniques,

                    "evidence": stage_evidence,

                }

            )


    # ------------------------------------------------------
    # SORT ATTACK CHAIN
    # ------------------------------------------------------

    stages.sort(

        key=lambda stage:
        stage.get("order", 999)

    )


    # ------------------------------------------------------
    # CHAIN COMPLETENESS
    # ------------------------------------------------------

    total_possible_stages = len(
        stage_definitions
    )

    detected_stage_count = len(
        stages
    )


    completeness_score = round(

        (
            detected_stage_count
            / total_possible_stages
        ) * 100

    ) if total_possible_stages else 0


    # ------------------------------------------------------
    # PRIMARY ATTACK PATH
    # ------------------------------------------------------

    primary_attack_path = [

        stage["name"]

        for stage in stages

    ]


    # ------------------------------------------------------
    # OBJECTIVE INFERENCE
    # ------------------------------------------------------

    detected_ids = set(
        technique_map.keys()
    )


    if (
        "T1056" in detected_ids
        or "T1078" in detected_ids
    ):

        likely_objective = (
            "Credential Theft / "
            "Account Compromise"
        )


    elif (
        "T1204" in detected_ids
        or "T1204.002" in detected_ids
    ):

        likely_objective = (
            "Malicious Code Execution"
        )


    elif any(

        technique_id.startswith(
            "T1566"
        )

        for technique_id
        in detected_ids

    ):

        likely_objective = (
            "Phishing-Based Initial Access"
        )


    elif detected_ids:

        likely_objective = (
            "Suspicious Adversarial Activity"
        )


    else:

        likely_objective = (
            "No Clear Attack Objective"
        )


    # ------------------------------------------------------
    # SOPHISTICATION ESTIMATION
    # ------------------------------------------------------

    if (
        detected_stage_count >= 4
        and completeness_score >= 70
    ):

        sophistication = "ADVANCED"


    elif (
        detected_stage_count >= 2
    ):

        sophistication = "MODERATE"


    elif (
        detected_stage_count == 1
    ):

        sophistication = "LOW"


    else:

        sophistication = "NONE"


    # ------------------------------------------------------
    # CHAIN STATUS
    # ------------------------------------------------------

    if detected_stage_count == 0:

        chain_status = "NO_ATTACK_CHAIN"


    elif detected_stage_count == 1:

        chain_status = "PARTIAL"


    elif detected_stage_count >= 3:

        chain_status = "MULTI_STAGE"


    else:

        chain_status = "DEVELOPING"


    # ------------------------------------------------------
    # RESULT
    # ------------------------------------------------------

    return {

        "attack_detected": (
            detected_stage_count > 0
        ),

        "chain_status": chain_status,

        "stages": stages,

        "stage_count": detected_stage_count,

        "primary_attack_path": (
            primary_attack_path
        ),

        "chain_completeness_score": (
            completeness_score
        ),

        "likely_objective": (
            likely_objective
        ),

        "attack_sophistication": (
            sophistication
        ),

        "mitre_technique_count": (
            len(technique_map)
        ),

    }
