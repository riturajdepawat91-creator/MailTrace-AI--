from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


# =========================================================
# URL FORENSICS ANALYZER
# =========================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "click", "link",
    "work", "zip", "mov"
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
}


BRAND_KEYWORDS = {
    "microsoft",
    "google",
    "apple",
    "paypal",
    "amazon",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "docusign"
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "credential",
    "credentials",
    "update",
    "confirm",
    "authenticate",
    "authentication",
    "unlock",
    "suspended",
    "wallet",
    "payment",
    "invoice",
    "refund",
    "urgent"
}


def _clean_url(url: str) -> str:
    return url.rstrip(
        ".,;:!?)]}>\"'"
    )


def _hostname_is_ip(hostname: str | None) -> bool:
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_tld(hostname: str | None) -> str | None:
    if not hostname:
        return None

    if _hostname_is_ip(hostname):
        return None

    hostname = hostname.lower().rstrip(".")

    parts = hostname.split(".")

    if len(parts) < 2:
        return None

    return parts[-1]


def _count_subdomains(hostname: str | None) -> int:
    if not hostname:
        return 0

    if _hostname_is_ip(hostname):
        return 0

    parts = hostname.rstrip(".").split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def _find_brand_indicators(
    hostname: str | None
) -> list[str]:

    if not hostname:
        return []

    hostname_lower = hostname.lower()

    return [
        brand
        for brand in BRAND_KEYWORDS
        if brand in hostname_lower
    ]


def _find_suspicious_keywords(
    url: str
) -> list[str]:

    if not url:
        return []

    url_lower = url.lower()

    return [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]


def _analyse_url(
    url: str
) -> dict[str, Any]:

    parsed = urlparse(url)

    hostname = parsed.hostname
    scheme = parsed.scheme.lower()

    tld = _get_tld(hostname)

    is_ip_address = _hostname_is_ip(
        hostname
    )

    subdomain_count = _count_subdomains(
        hostname
    )

    normalized_host = (
        hostname.lower().rstrip(".")
        if hostname
        else ""
    )

    suspicious_keywords = (
        _find_suspicious_keywords(url)
    )

    brand_indicators = (
        _find_brand_indicators(hostname)
    )

    findings: list[dict[str, Any]] = []
    reasons: list[str] = []

    score = 0

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    if scheme == "http":

        score += 10

        finding = {
            "type": "transport",
            "severity": "MEDIUM",
            "title": "URL uses HTTP",
            "description": (
                "The URL does not use HTTPS encryption."
            )
        }

        findings.append(finding)
        reasons.append(
            "URL does not use HTTPS."
        )

    # ---------------------------------------------------------
    # DIRECT IP
    # ---------------------------------------------------------

    if is_ip_address:

        score += 30

        finding = {
            "type": "ip_url",
            "severity": "HIGH",
            "title": "URL uses an IP address",
            "description": (
                "The destination is specified directly "
                "as an IP address instead of a domain name."
            )
        }

        findings.append(finding)
        reasons.append(
            "URL uses a direct IP address instead of a domain."
        )

    # ---------------------------------------------------------
    # SUSPICIOUS TLD
    # ---------------------------------------------------------

    if tld and tld in SUSPICIOUS_TLDS:

        score += 20

        findings.append({
            "type": "tld",
            "severity": "MEDIUM",
            "title": "Suspicious top-level domain",
            "description": (
                f"The URL uses the .{tld} top-level domain."
            )
        })

        reasons.append(
            f"URL uses suspicious .{tld} TLD."
        )

    # ---------------------------------------------------------
    # URL SHORTENER
    # ---------------------------------------------------------

    if normalized_host in SHORTENER_DOMAINS:

        score += 20

        findings.append({
            "type": "shortener",
            "severity": "MEDIUM",
            "title": "URL shortener detected",
            "description": (
                "The URL uses a known URL-shortening service, "
                "which can hide the final destination."
            )
        })

        reasons.append(
            "URL uses a known URL-shortening service."
        )

    # ---------------------------------------------------------
    # DEEP SUBDOMAIN
    # ---------------------------------------------------------

    if subdomain_count >= 3:

        score += 15

        findings.append({
            "type": "subdomain",
            "severity": "MEDIUM",
            "title": "Deep subdomain structure",
            "description": (
                "The URL contains multiple subdomain levels."
            )
        })

        reasons.append(
            "Domain contains an unusually deep subdomain structure."
        )

    # ---------------------------------------------------------
    # EMBEDDED CREDENTIALS
    # ---------------------------------------------------------

    if parsed.username or parsed.password:

        score += 30

        findings.append({
            "type": "userinfo",
            "severity": "HIGH",
            "title": "Credentials embedded in URL",
            "description": (
                "The URL contains username or password "
                "information before the destination host."
            )
        })

        reasons.append(
            "URL contains embedded username or password information."
        )

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    if suspicious_keywords:

        keyword_score = min(
            len(suspicious_keywords) * 5,
            20
        )

        score += keyword_score

        # Stronger signal when a direct IP is combined
        # with account/authentication-related keywords.
        if is_ip_address and any(
            keyword in suspicious_keywords
            for keyword in (
                "login",
                "signin",
                "verify",
                "verification",
                "password",
                "account",
                "secure",
                "update",
                "confirm",
                "billing"
            )
        ):
            score += 10

        findings.append({
            "type": "keyword",
            "severity": "MEDIUM",
            "title": "Suspicious security keywords detected",
            "description": (
                "The URL contains keywords commonly associated "
                "with account, authentication, payment, or "
                "credential-related actions."
            ),
            "matches": suspicious_keywords
        })

        reasons.append(
            "URL contains suspicious security or authentication keywords."
        )

    # ---------------------------------------------------------
    # BRAND INDICATORS
    # ---------------------------------------------------------

    if brand_indicators:

        score += 25

        findings.append({
            "type": "brand",
            "severity": "MEDIUM",
            "title": "Known brand indicator detected",
            "description": (
                "The destination domain contains a known brand "
                "name and may require impersonation analysis."
            ),
            "matches": brand_indicators
        })

        reasons.append(
            "Domain contains a known brand name."
        )

    # ---------------------------------------------------------
    # LONG URL
    # ---------------------------------------------------------

    if len(url) >= 150:

        score += 10

        findings.append({
            "type": "length",
            "severity": "LOW",
            "title": "Unusually long URL",
            "description": (
                "The URL is unusually long and may contain "
                "tracking or obfuscation parameters."
            )
        })

        reasons.append(
            "URL is unusually long."
        )

    # ---------------------------------------------------------
    # MISSING SCHEME
    # ---------------------------------------------------------

    if not scheme:

        score += 10

        findings.append({
            "type": "scheme",
            "severity": "LOW",
            "title": "URL scheme is missing",
            "description": (
                "The URL does not contain a recognized "
                "HTTP or HTTPS scheme."
            )
        })

        reasons.append(
            "URL does not contain a valid scheme."
        )

    # ---------------------------------------------------------
    # NORMALIZE
    # ---------------------------------------------------------

    score = max(
        0,
        min(
            int(score),
            100
        )
    )

    if score >= 75:
        risk = "CRITICAL"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "NONE"

    suspicious = score >= 25

    return {
        "url": url,
        "domain": hostname,
        "hostname": hostname,
        "scheme": scheme or None,
        "is_https": scheme == "https",
        "is_ip_url": is_ip_address,
        "is_ip_address": is_ip_address,
        "port": parsed.port,
        "path": parsed.path or None,
        "query": parsed.query or None,
        "fragment": parsed.fragment or None,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "suspicious": suspicious,
        "risk": risk,
        "risk_score": score,
        "suspicious_keywords": suspicious_keywords,
        "brand_indicators": brand_indicators,
        "findings": findings,
        "finding_count": len(findings),
        "reasons": reasons
    }


def analyze_urls(
    text: str
) -> dict[str, Any]:

    """
    Extract and statically analyze URLs from email content.

    URLs are never visited or executed.
    """

    if not text:

        return {
            "urls": [],
            "url_count": 0,
            "risk": "NONE",
            "risk_score": 0,
            "suspicious": False,
            "findings": [],
            "finding_count": 0
        }

    extracted = [
        _clean_url(match.group(0))
        for match in URL_PATTERN.finditer(text)
    ]

    urls = list(
        dict.fromkeys(
            url
            for url in extracted
            if url
        )
    )

    analyses = [
        _analyse_url(url)
        for url in urls
    ]

    findings: list[dict[str, Any]] = []

    for analysis in analyses:

        findings.extend(
            analysis.get(
                "findings",
                []
            )
        )

    risk_score = max(
        (
            item["risk_score"]
            for item in analyses
        ),
        default=0
    )

    if risk_score >= 75:
        risk = "CRITICAL"
    elif risk_score >= 60:
        risk = "HIGH"
    elif risk_score >= 30:
        risk = "MEDIUM"
    elif risk_score > 0:
        risk = "LOW"
    else:
        risk = "NONE"

    return {
        "urls": analyses,
        "url_count": len(analyses),
        "risk": risk,
        "risk_score": risk_score,
        "suspicious": risk_score >= 25,
        "findings": findings,
        "finding_count": len(findings)
    }

