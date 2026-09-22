# ==========================================
# MAILTRACE AI
# URL INTELLIGENCE ENGINE
# ==========================================

import re
from urllib.parse import urlparse


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

SUSPICIOUS_KEYWORDS = [

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

]


# ==========================================
# BRAND KEYWORDS
# ==========================================

BRAND_KEYWORDS = [

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

]


# ==========================================
# EXTRACT DOMAIN
# ==========================================

def extract_domain(url: str):

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower()

    except Exception:

        return None


# ==========================================
# CHECK IP-BASED URL
# ==========================================

def is_ip_url(domain: str):

    if not domain:
        return False

    ipv4_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(
        ipv4_pattern,
        domain
    ):

        parts = domain.split(".")

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    return False


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

def find_suspicious_keywords(url: str):

    if not url:
        return []

    url_lower = url.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            found.append(keyword)

    return found


# ==========================================
# BRAND INDICATORS
# ==========================================

def find_brand_indicators(domain: str):

    if not domain:
        return []

    domain_lower = domain.lower()

    found = []

    for brand in BRAND_KEYWORDS:

        if brand in domain_lower:

            found.append(brand)

    return found


# ==========================================
# EXCESSIVE SUBDOMAIN CHECK
# ==========================================

def has_deep_subdomain(domain: str):

    if not domain:
        return False

    parts = domain.split(".")

    return len(parts) >= 4


# ==========================================
# LONG URL CHECK
# ==========================================

def is_long_url(url: str):

    if not url:
        return False

    return len(url) > 150


# ==========================================
# ANALYZE SINGLE URL
# ==========================================

def analyze_url(url: str):

    # --------------------------------------
    # Clean input
    # --------------------------------------

    url = (
        url or ""
    ).strip()


    # --------------------------------------
    # Basic parsing
    # --------------------------------------

    try:

        parsed = urlparse(url)

    except Exception:

        parsed = None


    if not parsed:

        return {

            "url": url,

            "domain": None,

            "scheme": None,

            "is_https": False,

            "is_ip_url": False,

            "suspicious": False,

            "risk": "UNKNOWN",

            "risk_score": 0,

            "suspicious_keywords": [],

            "brand_indicators": [],

            "reasons": [

                "Unable to parse URL."

            ]

        }


    # --------------------------------------
    # Extract information
    # --------------------------------------

    domain = extract_domain(
        url
    )


    scheme = (

        parsed.scheme.lower()

        if parsed.scheme

        else ""

    )


    is_https = (
        scheme == "https"
    )


    ip_based = is_ip_url(
        domain
    )


    suspicious_keywords = (
        find_suspicious_keywords(
            url
        )
    )


    brand_indicators = (
        find_brand_indicators(
            domain
        )
    )


    deep_subdomain = (
        has_deep_subdomain(
            domain
        )
    )


    long_url = (
        is_long_url(
            url
        )
    )


    # ======================================
    # RISK CALCULATION
    # ======================================

    risk_score = 0

    reasons = []


    # --------------------------------------
    # IP based URL
    # --------------------------------------

    if ip_based:

        risk_score += 30

        reasons.append(
            "URL uses a direct IP address instead of a domain."
        )


    # --------------------------------------
    # Suspicious keywords
    # --------------------------------------

    if suspicious_keywords:

        keyword_score = min(
            len(suspicious_keywords) * 10,
            30
        )

        risk_score += keyword_score

        reasons.append(
            "URL contains suspicious security "
            "or authentication keywords."
        )


    # --------------------------------------
    # Brand indicators
    # --------------------------------------

    if brand_indicators:

        risk_score += 25

        reasons.append(
            "Domain contains a known brand name "
            "and may require impersonation analysis."
        )


    # --------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------

    if scheme == "http":

        risk_score += 15

        reasons.append(
            "URL does not use HTTPS."
        )


    # --------------------------------------
    # Missing scheme
    # --------------------------------------

    if not scheme:

        risk_score += 10

        reasons.append(
            "URL does not contain a valid scheme."
        )


    # --------------------------------------
    # Deep subdomain
    # --------------------------------------

    if deep_subdomain:

        risk_score += 15

        reasons.append(
            "Domain contains an unusually deep "
            "subdomain structure."
        )


    # --------------------------------------
    # Long URL
    # --------------------------------------

    if long_url:

        risk_score += 10

        reasons.append(
            "URL is unusually long."
        )


    # --------------------------------------
    # Empty domain
    # --------------------------------------

    if not domain:

        risk_score += 20

        reasons.append(
            "URL does not contain a valid domain."
        )


    # --------------------------------------
    # Cap score
    # --------------------------------------

    risk_score = min(
        risk_score,
        100
    )


    # ======================================
    # RISK LEVEL
    # ======================================

    if risk_score >= 75:

        risk = "CRITICAL"

    elif risk_score >= 50:

        risk = "HIGH"

    elif risk_score >= 25:

        risk = "MEDIUM"

    else:

        risk = "LOW"


    # ======================================
    # SUSPICIOUS FLAG
    # ======================================

    suspicious = (
        risk_score >= 25
    )


    # ======================================
    # RESULT
    # ======================================

    return {

        "url": url,

        "domain": domain,

        "scheme": scheme,

        "is_https": is_https,

        "is_ip_url": ip_based,

        "suspicious": suspicious,

        "risk": risk,

        "risk_score": risk_score,

        "suspicious_keywords":
            suspicious_keywords,

        "brand_indicators":
            brand_indicators,

        "reasons":
            reasons

    }


# ==========================================
# ANALYZE MULTIPLE URLs
# ==========================================

def analyze_urls(urls):

    results = []

    if not urls:
        return results


    # --------------------------------------
    # Remove duplicates
    # --------------------------------------

    seen = set()


    for url in urls:

        if not url:
            continue


        url = url.strip()


        if not url:
            continue


        if url in seen:
            continue


        seen.add(url)


        try:

            result = analyze_url(
                url
            )

            results.append(
                result
            )


        except Exception as error:

            results.append({

                "url": url,

                "domain": None,

                "scheme": None,

                "is_https": False,

                "is_ip_url": False,

                "suspicious": False,

                "risk": "UNKNOWN",

                "risk_score": 0,

                "suspicious_keywords": [],

                "brand_indicators": [],

                "reasons": [

                    f"URL analysis error: {error}"

                ]

            })


    return results