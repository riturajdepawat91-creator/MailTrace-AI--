from email import policy
from email.parser import BytesParser
from email.message import Message
import re




# ==========================================
# IP INTELLIGENCE
# ==========================================

from services.ip_intelligence import (
    extract_ips_from_chain,
    analyze_ips
)

from services.url_analysis import analyze_urls


# ==========================================
# URL INTELLIGENCE
# ==========================================




# ==========================================
# MAIN EMAIL PARSER
# ==========================================

def parse_email(file_content: bytes, filename: str):

    message = BytesParser(
        policy=policy.default
    ).parsebytes(file_content)


    # --------------------------------------
    # Extract basic email data
    # --------------------------------------

    headers = extract_headers(message)

    body = extract_body(message)

    attachments = extract_attachments(message)

    urls = extract_urls(body)

    # ======================================
    # URL INTELLIGENCE
    # ======================================

    url_intelligence = analyze_urls(
        urls
    )

    authentication = analyze_authentication(
        message
    )

    received_chain = extract_received_chain(
        message
    )


    # --------------------------------------
    # IP INTELLIGENCE
    # --------------------------------------

    relay_ips = extract_ips_from_chain(
        received_chain
    )

    ip_intelligence = analyze_ips(
        relay_ips
    )


    # --------------------------------------
    # Threat analysis
    # --------------------------------------

    threat_analysis = analyze_threat(
        message,
        body,
        urls,
        authentication,
        received_chain
    )


    # --------------------------------------
    # Final analysis result
    # --------------------------------------

    return {

        "filename": filename,

        "basic_information": {

            "subject": message.get(
                "Subject"
            ),

            "from": message.get(
                "From"
            ),

            "to": message.get(
                "To"
            ),

            "cc": message.get(
                "Cc"
            ),

            "reply_to": message.get(
                "Reply-To"
            ),

            "return_path": message.get(
                "Return-Path"
            ),

            "message_id": message.get(
                "Message-ID"
            ),

            "date": message.get(
                "Date"
            )

        },

        "headers": headers,

        "received_chain": received_chain,

        "ip_intelligence": ip_intelligence,

        "body": {

            "text": body,

            "length": len(body)

        },

        "urls": urls,

        # ==================================
        # URL INTELLIGENCE RESULT
        # ==================================

        "url_intelligence": url_intelligence,

        "attachments": attachments,

        "authentication": authentication,

        "threat_analysis": threat_analysis

    }


# ==========================================
# HEADER EXTRACTION
# ==========================================

def extract_headers(message: Message):

    headers = {}


    for key, value in message.items():

        key_lower = key.lower()


        if key_lower == "received":

            if "received" not in headers:

                headers["received"] = []


            headers["received"].append(
                value
            )

        else:

            headers[key_lower] = value


    return headers


# ==========================================
# BODY EXTRACTION
# ==========================================

def extract_body(message: Message):

    body_parts = []


    # --------------------------------------
    # Multipart email
    # --------------------------------------

    if message.is_multipart():

        for part in message.walk():

            content_type = (
                part.get_content_type()
            )

            disposition = (
                part.get_content_disposition()
            )


            if (
                content_type == "text/plain"
                and
                disposition != "attachment"
            ):

                try:

                    content = part.get_content()


                    if content:

                        body_parts.append(
                            content
                        )

                except Exception:

                    pass


    # --------------------------------------
    # Single-part email
    # --------------------------------------

    else:

        try:

            if message.get_content_type() in [
                "text/plain",
                "text/html"
            ]:

                content = message.get_content()


                if content:

                    body_parts.append(
                        content
                    )

        except Exception:

            pass


    return "\n".join(
        body_parts
    ).strip()


# ==========================================
# URL EXTRACTION
# ==========================================

def extract_urls(text: str):

    if not text:

        return []


    pattern = r"https?://[^\s<>\"]+"


    urls = re.findall(
        pattern,
        text
    )


    # --------------------------------------
    # Remove duplicate URLs
    # --------------------------------------

    unique_urls = list(
        dict.fromkeys(
            urls
        )
    )


    return unique_urls


# ==========================================
# ATTACHMENT EXTRACTION
# ==========================================

def extract_attachments(message: Message):

    attachments = []


    for part in message.walk():

        filename = part.get_filename()


        if filename:

            payload = part.get_payload(
                decode=True
            )


            size = (
                len(payload)
                if payload
                else 0
            )


            attachments.append({

                "filename": filename,

                "content_type":
                    part.get_content_type(),

                "size": size

            })


    return attachments


# ==========================================
# SPF / DKIM / DMARC ANALYSIS
# ==========================================

def analyze_authentication(message: Message):

    results = {

        "spf": "NOT_FOUND",

        "dkim": "NOT_FOUND",

        "dmarc": "NOT_FOUND"

    }


    auth_headers = message.get_all(
        "Authentication-Results",
        []
    )


    if not auth_headers:

        return results


    combined = " ".join(
        auth_headers
    ).lower()


    # --------------------------------------
    # SPF
    # --------------------------------------

    spf_match = re.search(
        r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        combined
    )


    if spf_match:

        results["spf"] = (
            spf_match.group(1).upper()
        )


    # --------------------------------------
    # DKIM
    # --------------------------------------

    dkim_match = re.search(
        r"\bdkim\s*=\s*(pass|fail|none|temperror|permerror)",
        combined
    )


    if dkim_match:

        results["dkim"] = (
            dkim_match.group(1).upper()
        )


    # --------------------------------------
    # DMARC
    # --------------------------------------

    dmarc_match = re.search(
        r"\bdmarc\s*=\s*(pass|fail|none|temperror|permerror)",
        combined
    )


    if dmarc_match:

        results["dmarc"] = (
            dmarc_match.group(1).upper()
        )


    return results


# ==========================================
# RECEIVED / RELAY CHAIN
# ==========================================

def extract_received_chain(message: Message):

    received_headers = message.get_all(
        "Received",
        []
    )


    chain = []


    for index, received in enumerate(
        received_headers,
        start=1
    ):

        ip_addresses = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            received
        )


        chain.append({

            "hop": index,

            "raw": received,

            "ip_addresses":
                list(
                    dict.fromkeys(
                        ip_addresses
                    )
                )

        })


    return chain


# ==========================================
# THREAT DETECTION ENGINE
# ==========================================

def analyze_threat(
    message: Message,
    body: str,
    urls: list,
    authentication: dict,
    received_chain: list
):

    score = 0

    indicators = []

    # --------------------------------------
    # SCORE BREAKDOWN
    # --------------------------------------

    score_breakdown = []


    # --------------------------------------
    # Normalize email fields
    # --------------------------------------

    subject = (
        message.get("Subject") or ""
    ).lower()


    sender = (
        message.get("From") or ""
    ).lower()


    reply_to = (
        message.get("Reply-To") or ""
    ).lower()


    return_path = (
        message.get("Return-Path") or ""
    ).lower()


    body_lower = (
        body or ""
    ).lower()


    # --------------------------------------
    # SPF
    # --------------------------------------

    if authentication.get("spf") == "FAIL":

        score += 20

        score_breakdown.append({
            "category": "Authentication",
            "signal": "SPF validation failed",
            "points": 20
        })


        indicators.append({

            "type": "authentication",

            "severity": "high",

            "title":
                "SPF validation failed",

            "description":
                "The sending infrastructure failed SPF validation."

        })


    # --------------------------------------
    # DKIM
    # --------------------------------------

    if authentication.get("dkim") == "FAIL":

        score += 20

        score_breakdown.append({
            "category": "Authentication",
            "signal": "DKIM validation failed",
            "points": 20
        })


        indicators.append({

            "type": "authentication",

            "severity": "high",

            "title":
                "DKIM validation failed",

            "description":
                "The email failed DKIM signature validation."

        })


    # --------------------------------------
    # DMARC
    # --------------------------------------

    if authentication.get("dmarc") == "FAIL":

        score += 25

        score_breakdown.append({
            "category": "Authentication",
            "signal": "DMARC validation failed",
            "points": 25
        })


        indicators.append({

            "type": "authentication",

            "severity": "critical",

            "title":
                "DMARC validation failed",

            "description":
                "The visible sender identity failed DMARC alignment."

        })


    # --------------------------------------
    # Reply-To mismatch
    # --------------------------------------

    if sender and reply_to:

        sender_domain = extract_domain(
            sender
        )


        reply_domain = extract_domain(
            reply_to
        )


        if (
            sender_domain
            and reply_domain
            and sender_domain != reply_domain
        ):

            score += 20

            score_breakdown.append({
                "category": "Identity",
                "signal": "Reply-To domain mismatch",
                "points": 20
            })


            indicators.append({

                "type": "identity",

                "severity": "high",

                "title":
                    "Reply-To domain mismatch",

                "description":
                    f"Sender domain '{sender_domain}' "
                    f"differs from Reply-To domain "
                    f"'{reply_domain}'."

            })


    # --------------------------------------
    # Return-Path mismatch
    # --------------------------------------

    if sender and return_path:

        sender_domain = extract_domain(
            sender
        )


        return_domain = extract_domain(
            return_path
        )


        if (
            sender_domain
            and return_domain
            and sender_domain != return_domain
        ):

            score += 10

            score_breakdown.append({
                "category": "Identity",
                "signal": "Return-Path mismatch",
                "points": 10
            })


            indicators.append({

                "type": "identity",

                "severity": "medium",

                "title":
                    "Return-Path mismatch",

                "description":
                    f"Return-Path domain '{return_domain}' "
                    f"does not match sender domain "
                    f"'{sender_domain}'."

            })


    # --------------------------------------
    # Suspicious URL detection
    # --------------------------------------

    for url in urls:

        url_lower = url.lower()


        suspicious_terms = [

            "login",

            "verify",

            "verification",

            "account",

            "secure",

            "password",

            "update",

            "confirm"

        ]


        matched_terms = [

            term

            for term in suspicious_terms

            if term in url_lower

        ]


        if matched_terms:

            score += 10

            score_breakdown.append({
                "category": "URL",
                "signal": "Suspicious URL detected",
                "points": 10,
                "url": url
            })


            indicators.append({

                "type": "url",

                "severity": "medium",

                "title":
                    "Suspicious URL detected",

                "description":
                    "URL contains credential or "
                    "account-related keywords.",

                "url":
                    url,

                "matched_terms":
                    matched_terms

            })


    # --------------------------------------
    # Urgency / social engineering
    # --------------------------------------

    urgency_terms = [

        "urgent",

        "immediately",

        "within 24 hours",

        "action required",

        "account suspended",

        "verify your account",

        "failure to verify",

        "confirm your account"

    ]


    matched_urgency = [

        term

        for term in urgency_terms

        if (
            term in subject
            or
            term in body_lower
        )

    ]


    if matched_urgency:

        score += 10

        score_breakdown.append({
            "category": "Social Engineering",
            "signal": "Urgency-based social engineering",
            "points": 10
        })


        indicators.append({

            "type":
                "social_engineering",

            "severity":
                "medium",

            "title":
                "Urgency-based social engineering",

            "description":
                "The message uses urgency or "
                "account-pressure language.",

            "matches":
                matched_urgency

        })


    # --------------------------------------
    # Multiple relay hops
    # --------------------------------------

    if len(received_chain) >= 2:

        indicators.append({

            "type":
                "routing",

            "severity":
                "info",

            "title":
                "Multiple relay hops detected",

            "description":
                f"{len(received_chain)} mail routing hops "
                "were found in the header chain."

        })


    # --------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------

    score = min(
        max(score, 0),
        100
    )


    # --------------------------------------
    # Threat verdict
    # --------------------------------------

    if score >= 75:

        verdict = "CRITICAL"

        confidence = "HIGH"


    elif score >= 50:

        verdict = "HIGH RISK"

        confidence = "HIGH"


    elif score >= 30:

        verdict = "SUSPICIOUS"

        confidence = "MEDIUM"


    else:

        verdict = "LOW RISK"

        confidence = "LOW"


    # --------------------------------------
    # Final threat result
    # --------------------------------------

    return {

        "score":
            score,

        "verdict":
            verdict,

        "confidence":
            confidence,

        "indicator_count":
            len(indicators),

        "indicators":
            indicators
,

        "score_breakdown":
            score_breakdown

    }


# ==========================================
# DOMAIN EXTRACTION
# ==========================================

def extract_domain(value: str):

    match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        value
    )


    if match:

        return match.group(1).lower()


    return None



