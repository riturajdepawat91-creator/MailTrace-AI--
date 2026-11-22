from __future__ import annotations

from typing import Any

from services.email_parsing import parse_email_bytes


# =========================================================
# HEADER PARSER
# =========================================================

def parse_email_headers(raw_email: bytes | str) -> dict[str, Any]:
    """
    Parse raw RFC-compliant email content.

    The parser preserves:
    - original header values
    - repeated headers
    - Received chain
    - authentication-related headers

    No trust decision is made here.
    This module only extracts evidence.
    """

    if isinstance(raw_email, str):
        raw_email = raw_email.encode(
            "utf-8",
            errors="replace"
        )

    message, parse_diagnostics = parse_email_bytes(raw_email)

    # -----------------------------------------------------
    # ALL HEADERS
    # -----------------------------------------------------

    all_headers = []
    header_occurrences: dict[str, list[str]] = {}

    for name, value in message.raw_items():

        all_headers.append({
            "name": name,
            "value": str(value)
        })
        header_occurrences.setdefault(name.lower(), []).append(str(value))

    # -----------------------------------------------------
    # REPEATED HEADER HELPER
    # -----------------------------------------------------

    def get_all(name: str) -> list[str]:
        return list(header_occurrences.get(name.lower(), []))

    def get_first(name: str) -> str | None:

        values = get_all(name)

        return values[0] if values else None

    # -----------------------------------------------------
    # IMPORTANT FORENSIC HEADERS
    # -----------------------------------------------------

    received = get_all("Received")

    authentication_results = get_all(
        "Authentication-Results"
    )

    received_spf = get_all(
        "Received-SPF"
    )

    dkim_signature = get_all(
        "DKIM-Signature"
    )

    return_path = get_first(
        "Return-Path"
    )

    reply_to = get_first(
        "Reply-To"
    )

    message_id = get_first(
        "Message-ID"
    )

    date = get_first(
        "Date"
    )

    subject = get_first(
        "Subject"
    )

    sender = get_first(
        "From"
    )

    recipient = get_first(
        "To"
    )

    # -----------------------------------------------------
    # AUTHENTICATION HEADER SUMMARY
    # -----------------------------------------------------

    authentication_headers = {

        "authentication_results":
            authentication_results,

        "received_spf":
            received_spf,

        "dkim_signature":
            dkim_signature,

        "count":
            (
                len(authentication_results)
                + len(received_spf)
                + len(dkim_signature)
            )
    }

    # -----------------------------------------------------
    # BODY EXTRACTION
    # -----------------------------------------------------

    body_text = ""
    body_html = ""
    parse_issues = []

    try:
        if message.is_multipart():

            for part_index, part in enumerate(message.walk()):

                content_type = part.get_content_type()

                if content_type == "text/plain" and part.get_content_disposition() != "attachment":
                    try:
                        body_text += part.get_content()
                    except Exception as error:
                        parse_issues.append({"code": "BODY_DECODE_FAILED", "part_index": part_index, "error_type": type(error).__name__})

                elif content_type == "text/html" and part.get_content_disposition() != "attachment":
                    try:
                        body_html += part.get_content()
                    except Exception as error:
                        parse_issues.append({"code": "HTML_BODY_DECODE_FAILED", "part_index": part_index, "error_type": type(error).__name__})

        else:

            content_type = message.get_content_type()

            if content_type == "text/plain":
                body_text = message.get_content()

            elif content_type == "text/html":
                body_html = message.get_content()

    except Exception as error:
        parse_issues.append({"code": "MIME_BODY_PARSE_FAILED", "error_type": type(error).__name__})
        body_text = ""
        body_html = ""

    body_text = body_text or ""
    body_html = body_html or ""

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {

        "parsing": {
            **parse_diagnostics,
            "status": "PARTIAL" if parse_diagnostics["status"] == "PARTIAL" or parse_issues else "COMPLETE",
            "issues": parse_issues,
        },

        "header_occurrences": header_occurrences,

        "duplicate_headers": [
            {"name": name, "count": len(values), "values": values}
            for name, values in header_occurrences.items()
            if len(values) > 1
        ],

        "header_count":
            len(all_headers),

        "all_headers":
            all_headers,

        "received":
            received,

        "received_count":
            len(received),

        "authentication":
            authentication_headers,

        "return_path":
            return_path,

        "reply_to":
            reply_to,

        "message_id":
            message_id,

        "date":
            date,

        "subject":
            subject,

        "from":
            sender,

        "to":
            recipient,

        "body": {
            "text":
                body_text,

            "html":
                body_html,

            "length":
                len(body_text)
        }
    }
