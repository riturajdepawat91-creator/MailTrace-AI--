from __future__ import annotations

from typing import Any

from .header_parser import parse_email_headers
from .ip_extractor import extract_ip_candidates, extract_public_ips
from .relay_chain import build_relay_chain, summarize_relay_chain
from .authentication_analyzer import analyze_authentication
from .timeline_analyzer import analyze_timeline
from .url_analyzer import analyze_urls
from .origin_scoring import (
    score_origin_candidates,
    get_top_origin_candidate,
)


def analyze_email_forensics(
    raw_email: bytes | str,
    ip_intelligence: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Complete email-forensics evidence pipeline.

    Pipeline:
        raw email
          -> header parsing
          -> IP extraction
          -> relay-chain reconstruction
          -> origin candidate scoring
          -> authentication analysis

    This module evaluates technical infrastructure evidence.
    It does not identify a specific person.
    """

    ip_intelligence = ip_intelligence or {}

    # -----------------------------------------------------
    # HEADER PARSING
    # -----------------------------------------------------

    headers = parse_email_headers(raw_email)

    received_headers = headers.get(
        "received",
        []
    )

    # -----------------------------------------------------
    # IP EXTRACTION
    # -----------------------------------------------------

    ip_candidates = extract_ip_candidates(
        received_headers
    )

    public_ips = extract_public_ips(
        received_headers
    )

    # -----------------------------------------------------
    # RELAY CHAIN
    # -----------------------------------------------------

    relay_chain = build_relay_chain(
        received_headers,
        ip_candidates
    )

    relay_summary = summarize_relay_chain(
        relay_chain
    )

    # -----------------------------------------------------
    # ORIGIN SCORING
    # -----------------------------------------------------

    origin_candidates = score_origin_candidates(
        relay_chain,
        ip_intelligence
    )

    top_origin = get_top_origin_candidate(
        origin_candidates
    )

    # -----------------------------------------------------
    # AUTHENTICATION ANALYSIS
    # -----------------------------------------------------

    authentication_analysis = analyze_authentication(
        headers
    )

    # -----------------------------------------------------
    # TIMELINE ANALYSIS
    # -----------------------------------------------------

    timeline_analysis = analyze_timeline(
        headers
    )

    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    body_text = ""

    try:
        body = headers.get("body", {})
        if isinstance(body, dict):
            body_text = body.get("text", "") or ""
        elif isinstance(body, str):
            body_text = body
    except Exception:
        body_text = ""

    url_analysis = analyze_urls(body_text)

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {
        "headers": headers,

        "ip_intelligence": {
            "candidates": ip_candidates,
            "public_ips": public_ips,
            "public_ip_count": len(public_ips)
        },

        "relay_chain": relay_chain,

        "relay_summary": relay_summary,

        "authentication_analysis": authentication_analysis,

        "timeline_analysis": timeline_analysis,

        "url_analysis": url_analysis,

        "origin_scoring": {
            "candidate_count": len(
                origin_candidates
            ),
            "candidates": origin_candidates,
            "top_candidate": top_origin,
        },

        "forensics_status": {
            "headers_parsed": True,

            "received_headers_found": len(
                received_headers
            ),

            "ip_candidates_found": len(
                ip_candidates
            ),

            "public_ips_found": len(
                public_ips
            ),

            "relay_hops_found": len(
                relay_chain
            ),

            "origin_candidates_found": len(
                origin_candidates
            )
        }
    }






