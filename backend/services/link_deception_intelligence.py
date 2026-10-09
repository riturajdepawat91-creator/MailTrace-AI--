"""
MailTrace-AI - Rendered-Link Deception & Visual URL Mismatch Intelligence

Purpose:
    Static SOC-grade analysis of HTML anchors where the URL shown to a user
    can differ from the actual <a href> destination.

Safety:
    - No HTTP/DNS/network activity.
    - No browser/DOM execution.
    - No JavaScript execution.
    - No redirects followed.
    - Bounded parsing and bounded result size.

This module is intentionally standalone. Existing email/url pipelines are not
modified by this file.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

try:
    from .advanced_url_intelligence import analyze_url_deception
except ImportError:  # pragma: no cover
    from advanced_url_intelligence import analyze_url_deception

ANALYSIS_VERSION = "1.0.1"
STATIC_ONLY = True

MAX_HTML_LENGTH = 2 * 1024 * 1024
MAX_ANCHORS = 5000
MAX_VISIBLE_TEXT_CHARS = 8192
MAX_ATTRIBUTE_CHARS = 8192
MAX_ATTR_COUNT = 64
MAX_FINDINGS_PER_LINK = 40
MAX_URL_ANALYSIS_LENGTH = 8192
MAX_RESULT_JSON_CHARS = 2 * 1024 * 1024

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "ms-msdt", "ms-officecmd", "search-ms"}
WEB_SCHEMES = {"http", "https"}
PASSIVE_SCHEMES = {"mailto", "tel", "sms", "cid"}

URL_RE = re.compile(r"(?:(?:https?|ftp)://|//)[^\s<>\"']+", re.I)
DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"']*)?", re.I)
WHITESPACE_RE = re.compile(r"\s+")
ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
BIDI_CONTROL_CHARS = {"\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

# Keep this intentionally aligned with the advanced URL analyzer's supported brands.
KNOWN_BRANDS = {
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com"},
}

CONFUSABLE_MAP = str.maketrans({
    "а": "a", "ɑ": "a", "α": "a", "с": "c", "ϲ": "c", "е": "e", "ε": "e",
    "һ": "h", "н": "h", "і": "i", "ι": "i", "ј": "j", "к": "k", "ｍ": "m",
    "ո": "n", "о": "o", "ο": "o", "р": "p", "ρ": "p", "ѕ": "s", "τ": "t",
    "υ": "u", "х": "x", "χ": "x", "у": "y", "γ": "y", "в": "b", "ԁ": "d",
    "ɡ": "g", "ℓ": "l",
})


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().translate(CONFUSABLE_MAP)
    return "".join(ch for ch in normalized if ch.isalnum() or ch in ".-_")


def _clean_visible_text(value: str) -> str:
    value = html.unescape(value or "")
    value = "".join(ch for ch in value if ch not in ZERO_WIDTH_CHARS)
    value = WHITESPACE_RE.sub(" ", value).strip()
    return value[:MAX_VISIBLE_TEXT_CHARS]


def _safe_decode(value: str, rounds: int = 2) -> str:
    current = value
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _hostname(url: str) -> str | None:
    try:
        return urlsplit(url).hostname.casefold() if urlsplit(url).hostname else None
    except ValueError:
        return None


def _registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    labels = [p for p in host.casefold().rstrip(".").split(".") if p]
    if len(labels) < 2:
        return host.casefold()
    return ".".join(labels[-2:])


def _extract_visible_url(text: str) -> str | None:
    text = _clean_visible_text(text)
    if not text:
        return None
    match = URL_RE.search(text)
    if match:
        return match.group(0).rstrip(".,);]}>\"")
    match = DOMAIN_RE.search(text)
    if match:
        candidate = match.group(0).rstrip(".,);]}>\"")
        return "https://" + candidate
    return None


def _brand_candidates(text: str, hostname: str | None) -> list[str]:
    haystack = _skeleton(text)
    host_skeleton = _skeleton(hostname or "")
    result: list[str] = []
    for brand in KNOWN_BRANDS:
        if brand in haystack or brand in host_skeleton:
            result.append(brand)
    return result


def _is_external(actual_url: str, base_url: str | None) -> bool | None:
    actual_host = _hostname(actual_url)
    if not actual_host or not base_url:
        return None
    base_host = _hostname(base_url)
    if not base_host:
        return None
    return _registrable_domain(actual_host) != _registrable_domain(base_host)


@dataclass
class LinkFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    score: float
    confidence: float = 0.9
    evidence: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": round(float(self.score), 2),
            "confidence": round(float(self.confidence), 3),
            "evidence": self.evidence,
        }


@dataclass
class LinkAnalysisResult:
    index: int
    visible_text: str = ""
    href: str = ""
    visible_url: str | None = None
    actual_destination: str | None = None
    text_domain: str | None = None
    destination_domain: str | None = None
    text_registrable_domain: str | None = None
    destination_registrable_domain: str | None = None
    domain_mismatch: bool = False
    registrable_domain_mismatch: bool = False
    brand_mismatch: bool = False
    visible_brands: list[str] = field(default_factory=list)
    destination_brands: list[str] = field(default_factory=list)
    protocol_mismatch: bool = False
    encoded_href: bool = False
    javascript_href: bool = False
    dangerous_scheme: bool = False
    userinfo_href: bool = False
    relative_href: bool = False
    fragment_only: bool = False
    passive_scheme: bool = False
    external_link: bool | None = None
    link_context: str = "unknown"
    deception_score: float = 0.0
    confidence: float = 0.0
    severity: str = "NONE"
    verdict: str = "LOW_RISK"
    bounded: bool = False
    findings: list[LinkFinding] = field(default_factory=list)

    def add_finding(self, finding: LinkFinding) -> None:
        if len(self.findings) >= MAX_FINDINGS_PER_LINK:
            return
        self.findings.append(finding)
        self.deception_score = min(100.0, self.deception_score + max(0.0, finding.score))

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "visible_text": self.visible_text,
            "href": self.href,
            "visible_url": self.visible_url,
            "actual_destination": self.actual_destination,
            "text_domain": self.text_domain,
            "destination_domain": self.destination_domain,
            "text_registrable_domain": self.text_registrable_domain,
            "destination_registrable_domain": self.destination_registrable_domain,
            "domain_mismatch": self.domain_mismatch,
            "registrable_domain_mismatch": self.registrable_domain_mismatch,
            "brand_mismatch": self.brand_mismatch,
            "visible_brands": self.visible_brands,
            "destination_brands": self.destination_brands,
            "protocol_mismatch": self.protocol_mismatch,
            "encoded_href": self.encoded_href,
            "javascript_href": self.javascript_href,
            "dangerous_scheme": self.dangerous_scheme,
            "userinfo_href": self.userinfo_href,
            "relative_href": self.relative_href,
            "fragment_only": self.fragment_only,
            "passive_scheme": self.passive_scheme,
            "external_link": self.external_link,
            "link_context": self.link_context,
            "deception_score": round(self.deception_score, 2),
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "verdict": self.verdict,
            "bounded": self.bounded,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class LinkDeceptionAnalysis:
    raw_html_length: int
    bounded_input: bool = False
    anchors_found: int = 0
    anchors_inspected: int = 0
    anchors_truncated: bool = False
    visible_text_chars_inspected: int = 0
    findings_count: int = 0
    high_risk_links: int = 0
    critical_links: int = 0
    risk_score: float = 0.0
    severity: str = "NONE"
    verdict: str = "NO_LINKS"
    confidence: float = 0.0
    links: list[LinkAnalysisResult] = field(default_factory=list)
    static_only: bool = STATIC_ONLY
    analysis_version: str = ANALYSIS_VERSION

    def to_dict(self) -> dict[str, object]:
        payload = {
            "raw_html_length": self.raw_html_length,
            "bounded_input": self.bounded_input,
            "anchors_found": self.anchors_found,
            "anchors_inspected": self.anchors_inspected,
            "anchors_truncated": self.anchors_truncated,
            "visible_text_chars_inspected": self.visible_text_chars_inspected,
            "findings_count": self.findings_count,
            "high_risk_links": self.high_risk_links,
            "critical_links": self.critical_links,
            "risk_score": round(self.risk_score, 2),

            # SOC-normalized aggregate deception score.
            # Kept alongside risk_score for backward compatibility.
            "deception_score": round(self.risk_score, 2),

            "severity": self.severity,
            "verdict": self.verdict,

            # Explicit top-level confidence contract for SOC consumers.
            "confidence": round(self.confidence, 3),
            "links": [link.to_dict() for link in self.links],
            "static_only": self.static_only,
            "analysis_version": self.analysis_version,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded) <= MAX_RESULT_JSON_CHARS:
            return payload
        # Hard-stop on result size rather than emitting an unbounded structure.
        slim = dict(payload)
        links = list(payload["links"])
        # Deterministically shrink the serialized result until it is below the
        # hard output ceiling. Keep the earliest links because input order is
        # stable and those entries are the first inspected evidence.
        while links:
            slim["links"] = links
            slim["anchors_inspected"] = len(links)
            slim["anchors_truncated"] = True
            encoded = json.dumps(slim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if len(encoded) <= MAX_RESULT_JSON_CHARS:
                return slim
            new_len = max(1, len(links) // 2)
            links = links[:new_len]
        slim["links"] = []
        slim["anchors_inspected"] = 0
        slim["anchors_truncated"] = True
        return slim


class _Anchor:
    __slots__ = ("href", "parts", "attr_truncated", "context")

    def __init__(self, href: str, context: str) -> None:
        self.href = href[:MAX_ATTRIBUTE_CHARS]
        self.parts: list[str] = []
        self.attr_truncated = len(href) > MAX_ATTRIBUTE_CHARS
        self.context = context


class _BoundedAnchorParser(HTMLParser):
    def __init__(self, max_anchors: int) -> None:
        super().__init__(convert_charrefs=True)
        self.max_anchors = max_anchors
        self.anchors: list[_Anchor] = []
        self.current: _Anchor | None = None
        self.context_stack: list[str] = []
        self.saw_truncation = False

    def _context(self) -> str:
        return self.context_stack[-1] if self.context_stack else "unknown"

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in {"button", "form", "nav", "footer", "header", "section"}:
            if len(self.context_stack) < 12:
                self.context_stack.append(tag)
        if tag != "a":
            return
        if len(self.anchors) >= self.max_anchors:
            self.saw_truncation = True
            self.current = None
            return
        attr_map: dict[str, str] = {}
        for key, value in attrs[:MAX_ATTR_COUNT]:
            if value is not None and key.casefold() not in attr_map:
                attr_map[key.casefold()] = value
        href = attr_map.get("href", "")
        self.current = _Anchor(href, self._context())
        self.anchors.append(self.current)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() == "a":
            self.current = None

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "a":
            self.current = None
        elif tag in {"button", "form", "nav", "footer", "header", "section"}:
            if self.context_stack:
                self.context_stack.pop()

    def handle_data(self, data: str) -> None:
        if self.current is None:
            return
        if sum(len(x) for x in self.current.parts) >= MAX_VISIBLE_TEXT_CHARS:
            return
        self.current.parts.append(data[: MAX_VISIBLE_TEXT_CHARS])


def _make_finding(rule_id: str, title: str, description: str, severity: str, score: float, confidence: float, evidence: dict[str, object] | None = None) -> LinkFinding:
    return LinkFinding(rule_id, title, description, severity, score, confidence, evidence or {})


def _analyze_link(anchor: _Anchor, index: int, base_url: str | None) -> LinkAnalysisResult:
    visible_text = _clean_visible_text(" ".join(anchor.parts))
    href = html.unescape(anchor.href.strip())[:MAX_ATTRIBUTE_CHARS]
    result = LinkAnalysisResult(index=index, visible_text=visible_text, href=href, link_context=anchor.context, bounded=anchor.attr_truncated)

    if anchor.attr_truncated:
        result.add_finding(_make_finding(
            "LINK_HREF_BOUNDED",
            "Href attribute bounded",
            "The href attribute exceeded the per-attribute inspection limit and was truncated for safety.",
            "INFO", 0.0, 1.0,
        ))

    if not href:
        result.verdict = "INCOMPLETE"
        result.severity = "LOW"
        result.confidence = 1.0
        return result

    lower = href.casefold().lstrip()
    decoded_href = html.unescape(_safe_decode(href))[:MAX_ATTRIBUTE_CHARS]
    decoded_lower = decoded_href.casefold().lstrip()
    result.encoded_href = bool(re.search(r"%[0-9a-fA-F]{2}", href)) or decoded_href != href
    if result.encoded_href:
        result.add_finding(_make_finding(
            "LINK_ENCODED_HREF",
            "Encoded href detected",
            "Percent-encoded characters are present in the link destination and decoded inspection is applied.",
            "LOW", 4.0, 0.96,
        ))

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", decoded_lower)
    scheme = scheme_match.group(1).casefold() if scheme_match else ""
    result.javascript_href = scheme == "javascript"
    result.dangerous_scheme = scheme in DANGEROUS_SCHEMES
    result.passive_scheme = scheme in PASSIVE_SCHEMES
    result.fragment_only = lower.startswith("#")
    result.relative_href = not bool(scheme) and not lower.startswith(("//", "#"))

    if result.dangerous_scheme:
        result.add_finding(_make_finding(
            "LINK_DANGEROUS_SCHEME",
            "Dangerous link scheme",
            "The href uses a non-web scheme that can invoke active, local, or embedded resources.",
            "CRITICAL", 45.0, 0.995, {"scheme": scheme},
        ))
    elif result.passive_scheme:
        result.add_finding(_make_finding(
            "LINK_PASSIVE_SCHEME",
            "Non-web passive scheme",
            "The href uses a passive/contact-oriented URI scheme rather than ordinary web navigation.",
            "INFO", 0.0, 0.98, {"scheme": scheme},
        ))

    if result.userinfo_href or "@" in lower:
        try:
            parsed = urlsplit(decoded_lower)
            result.userinfo_href = parsed.username is not None or parsed.password is not None
        except ValueError:
            result.userinfo_href = "@" in lower
        if result.userinfo_href:
            result.add_finding(_make_finding(
                "LINK_USERINFO",
                "Userinfo component present",
                "An @-based userinfo component can visually obscure the actual hostname in a web URL.",
                "HIGH", 18.0, 0.98,
            ))

    actual = href
    if result.relative_href and base_url:
        try:
            actual = urljoin(base_url, href)
        except ValueError:
            actual = href
    # Decode only for static inspection. Nothing is fetched or executed.
    if decoded_href != href and (decoded_lower.startswith(("http:", "https:", "//", "javascript:", "data:", "vbscript:", "file:"))):
        actual = decoded_href
    result.actual_destination = actual[:MAX_URL_ANALYSIS_LENGTH]

    visible_url = _extract_visible_url(visible_text)
    result.visible_url = visible_url
    result.text_domain = _hostname(visible_url) if visible_url else None
    result.destination_domain = _hostname(result.actual_destination) if result.actual_destination else None
    result.text_registrable_domain = _registrable_domain(result.text_domain)
    result.destination_registrable_domain = _registrable_domain(result.destination_domain)

    if visible_url and result.actual_destination and result.text_domain and result.destination_domain:
        result.domain_mismatch = result.text_domain.casefold().rstrip(".") != result.destination_domain.casefold().rstrip(".")
        result.registrable_domain_mismatch = result.text_registrable_domain != result.destination_registrable_domain
        if result.registrable_domain_mismatch:
            result.add_finding(_make_finding(
                "LINK_VISIBLE_DESTINATION_MISMATCH",
                "Visible URL and destination domain mismatch",
                "The URL shown in the rendered link text points to a different registrable domain than the href destination.",
                "CRITICAL", 48.0, 0.995,
                {"visible_domain": result.text_domain, "destination_domain": result.destination_domain},
            ))
        elif result.domain_mismatch:
            result.add_finding(_make_finding(
                "LINK_HOSTNAME_MISMATCH",
                "Visible hostname and destination hostname differ",
                "The displayed hostname and href hostname differ even though their registrable domains match.",
                "HIGH", 22.0, 0.97,
                {"visible_domain": result.text_domain, "destination_domain": result.destination_domain},
            ))

        try:
            text_scheme = urlsplit(visible_url).scheme.casefold()
            dest_scheme = urlsplit(result.actual_destination).scheme.casefold()
            result.protocol_mismatch = bool(text_scheme and dest_scheme and text_scheme != dest_scheme)
        except ValueError:
            result.protocol_mismatch = False
        if result.protocol_mismatch:
            result.add_finding(_make_finding(
                "LINK_PROTOCOL_MISMATCH",
                "Displayed and destination protocols differ",
                "The rendered URL advertises a different protocol from the actual href destination.",
                "HIGH", 18.0, 0.96,
                {"visible_scheme": urlsplit(visible_url).scheme, "destination_scheme": urlsplit(result.actual_destination).scheme},
            ))

    result.visible_brands = _brand_candidates(visible_text, result.text_domain)
    result.destination_brands = _brand_candidates(result.actual_destination or "", result.destination_domain)
    if result.visible_brands and result.destination_domain:
        unrelated = []
        for brand in result.visible_brands:
            domains = KNOWN_BRANDS[brand]
            if result.destination_registrable_domain not in domains:
                unrelated.append(brand)
        if unrelated:
            result.brand_mismatch = True
            result.add_finding(_make_finding(
                "LINK_VISIBLE_BRAND_DESTINATION_MISMATCH",
                "Visible brand does not match destination",
                "The rendered link text contains a recognized brand cue while the href leads to an unrelated registrable domain.",
                "CRITICAL", 30.0, 0.99,
                {"brands": unrelated, "destination_domain": result.destination_domain},
            ))

    if result.actual_destination and urlsplit(result.actual_destination).scheme.casefold() in WEB_SCHEMES:
        external = _is_external(result.actual_destination, base_url)
        result.external_link = external
        try:
            advanced = analyze_url_deception(result.actual_destination)
            if advanced.userinfo_present and not result.userinfo_href:
                result.userinfo_href = True
                result.add_finding(_make_finding(
                    "LINK_USERINFO_DETECTED_BY_URL_ANALYZER",
                    "Destination contains userinfo",
                    "The destination URL analyzer identified a userinfo component in the final href.",
                    "HIGH", 14.0, 0.98,
                ))
            for f in advanced.findings:
                if f.rule_id in {"URL_ZERO_WIDTH_CHARACTER", "URL_BIDI_CONTROL", "URL_DANGEROUS_SCHEME", "URL_PARSER_CONFUSION", "URL_BRAND_DOMAIN_MISMATCH"}:
                    result.add_finding(_make_finding(
                        f"LINK_DEST_{f.rule_id}",
                        f.title,
                        f.description,
                        f.severity,
                        min(20.0, f.score * 0.5),
                        min(1.0, f.confidence),
                        {"source_rule": f.rule_id},
                    ))
        except Exception:
            # The link module remains functional even if optional delegated analysis fails.
            pass

    # Strong compound-context rule: known-brand visible URL + unrelated destination.
    if result.registrable_domain_mismatch and result.visible_brands:
        result.add_finding(_make_finding(
            "LINK_BRAND_DOMAIN_DECEPTION_CORRELATION",
            "Brand/domain deception correlation",
            "A recognizable brand appears in the rendered URL while the actual href resolves to another registrable domain.",
            "CRITICAL", 20.0, 0.995,
            {"visible_brands": result.visible_brands},
        ))

    if result.deception_score >= 40:
        result.severity, result.verdict = "CRITICAL", "HIGH_CONFIDENCE_DECEPTIVE"
    elif result.deception_score >= 20:
        result.severity, result.verdict = "HIGH", "DECEPTIVE_OR_SUSPICIOUS"
    elif result.deception_score >= 10:
        result.severity, result.verdict = "MEDIUM", "SUSPICIOUS"
    elif result.deception_score > 0:
        result.severity, result.verdict = "LOW", "LOW_RISK_WITH_SIGNALS"
    else:
        result.severity, result.verdict = "NONE", "LOW_RISK"

    # Confidence is evidence-density based, capped and deterministic.
    base_conf = 0.55
    if visible_url:
        base_conf += 0.15
    if result.actual_destination:
        base_conf += 0.15
    if result.findings:
        base_conf += 0.10
    if result.registrable_domain_mismatch:
        base_conf += 0.05
    result.confidence = min(0.99, base_conf)
    return result


def analyze_link_deception(html_body: str, base_url: str | None = None) -> LinkDeceptionAnalysis:
    raw = "" if html_body is None else str(html_body)
    original_length = len(raw)
    bounded = original_length > MAX_HTML_LENGTH
    if bounded:
        raw = raw[:MAX_HTML_LENGTH]

    result = LinkDeceptionAnalysis(raw_html_length=original_length, bounded_input=bounded)

    parser = _BoundedAnchorParser(MAX_ANCHORS)
    try:
        parser.feed(raw)
        parser.close()
    except Exception:
        # HTMLParser is intentionally tolerant; if an implementation/runtime
        # edge case happens, preserve already parsed anchors and continue.
        parser.saw_truncation = True

    result.anchors_found = len(parser.anchors)
    result.anchors_truncated = parser.saw_truncation
    result.anchors_inspected = len(parser.anchors)

    for idx, anchor in enumerate(parser.anchors):
        link = _analyze_link(anchor, idx, base_url)
        result.links.append(link)
        result.visible_text_chars_inspected += min(MAX_VISIBLE_TEXT_CHARS, len(link.visible_text))
        result.findings_count += len(link.findings)
        result.risk_score = min(100.0, result.risk_score + link.deception_score / max(1, len(parser.anchors)))
        if link.severity == "CRITICAL":
            result.critical_links += 1
        if link.severity in {"CRITICAL", "HIGH"}:
            result.high_risk_links += 1

    if not parser.anchors:
        result.verdict = "NO_LINKS"
        result.severity = "NONE"
        result.confidence = 1.0
    elif result.critical_links:
        result.verdict = "DECEPTIVE_LINKS_PRESENT"
        result.severity = "CRITICAL"
        result.confidence = 0.99
    elif result.high_risk_links:
        result.verdict = "HIGH_RISK_LINKS_PRESENT"
        result.severity = "HIGH"
        result.confidence = 0.96
    elif any(link.severity == "MEDIUM" for link in result.links):
        result.verdict = "SUSPICIOUS_LINKS_PRESENT"
        result.severity = "MEDIUM"
        result.confidence = 0.90
    else:
        result.verdict = "NO_HIGH_RISK_LINK_DECEPTION"
        result.severity = "NONE"
        result.confidence = 0.85

    return result


def analyze_link_deception_to_dict(html_body: str, base_url: str | None = None) -> dict[str, object]:
    return analyze_link_deception(html_body, base_url).to_dict()


__all__ = [
    "ANALYSIS_VERSION",
    "STATIC_ONLY",
    "LinkFinding",
    "LinkAnalysisResult",
    "LinkDeceptionAnalysis",
    "analyze_link_deception",
    "analyze_link_deception_to_dict",
]
