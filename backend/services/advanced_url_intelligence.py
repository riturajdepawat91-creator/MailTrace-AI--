"""
MailTrace-AI - Advanced URL Deception & Context Intelligence

New future capability:
    services/advanced_url_intelligence.py

This module deliberately does NOT replace the existing:
    services/url_analysis.py
    services/email_forensics/url_analyzer.py
    services/threat_intelligence/ioc_normalizer.py

Purpose:
    Deep static analysis of a single URL for deception, obfuscation,
    parser-confusion and social-engineering signals.

Safety:
    - No DNS resolution.
    - No HTTP/S requests.
    - No URL fetching.
    - No redirects followed.
    - No subprocess/eval/exec.
    - Bounded input sizes.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata

from dataclasses import dataclass, field
from urllib.parse import (
    ParseResult,
    SplitResult,
    parse_qsl,
    quote,
    unquote,
    urlsplit,
    urlunsplit,
)


ANALYSIS_VERSION = "1.0.4"
STATIC_ONLY = True

MAX_URL_LENGTH = 8192
MAX_HOST_LENGTH = 255
MAX_COMPONENT_LENGTH = 4096
MAX_QUERY_PAIRS = 100
MAX_FINDINGS = 100
MAX_LURE_TOKENS = 40

HTTP_SCHEMES = {"http", "https"}
DANGEROUS_SCHEMES = {
    "javascript",
    "data",
    "vbscript",
    "file",
    "ms-msdt",
    "ms-officecmd",
    "search-ms",
}

SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 110, 135, 139, 143, 389, 445, 1433, 1521,
    3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8081, 8443,
    8888, 9000, 9200,
}

LURE_TERMS = {
    "account", "accounts", "authenticate", "authentication", "billing",
    "confirm", "credential", "credentials", "document", "documents",
    "download", "invoice", "invoices", "login", "log-in", "password",
    "payment", "payments", "payroll", "refund", "reset", "secure",
    "security", "signin", "sign-in", "suspended", "unlock", "update",
    "urgent", "verify", "verification", "wallet", "webmail", "mfa",
    "2fa", "otp", "support", "tax", "delivery", "sharepoint",
    "onedrive", "office365", "microsoft365",
}

KNOWN_BRANDS = {
    "microsoft": {
        "microsoft.com",
        "live.com",
        "office.com",
        "office365.com",
        "microsoftonline.com",
    },
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
    "а": "a", "ɑ": "a", "α": "a",
    "с": "c", "ϲ": "c",
    "е": "e", "ε": "e",
    "һ": "h", "н": "h",
    "і": "i", "ι": "i",
    "ј": "j",
    "к": "k",
    "ｍ": "m",
    "ո": "n",
    "о": "o", "ο": "o",
    "р": "p", "ρ": "p",
    "ѕ": "s",
    "τ": "t",
    "υ": "u",
    "х": "x", "χ": "x",
    "у": "y", "γ": "y",
    "в": "b",
    "ԁ": "d",
    "ɡ": "g",
    "ℓ": "l",
})

ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
}

BIDI_CONTROL_CHARS = {
    "\u061c", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

HEX_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
MULTI_DOT_RE = re.compile(r"\.{2,}")
NUMERIC_HOST_RE = re.compile(r"^(?:\d+|0x[0-9a-f]+|\d+(?:\.\d+){1,3})$", re.I)

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.I)


@dataclass
class URLFinding:
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
class URLAnalysisResult:
    raw_url: str
    canonical_url: str | None = None
    scheme: str | None = None
    username_present: bool = False
    password_present: bool = False
    userinfo_present: bool = False

    hostname: str | None = None
    unicode_hostname: str | None = None
    ascii_hostname: str | None = None
    registrable_domain: str | None = None
    subdomains: list[str] = field(default_factory=list)

    port: int | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None

    normalized_path: str | None = None
    decoded_path: str | None = None
    decoded_query: str | None = None

    ip_address: str | None = None
    ip_version: int | None = None
    alternate_ip_form: str | None = None

    idn_detected: bool = False
    punycode_detected: bool = False
    unicode_confusable: bool = False
    zero_width_detected: bool = False
    bidi_control_detected: bool = False
    encoded_host_detected: bool = False
    encoded_path_detected: bool = False
    parser_confusion: bool = False

    lure_tokens: list[str] = field(default_factory=list)
    brand_candidates: list[str] = field(default_factory=list)
    legitimate_brand_domain: bool = False
    brand_domain_mismatch: bool = False

    findings: list[URLFinding] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "NONE"
    verdict: str = "LOW_RISK"
    confidence: float = 0.0

    bounded_input: bool = False
    query_pairs_inspected: int = 0
    static_only: bool = STATIC_ONLY
    analysis_version: str = ANALYSIS_VERSION

    def add_finding(self, finding: URLFinding) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            return
        self.findings.append(finding)
        self.risk_score = min(100.0, self.risk_score + float(finding.score))

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_url": self.raw_url,
            "canonical_url": self.canonical_url,
            "scheme": self.scheme,
            "username_present": self.username_present,
            "password_present": self.password_present,
            "userinfo_present": self.userinfo_present,
            "hostname": self.hostname,
            "unicode_hostname": self.unicode_hostname,
            "ascii_hostname": self.ascii_hostname,
            "registrable_domain": self.registrable_domain,
            "subdomains": self.subdomains,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "normalized_path": self.normalized_path,
            "decoded_path": self.decoded_path,
            "decoded_query": self.decoded_query,
            "ip_address": self.ip_address,
            "ip_version": self.ip_version,
            "alternate_ip_form": self.alternate_ip_form,
            "idn_detected": self.idn_detected,
            "punycode_detected": self.punycode_detected,
            "unicode_confusable": self.unicode_confusable,
            "zero_width_detected": self.zero_width_detected,
            "bidi_control_detected": self.bidi_control_detected,
            "encoded_host_detected": self.encoded_host_detected,
            "encoded_path_detected": self.encoded_path_detected,
            "parser_confusion": self.parser_confusion,
            "lure_tokens": self.lure_tokens,
            "brand_candidates": self.brand_candidates,
            "legitimate_brand_domain": self.legitimate_brand_domain,
            "brand_domain_mismatch": self.brand_domain_mismatch,
            "findings": [item.to_dict() for item in self.findings],
            "risk_score": round(self.risk_score, 2),
            "severity": self.severity,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "bounded_input": self.bounded_input,
            "query_pairs_inspected": self.query_pairs_inspected,
            "static_only": self.static_only,
            "analysis_version": self.analysis_version,
        }


def _finding(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    score: float,
    confidence: float,
    evidence: dict[str, object] | None = None,
) -> URLFinding:
    return URLFinding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=evidence or {},
    )


def _safe_unquote(value: str, rounds: int = 2) -> str:
    current = value
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _normalize_host(host: str) -> tuple[str, str]:
    unicode_host = host
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host.casefold()
    return unicode_host, ascii_host.casefold().rstrip(".")


def _registrable_domain(ascii_host: str) -> str | None:
    if not ascii_host:
        return None
    try:
        ipaddress.ip_address(ascii_host)
        return ascii_host
    except ValueError:
        pass

    labels = [label for label in ascii_host.split(".") if label]
    if len(labels) < 2:
        return ascii_host
    # Stdlib-only approximation. Exact public-suffix resolution is intentionally
    # not performed here because it would need an external PSL dataset.
    return ".".join(labels[-2:])


def _levenshtein(a: str, b: str, limit: int = 64) -> int:
    if a == b:
        return 0
    if not a:
        return min(len(b), limit)
    if not b:
        return min(len(a), limit)

    if len(a) > len(b):
        a, b = b, a

    prev = list(range(len(a) + 1))
    for j, char_b in enumerate(b, start=1):
        cur = [j]
        row_min = j
        for i, char_a in enumerate(a, start=1):
            cost = 0 if char_a == char_b else 1
            value = min(
                cur[-1] + 1,
                prev[i] + 1,
                prev[i - 1] + cost,
            )
            cur.append(value)
            row_min = min(row_min, value)
        prev = cur
        if row_min > limit:
            return limit
    return min(prev[-1], limit)


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = normalized.translate(CONFUSABLE_MAP)
    return "".join(
        ch for ch in normalized
        if ch.isalnum() or ch in ".-_"
    )


def _detect_ip(host: str | None) -> tuple[str | None, int | None]:
    if not host:
        return None, None
    try:
        addr = ipaddress.ip_address(host)
        return str(addr), addr.version
    except ValueError:
        return None, None


def _detect_numeric_ip_form(host: str | None) -> str | None:
    if not host:
        return None
    candidate = host.casefold().strip()

    # Dotted integer, hexadecimal, decimal-integer forms are intentionally
    # surfaced as alternate representations rather than resolved/connected.
    if re.fullmatch(r"0x[0-9a-f]+", candidate):
        return "hexadecimal"
    if re.fullmatch(r"\d+", candidate):
        try:
            value = int(candidate, 10)
        except ValueError:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return "decimal_integer_ipv4"
        return None

    parts = candidate.split(".")
    if 1 < len(parts) <= 4 and all(re.fullmatch(r"0x[0-9a-f]+|\d+", p) for p in parts):
        if any(p.casefold().startswith("0x") for p in parts):
            return "mixed_numeric_ipv4"
        if any(len(p) > 1 and p.startswith("0") for p in parts):
            return "dotted_octal_like"
    return None


def _host_confusable(host: str) -> bool:
    if not host:
        return False
    skeleton = _skeleton(host)
    return skeleton != host.casefold()


def _path_lure_tokens(path: str, query: str) -> list[str]:
    """
    Detect lure terms as both standalone terms and components of
    hyphen/underscore-separated phrases such as:
        verify-account-password
        sign-in
        reset_password

    Substring matching is deliberately avoided so words such as
    "supporting" do not produce the "support" signal.
    """
    text = f"{_safe_unquote(path)}?{_safe_unquote(query)}".casefold()

    normalized = re.sub(r"[_\-]+", " ", text)
    tokens: list[str] = []

    for term in sorted(LURE_TERMS, key=len, reverse=True):
        escaped = re.escape(term.casefold().replace("-", " "))
        if re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", normalized):
            if term not in tokens:
                tokens.append(term)
            if len(tokens) >= MAX_LURE_TOKENS:
                break

    return tokens


def _brand_candidates(
    host_ascii: str | None,
    userinfo: str = "",
) -> tuple[list[str], bool, bool]:
    if not host_ascii and not userinfo:
        return [], False, False

    host_value = (host_ascii or "").casefold()
    userinfo_value = (userinfo or "").casefold()

    registrable = _registrable_domain(host_value)

    if not registrable:
        return [], False, False

    candidates: list[str] = []
    legitimate = False
    mismatch = False

    skeleton_host = _skeleton(host_ascii)

    for brand, domains in KNOWN_BRANDS.items():
        brand_hit = (
            brand in host_value
            or brand in skeleton_host
            or brand in _skeleton(userinfo_value)
        )

        if not brand_hit:
            continue

        candidates.append(brand)

        if registrable in domains:
            legitimate = True
            continue

        # Brand text appears but registrable destination is unrelated.
        # Use similarity as supplemental evidence rather than identity proof.
        for legitimate_domain in domains:
            legitimate_label = legitimate_domain.split(".")[0]
            distance = _levenshtein(
                _skeleton(registrable.split(".")[0]),
                _skeleton(legitimate_label),
                limit=8,
            )
            if distance <= 2:
                mismatch = True
                break

        if registrable not in domains:
            mismatch = True

    return list(dict.fromkeys(candidates)), legitimate, mismatch


def _canonicalize(
    split: SplitResult,
    ascii_host: str | None,
) -> str:
    scheme = split.scheme.casefold()
    hostname = ascii_host or ""
    userinfo = ""

    if split.username is not None:
        userinfo = quote(split.username, safe=":@-._~") + "@"

    # Passwords are deliberately not reproduced in canonical output.
    # The presence of password is represented separately.
    if split.password is not None:
        userinfo = quote(split.username or "", safe=":@-._~") + ":<redacted>@"

    netloc = f"{userinfo}{hostname}"
    if split.port is not None:
        netloc += f":{split.port}"

    path = re.sub(r"/{2,}", "/", split.path or "")
    path = quote(
        _safe_unquote(path, rounds=1),
        safe="/:@-._~!$&'()*+,;=%",
    )

    query = split.query or ""
    fragment = split.fragment or ""

    return urlunsplit(
        (scheme, netloc, path, query, fragment)
    )


def analyze_url_deception(url: str) -> URLAnalysisResult:
    """
    Perform bounded, static URL deception analysis.

    No network activity occurs.
    """
    raw = str(url or "").strip()
    bounded = len(raw) > MAX_URL_LENGTH
    if bounded:
        raw = raw[:MAX_URL_LENGTH]

    result = URLAnalysisResult(
        raw_url=raw,
        bounded_input=bounded,
    )

    if not raw:
        result.add_finding(_finding(
            "URL_EMPTY_INPUT",
            "Empty URL input",
            "No URL value was supplied for analysis.",
            "INFO",
            0.0,
            1.0,
        ))
        result.severity = "NONE"
        result.verdict = "LOW_RISK"
        return result

    # Raw-string deception signals before parsing.
    raw_lower = raw.casefold()

    if CONTROL_RE.search(raw):
        result.add_finding(_finding(
            "URL_CONTROL_CHARACTERS",
            "Control characters present",
            "The URL contains control characters that can complicate parsing or display.",
            "HIGH",
            20.0,
            0.98,
        ))

    if any(ch in raw for ch in ZERO_WIDTH_CHARS):
        result.zero_width_detected = True
        result.add_finding(_finding(
            "URL_ZERO_WIDTH_CHARACTER",
            "Zero-width Unicode character detected",
            "Invisible Unicode characters are present and can conceal host/path differences.",
            "HIGH",
            18.0,
            0.98,
        ))

    if any(ch in raw for ch in BIDI_CONTROL_CHARS):
        result.bidi_control_detected = True
        result.add_finding(_finding(
            "URL_BIDI_CONTROL",
            "Bidirectional control character detected",
            "Bidirectional formatting controls can alter the visual presentation of URL text.",
            "HIGH",
            22.0,
            0.98,
        ))

    if HEX_ESCAPE_RE.search(raw):
        decoded_once = _safe_unquote(raw, rounds=1)
        if decoded_once != raw:
            result.add_finding(_finding(
                "URL_PERCENT_ENCODING",
                "Percent-encoded URL components detected",
                "Encoded characters are present and decoded forms are inspected for deception signals.",
                "LOW",
                4.0,
                0.96,
                {"encoded_sequences": len(HEX_ESCAPE_RE.findall(raw))},
            ))

    try:
        split = urlsplit(raw)
    except ValueError as error:
        result.add_finding(_finding(
            "URL_PARSE_ERROR",
            "URL parsing failed",
            "The URL could not be parsed safely by the standard URL parser.",
            "HIGH",
            30.0,
            0.99,
            {"error": str(error)},
        ))
        result.severity = "HIGH"
        result.verdict = "SUSPICIOUS"
        result.confidence = 0.99
        return result

    result.scheme = split.scheme.casefold() or None
    result.username_present = split.username is not None
    result.password_present = split.password is not None
    result.userinfo_present = result.username_present or result.password_present

    # Unsupported or dangerous schemes.
    if result.scheme in DANGEROUS_SCHEMES:
        result.add_finding(_finding(
            "URL_DANGEROUS_SCHEME",
            "Non-web executable/resource scheme detected",
            "The URL uses a scheme capable of invoking local or embedded resources rather than ordinary web navigation.",
            "CRITICAL",
            40.0,
            0.99,
            {"scheme": result.scheme},
        ))
    elif result.scheme and result.scheme not in HTTP_SCHEMES:
        result.add_finding(_finding(
            "URL_NON_HTTP_SCHEME",
            "Non-HTTP(S) scheme detected",
            "The URL uses a scheme outside ordinary HTTP/HTTPS navigation.",
            "HIGH",
            18.0,
            0.96,
            {"scheme": result.scheme},
        ))

    if not result.scheme:
        result.add_finding(_finding(
            "URL_MISSING_SCHEME",
            "URL scheme missing",
            "The input does not explicitly declare an HTTP or HTTPS scheme.",
            "LOW",
            4.0,
            0.95,
        ))

    if split.hostname:
        try:
            if len(split.hostname) > MAX_HOST_LENGTH:
                result.add_finding(_finding(
                    "URL_HOST_LENGTH_ANOMALY",
                    "Hostname exceeds normal DNS length envelope",
                    "The hostname is unusually long and may indicate obfuscation or malformed input.",
                    "HIGH",
                    15.0,
                    0.97,
                    {"length": len(split.hostname)},
                ))
        except Exception:
            pass

    try:
        port = split.port
    except ValueError:
        port = None
        result.parser_confusion = True
        result.add_finding(_finding(
            "URL_INVALID_PORT",
            "Invalid port syntax",
            "The URL contains a port value that could not be parsed safely.",
            "HIGH",
            18.0,
            0.98,
        ))

    result.port = port

    if port is not None and port in SUSPICIOUS_PORTS:
        result.add_finding(_finding(
            "URL_SUSPICIOUS_PORT",
            "Unusual service port detected",
            "The URL uses a port commonly associated with administrative, database, remote-access, or alternate web services.",
            "MEDIUM",
            10.0,
            0.92,
            {"port": port},
        ))

    if result.userinfo_present:
        result.add_finding(_finding(
            "URL_USERINFO_COMPONENT",
            "Userinfo component present",
            "The URL includes a username or password before the destination host; this can conceal the true destination in visual lures.",
            "HIGH",
            20.0,
            0.99,
            {
                "username_present": result.username_present,
                "password_present": result.password_present,
            },
        ))

    if "@" in split.netloc:
        result.parser_confusion = True

    # Host normalization.
    host = split.hostname or ""
    result.hostname = host or None

    if host:
        unicode_host, ascii_host = _normalize_host(host)
        result.unicode_hostname = unicode_host
        result.ascii_hostname = ascii_host
        result.registrable_domain = _registrable_domain(ascii_host)

        labels = [x for x in ascii_host.split(".") if x]
        result.subdomains = labels[:-2] if len(labels) > 2 else []

        if any(label.startswith("xn--") for label in labels):
            result.punycode_detected = True
            result.idn_detected = True
            result.add_finding(_finding(
                "URL_PUNYCODE_HOST",
                "Punycode/IDN hostname detected",
                "The hostname contains an internationalized-domain representation and requires visual identity review.",
                "MEDIUM",
                12.0,
                0.98,
                {"ascii_hostname": ascii_host},
            ))

        if any(ord(ch) > 127 for ch in unicode_host):
            result.idn_detected = True

        if _host_confusable(host):
            result.unicode_confusable = True
            result.add_finding(_finding(
                "URL_UNICODE_CONFUSABLE_HOST",
                "Unicode/confusable hostname signal",
                "The hostname changes under Unicode skeleton normalization, indicating potential homoglyph or visual-deception risk.",
                "HIGH",
                24.0,
                0.97,
                {
                    "unicode_hostname": unicode_host,
                    "skeleton": _skeleton(unicode_host),
                },
            ))

        if "%" in split.netloc:
            result.encoded_host_detected = True
            result.add_finding(_finding(
                "URL_ENCODED_HOST",
                "Encoded hostname component",
                "Percent-encoding is present in the authority component and may create parser/display discrepancies.",
                "HIGH",
                18.0,
                0.96,
            ))

        ip_value, ip_version = _detect_ip(ascii_host)
        result.ip_address = ip_value
        result.ip_version = ip_version

        if ip_value:
            result.add_finding(_finding(
                "URL_DIRECT_IP",
                "Direct IP destination",
                "The destination is specified directly as an IP address rather than a DNS hostname.",
                "MEDIUM",
                18.0,
                0.97,
                {"ip": ip_value, "version": ip_version},
            ))

        numeric_form = _detect_numeric_ip_form(host)
        if numeric_form:
            result.alternate_ip_form = numeric_form
            result.add_finding(_finding(
                "URL_ALTERNATE_IP_FORM",
                "Alternate numeric IP representation",
                "The hostname resembles a decimal, hexadecimal, octal-like, or mixed numeric IPv4 representation.",
                "HIGH",
                24.0,
                0.95,
                {"representation": numeric_form, "host": host},
            ))

        brands, legitimate, mismatch = _brand_candidates(
            ascii_host,
            split.username or "",
        )
        result.brand_candidates = brands
        result.legitimate_brand_domain = legitimate
        result.brand_domain_mismatch = mismatch

        if mismatch and brands and not legitimate:
            result.add_finding(_finding(
                "URL_BRAND_DOMAIN_MISMATCH",
                "Brand identity conflicts with destination domain",
                "A recognizable brand appears in the destination identity while the registrable domain is not an approved brand domain.",
                "HIGH",
                25.0,
                0.95,
                {
                    "brands": brands,
                    "registrable_domain": result.registrable_domain,
                },
            ))

        if len(result.subdomains) >= 3:
            result.add_finding(_finding(
                "URL_DEEP_SUBDOMAIN",
                "Deep subdomain structure",
                "Multiple subdomain levels can be used to bury a deceptive registered domain.",
                "MEDIUM",
                10.0,
                0.9,
                {"subdomain_count": len(result.subdomains)},
            ))

    else:
        result.parser_confusion = True
        result.add_finding(_finding(
            "URL_MISSING_HOST",
            "URL host missing",
            "The URL has no usable hostname component.",
            "HIGH",
            20.0,
            0.99,
        ))

    # Path/query/fragment.
    result.path = split.path or None
    result.query = split.query or None
    result.fragment = split.fragment or None

    path = split.path or ""
    query = split.query or ""

    result.normalized_path = re.sub(r"/{2,}", "/", path) or None
    result.decoded_path = _safe_unquote(path)
    result.decoded_query = _safe_unquote(query)

    if _safe_unquote(path) != path:
        result.encoded_path_detected = True
        result.add_finding(_finding(
            "URL_ENCODED_PATH",
            "Encoded path component",
            "The URL path contains percent-encoded data that is decoded for secondary inspection.",
            "LOW",
            5.0,
            0.96,
        ))

    decoded_once = _safe_unquote(path, rounds=1)
    decoded_twice = _safe_unquote(decoded_once, rounds=1)

    if decoded_twice != decoded_once:
        result.add_finding(_finding(
            "URL_DOUBLE_ENCODING",
            "Potential double URL encoding",
            "Repeated percent-decoding changes the path further, which can indicate layered URL obfuscation.",
            "HIGH",
            15.0,
            0.95,
            {
                "original_path": path[:MAX_COMPONENT_LENGTH],
                "decoded_once": decoded_once[:MAX_COMPONENT_LENGTH],
                "decoded_twice": decoded_twice[:MAX_COMPONENT_LENGTH],
            },
        ))

    if MULTI_DOT_RE.search(path):
        result.add_finding(_finding(
            "URL_DOT_SEGMENT_ANOMALY",
            "Unusual repeated-dot path sequence",
            "Repeated dot sequences can be used in parser or redirect confusion.",
            "MEDIUM",
            8.0,
            0.9,
        ))

    if "@" in raw and split.hostname:
        result.parser_confusion = True

    lure_tokens = _path_lure_tokens(path, query)
    result.lure_tokens = lure_tokens

    if lure_tokens:
        result.add_finding(_finding(
            "URL_LURE_LANGUAGE",
            "Social-engineering lure terms detected",
            "Path/query content contains terms commonly associated with authentication, payments, account recovery, or urgent actions.",
            "MEDIUM",
            min(20.0, 5.0 + len(lure_tokens) * 2.0),
            0.92,
            {"tokens": lure_tokens},
        ))

    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            max_num_fields=MAX_QUERY_PAIRS,
        )
        result.query_pairs_inspected = len(pairs)
    except ValueError as error:
        result.parser_confusion = True
        result.add_finding(_finding(
            "URL_QUERY_PARSE_LIMIT",
            "Query parameter inspection was bounded",
            "The query exceeded the configured static inspection limit.",
            "INFO",
            0.0,
            1.0,
            {"error": str(error), "limit": MAX_QUERY_PAIRS},
        ))

    if len(query) > MAX_COMPONENT_LENGTH:
        result.add_finding(_finding(
            "URL_QUERY_LENGTH_ANOMALY",
            "Unusually large query component",
            "The query component exceeds the bounded inspection envelope and may contain obfuscated payload or tracking material.",
            "MEDIUM",
            8.0,
            0.93,
            {"length": len(query)},
        ))

    # Obvious destination-in-parameter patterns.
    decoded_query_lower = (result.decoded_query or "").casefold()
    if "http://" in decoded_query_lower or "https://" in decoded_query_lower:
        result.parser_confusion = True
        result.add_finding(_finding(
            "URL_NESTED_DESTINATION",
            "Nested URL inside query data",
            "A second URL appears inside query content, which can hide a redirect or destination from a quick visual review.",
            "HIGH",
            18.0,
            0.96,
        ))

    if result.brand_candidates and result.lure_tokens and not result.legitimate_brand_domain:
        result.add_finding(_finding(
            "URL_BRAND_LURE_CORRELATION",
            "Brand impersonation and lure language correlate",
            "Brand-like destination identity is combined with authentication, payment, security, or account-pressure language.",
            "HIGH",
            27.0,
            0.95,
            {
                "brands": result.brand_candidates,
                "lure_tokens": result.lure_tokens,
            },
        ))

    if result.parser_confusion:
        result.add_finding(_finding(
            "URL_PARSER_CONFUSION",
            "URL parser/display ambiguity",
            "Multiple authority, encoding, userinfo, or malformed-component signals indicate that different consumers may display or interpret the URL differently.",
            "HIGH",
            16.0,
            0.93,
        ))

    # A benign, HTTPS, well-formed URL with no deception signals should remain low.
    if result.scheme == "http":
        result.add_finding(_finding(
            "URL_PLAINTEXT_HTTP",
            "Plain HTTP transport",
            "The URL uses HTTP rather than HTTPS. This is contextual risk, not proof of maliciousness.",
            "LOW",
            5.0,
            0.99,
        ))

    if bounded:
        result.add_finding(_finding(
            "URL_INPUT_BOUNDED",
            "URL input exceeded static analysis ceiling",
            "The input was truncated to the configured maximum length before analysis.",
            "INFO",
            0.0,
            1.0,
            {"max_url_length": MAX_URL_LENGTH},
        ))

    # Canonical URL is deliberately sanitized and never network-resolved.
    try:
        result.canonical_url = _canonicalize(
            split,
            result.ascii_hostname,
        )
    except Exception:
        result.canonical_url = None

    # Final score/severity/verdict/confidence.
    result.risk_score = min(100.0, max(0.0, result.risk_score))

    if result.risk_score >= 75:
        result.severity = "CRITICAL"
        result.verdict = "HIGH_CONFIDENCE_DECEPTIVE"
    elif result.risk_score >= 50:
        result.severity = "HIGH"
        result.verdict = "SUSPICIOUS"
    elif result.risk_score >= 30:
        result.severity = "MEDIUM"
        result.verdict = "SUSPICIOUS"
    elif result.risk_score > 0:
        result.severity = "LOW"
        result.verdict = "LOW_RISK"
    else:
        result.severity = "NONE"
        result.verdict = "LOW_RISK"

    if not result.findings:
        result.confidence = 0.9 if result.canonical_url else 0.5
    else:
        result.confidence = min(
            0.99,
            max(item.confidence for item in result.findings),
        )

    return result


def analyze_urls_deception(urls: list[str]) -> list[dict[str, object]]:
    """
    Analyze multiple URLs with deterministic deduplication and bounded input.
    """
    results: list[dict[str, object]] = []
    seen: set[str] = set()

    for value in urls or []:
        cleaned = str(value or "").strip()
        if not cleaned:
            continue

        key = cleaned.casefold()
        if key in seen:
            continue

        seen.add(key)
        results.append(
            analyze_url_deception(cleaned).to_dict()
        )

    return results


__all__ = [
    "ANALYSIS_VERSION",
    "STATIC_ONLY",
    "MAX_URL_LENGTH",
    "MAX_HOST_LENGTH",
    "MAX_COMPONENT_LENGTH",
    "MAX_QUERY_PAIRS",
    "URLFinding",
    "URLAnalysisResult",
    "analyze_url_deception",
    "analyze_urls_deception",
]
