"""Static, network-free URL extraction shared across email analysis paths."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

import idna


MAX_URL_LENGTH = 8192
URL_PATTERN = re.compile(r"(?i)(?<![\w+.-])https?://[^\s<>\"']+")
TRAILING_PUNCTUATION = ".,;:!?\"'`"


def trim_url_candidate(value: str) -> str:
    """Drop sentence punctuation and only unmatched closing brackets."""
    value = str(value or "").strip()
    while value and value[-1] in TRAILING_PUNCTUATION:
        value = value[:-1]
    pairs = (("(", ")"), ("[", "]"), ("{", "}"))
    changed = True
    while value and changed:
        changed = False
        for opening, closing in pairs:
            if value.endswith(closing) and value.count(closing) > value.count(opening):
                value = value[:-1]
                changed = True
    return value


def normalize_url(value: str) -> str | None:
    """Canonical comparison form; preserve path/query/fragment and escapes."""
    candidate = trim_url_candidate(value)
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        return None
    if any(ord(ch) < 32 or ch.isspace() for ch in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.casefold()
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if scheme not in {"http", "https"} or not hostname:
        return None
    try:
        try:
            host = str(ipaddress.ip_address(hostname))
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii").casefold().rstrip(".")
            if not host or any(not label for label in host.split(".")):
                return None
    except (UnicodeError, ValueError):
        return None
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    if port is not None and not (scheme == "http" and port == 80 or scheme == "https" and port == 443):
        host = f"{host}:{port}"
    return urlunsplit((scheme, userinfo + host, parsed.path or "/", parsed.query, parsed.fragment))


def url_deduplication_key(value: str) -> str | None:
    return normalize_url(value)


def _plain_occurrences(text: str, part_index: int) -> list[dict]:
    found = []
    for match in URL_PATTERN.finditer(text or ""):
        raw = trim_url_candidate(match.group(0))
        normalized = normalize_url(raw)
        if normalized:
            found.append({
                "original_url": raw,
                "comparison_url": raw,
                "normalized_url": normalized,
                "source_locations": [{
                    "mime_part": part_index,
                    "part": "text/plain",
                    "body_type": "text/plain",
                    "offset": match.start(),
                    "source_fragment": match.group(0),
                    "original_url": raw,
                    "comparison_url": raw,
                }],
            })
    return found


class _HrefExtractor(HTMLParser):
    def __init__(self, html_text: str, part_index: int):
        super().__init__(convert_charrefs=True)
        self.html_text = html_text
        self.part_index = part_index
        self.line_offsets = [0]
        for index, char in enumerate(html_text):
            if char == "\n":
                self.line_offsets.append(index + 1)
        self.urls: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "a":
            return
        href = next((value for name, value in attrs if name.casefold() == "href"), None)
        if not href:
            return
        decoded = href.strip()
        normalized = normalize_url(decoded)
        if not normalized:
            return
        line, column = self.getpos()
        offset = self.line_offsets[min(line - 1, len(self.line_offsets) - 1)] + column
        raw_tag = self.get_starttag_text() or ""
        raw_match = re.search(r"(?is)\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", raw_tag)
        raw_href = next((group for group in raw_match.groups() if group is not None), decoded) if raw_match else decoded
        self.urls.append({
            "original_url": raw_href,
            "comparison_url": trim_url_candidate(decoded),
            "normalized_url": normalized,
            "source_locations": [{
                "mime_part": self.part_index,
                "part": "text/html",
                "body_type": "text/html",
                "offset": offset,
                "line": line,
                "column": column,
                "source_fragment": raw_tag[:2048],
                "original_url": raw_href,
                "comparison_url": trim_url_candidate(decoded),
            }],
        })


def extract_url_evidence(plain_parts: list[tuple[int, str]], html_parts: list[tuple[int, str]]) -> list[dict]:
    """Extract HTTP(S) URLs from decoded text bodies and anchor hrefs only."""
    occurrences: list[dict] = []
    for part_index, content in plain_parts:
        occurrences.extend(_plain_occurrences(content, part_index))
    for part_index, content in html_parts:
        parser = _HrefExtractor(content or "", part_index)
        try:
            parser.feed((content or "")[:2 * 1024 * 1024])
            parser.close()
        except Exception:
            # A malformed HTML fragment must not abort email analysis.
            pass
        occurrences.extend(parser.urls)

    unique: dict[str, dict] = {}
    for occurrence in occurrences:
        key = occurrence["normalized_url"]
        current = unique.setdefault(key, {
            "original_url": occurrence["original_url"],
            "comparison_url": occurrence["comparison_url"],
            "original_values": [],
            "comparison_values": [],
            "normalized_url": key,
            "source_locations": [],
        })
        if occurrence["original_url"] not in current["original_values"]:
            current["original_values"].append(occurrence["original_url"])
        if occurrence["comparison_url"] not in current["comparison_values"]:
            current["comparison_values"].append(occurrence["comparison_url"])
        for location in occurrence["source_locations"]:
            if location not in current["source_locations"]:
                current["source_locations"].append(location)
    return list(unique.values())


def extract_text_urls(text: str) -> list[dict]:
    """Compatibility wrapper for IOC extraction from plain text."""
    evidence = extract_url_evidence([(0, text or "")], [])
    return [{"ioc": item["normalized_url"], "ioc_type": "url", "value": item["normalized_url"]} for item in evidence]
