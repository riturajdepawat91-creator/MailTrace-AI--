from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit
import idna

from services.ip_address_policy import classify_ip

from services.url_extraction import (
    URL_PATTERN,
    normalize_url,
    url_deduplication_key,
    extract_text_urls,
)


# =========================================================
# IOC NORMALIZER
# =========================================================

IP_PORT_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{1,5})"
    r"(?!\w)"
)

IP_PATTERN = re.compile(
    r"(?<![\w.:])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])"
)

IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:::ffff:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:])"
)
IPV6_PORT_PATTERN = re.compile(r"\[(?P<ip>[0-9A-Fa-f:]+)\]:(?P<port>\d{1,5})")
HASH_PATTERN = re.compile(r"(?<![A-Fa-f0-9-])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9-])")
EMAIL_PATTERN = re.compile(
    r"(?<![\w.!#$%&'*+/=?^_`{|}~-])"
    r"[\w.!#$%&'*+/=?^_`{|}~-]{1,64}@(?:[\w-]{1,63}\.)+[\w-]{2,63}"
    r"(?![\w.-])",
    re.UNICODE,
)

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])"
    r"(?:[\w](?:[\w-]{0,61}[\w])?\.)+"
    r"[\w-]{2,63}"
    r"(?![\w.-])"
)


def _clean(value: str) -> str:
    return str(value).strip().rstrip(
        ".,;:!?)]}>\"'"
    )


def normalize_ip(value: str) -> str | None:
    policy = classify_ip(_clean(value))
    return policy["normalized_ip"] if policy["valid"] else None


def normalize_domain(value: str) -> str | None:
    value = _clean(value).rstrip(".")

    if not value:
        return None

    if "@" in value:
        return None

    if "/" in value:
        return None

    if ":" in value:
        return None

    try:
        value = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None
    final_label = value.rsplit(".", 1)[-1]
    valid_tld = final_label.isalpha() or final_label.startswith("xn--")
    if len(value) > 253 or not valid_tld or not DOMAIN_PATTERN.fullmatch(value):
        return None
    return value


def extract_ip_ports(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PORT_PATTERN.finditer(text):
        ip = normalize_ip(match.group("ip"))

        if not ip:
            continue

        port = int(match.group("port"))

        if port < 1 or port > 65535:
            continue

        ioc = f"{ip}:{port}"

        if ioc.lower() in seen:
            continue

        seen.add(ioc.lower())

        results.append({
            "ioc": ioc,
            "ioc_type": "ip:port",
            "value": ip,
            "port": port,
        })

    return results


def extract_ips(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PATTERN.finditer(text):
        ip = normalize_ip(match.group(0))

        if not ip:
            continue

        key = ip.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": ip,
            "ioc_type": "ip",
            "value": ip,
        })

    for match in IPV6_CANDIDATE_PATTERN.finditer(text):
        ip = normalize_ip(match.group(0))
        if not ip:
            continue
        if ip not in seen:
            seen.add(ip)
            results.append({"ioc": ip, "ioc_type": "ip", "value": ip})

    return results


def extract_urls(text: str) -> list[dict]:
    if not text:
        return []

    results = extract_text_urls(text)
    for item in results:
        parsed = urlsplit(item["ioc"])
        item["domain"] = parsed.hostname.lower() if parsed.hostname else None
    return results


def extract_domains(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in DOMAIN_PATTERN.finditer(text):
        domain = normalize_domain(match.group(0))

        if not domain:
            continue

        key = domain.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": domain,
            "ioc_type": "domain",
            "value": domain,
        })

    return results


def _ip_scope(value: str) -> str:
    policy = classify_ip(value)
    if not policy["valid"]:
        return "invalid"
    names = {
        "PUBLIC": "public",
        "PRIVATE": "private",
        "LOOPBACK": "loopback",
        "LINK_LOCAL": "link_local",
        "MULTICAST": "multicast",
        "UNSPECIFIED": "unspecified",
        "RESERVED": "reserved",
        "DOCUMENTATION": "documentation",
    }
    return names.get(policy["classification"], "non_public")



def _normalize_email(value: str) -> str | None:
    candidate = str(value or "").strip().strip("<>.,;:!?\"'")
    if candidate.count("@") != 1:
        return None
    local, domain = candidate.rsplit("@", 1)
    if not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    normalized_domain = normalize_domain(domain)
    if not normalized_domain:
        return None
    return f"{local}@{normalized_domain}"


def _normalize_hash(value: str) -> tuple[str, str] | None:
    value = str(value or "").strip()
    algorithms = {32: "md5", 40: "sha1", 64: "sha256"}
    algorithm = algorithms.get(len(value))
    if not algorithm or not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None
    return algorithm, value.lower()


def extract_iocs(
    text: str,
    url_evidence: list[dict] | None = None,
    additional_sources: list[dict] | None = None,
    extra_indicators: list[dict] | None = None,
) -> list[dict]:
    """Return type-aware, deduplicated indicators with all observed provenance."""
    records: dict[tuple[str, str], dict] = {}

    def add(
        indicator_type: str,
        original: str,
        normalized: str,
        location: dict,
        extraction_method: str,
        normalization_decision: str,
        indicator_category: str | None = None,
        **attributes,
    ) -> None:
        key = (indicator_type, normalized)
        record = records.setdefault(key, {
            "ioc": normalized,
            "value": normalized,
            "ioc_type": indicator_type,
            "indicator_type": indicator_category or indicator_type,
            "normalized_value": normalized,
            "original_value": original,
            "original_values": [],
            "comparison_values": [],
            "source_locations": [],
            "occurrence_count": 0,
            "extraction_method": extraction_method,
            "extraction_methods": [],
            "normalization_decision": normalization_decision,
        })
        if original not in record["original_values"]:
            record["original_values"].append(original)
        if location and location not in record["source_locations"]:
            record["source_locations"].append(location)
            record["occurrence_count"] += 1
        if extraction_method not in record["extraction_methods"]:
            record["extraction_methods"].append(extraction_method)
        for name, value in attributes.items():
            if isinstance(value, list):
                current_values = record.setdefault(name, [])
                for item in value:
                    if item not in current_values:
                        current_values.append(item)
            else:
                record[name] = value

    def add_ip(raw: str, location: dict, method: str = "body_pattern") -> None:
        normalized = normalize_ip(raw)
        if not normalized:
            return
        address = ipaddress.ip_address(normalized)
        add("ip", raw, normalized, location, method, "ipaddress compressed form", ip_version=address.version, ip_scope=_ip_scope(normalized))

    def scan_text(source_text: str, source_name: str, body_type: str = "text/plain") -> None:
        source_text = str(source_text or "")
        port_ranges = []
        for match in IP_PORT_PATTERN.finditer(source_text):
            port_ranges.append(match.span("ip"))
            ip = normalize_ip(match.group("ip"))
            port = int(match.group("port"))
            if ip and 1 <= port <= 65535:
                location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": match.group(0)}
                add_ip(match.group("ip"), location)
                add("ip:port", match.group(0), f"{ip}:{port}", location, "body_pattern", "validated IP plus port", port=port, ip_version=ipaddress.ip_address(ip).version, ip_scope=_ip_scope(ip))
        for match in IPV6_PORT_PATTERN.finditer(source_text):
            port_ranges.append(match.span("ip"))
            ip = normalize_ip(match.group("ip"))
            port = int(match.group("port"))
            if ip and 1 <= port <= 65535:
                location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": match.group(0)}
                add_ip(match.group("ip"), location)
                add("ip:port", match.group(0), f"[{ip}]:{port}", location, "body_pattern", "validated IPv6 plus port", port=port, ip_version=6, ip_scope=_ip_scope(ip))
        for match in IP_PATTERN.finditer(source_text):
            if any(start <= match.start() and match.end() <= end for start, end in port_ranges):
                continue
            location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": match.group(0)}
            add_ip(match.group(0), location)
        for match in IPV6_CANDIDATE_PATTERN.finditer(source_text):
            if any(start <= match.start() and match.end() <= end for start, end in port_ranges):
                continue
            location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": match.group(0)}
            add_ip(match.group(0), location)
        for match in EMAIL_PATTERN.finditer(source_text):
            raw = match.group(0)
            normalized = _normalize_email(raw)
            if normalized:
                location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": raw}
                add("email", raw, normalized, location, "email_pattern", "preserve local-part case; IDNA-normalize domain")
                email_domain = normalized.rsplit("@", 1)[1]
                add("domain", raw.rsplit("@", 1)[1], email_domain, {**location, "context": "email_domain"}, "email_domain", "lowercase IDNA ASCII domain")
        for match in HASH_PATTERN.finditer(source_text):
            raw = match.group(0)
            normalized_hash = _normalize_hash(raw)
            if normalized_hash:
                algorithm, normalized = normalized_hash
                location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": raw}
                add(algorithm, raw, normalized, location, "hex_digest_pattern", "lowercase hexadecimal; length identifies digest algorithm", indicator_category="hash", hash_algorithm=algorithm)
        for match in DOMAIN_PATTERN.finditer(source_text):
            raw = match.group(0)
            normalized = normalize_domain(raw)
            if normalized:
                location = {"source": source_name, "body_type": body_type, "offset": match.start(), "source_fragment": raw}
                add("domain", raw, normalized, location, "domain_pattern", "lowercase IDNA ASCII hostname")

    if text:
        scan_text(text, "body.text")
    for source in additional_sources or []:
        if not isinstance(source, dict):
            continue
        scan_text(source.get("text", ""), str(source.get("source") or "additional_source"), str(source.get("body_type") or "text/plain"))
    for item in extra_indicators or []:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("value") or "")
        indicator_type = str(item.get("indicator_type") or "")
        location = {key: item[key] for key in ("source", "mime_part", "filename", "field") if key in item}
        normalized_hash = _normalize_hash(raw)
        if indicator_type == "hash" or indicator_type.startswith("hash_") or indicator_type in {"md5", "sha1", "sha256"}:
            if normalized_hash:
                algorithm, normalized = normalized_hash
                add(algorithm, raw, normalized, location, str(item.get("extraction_method") or "attachment_sha256"), "lowercase hexadecimal; exact digest bytes", indicator_category="hash", hash_algorithm=algorithm)

    # Parser URL evidence is the only URL source when supplied; each original
    # occurrence survives under its canonical URL identity.
    evidence_items = url_evidence
    if evidence_items is None and text:
        from services.url_extraction import extract_url_evidence
        evidence_items = extract_url_evidence([(0, text)], [])
    for evidence in evidence_items or []:
        if not isinstance(evidence, dict):
            continue
        normalized = url_deduplication_key(str(evidence.get("normalized_url") or evidence.get("original_url") or ""))
        if not normalized:
            continue
        originals = evidence.get("original_values") or [evidence.get("original_url") or normalized]
        comparisons = evidence.get("comparison_values") or [evidence.get("comparison_url") or normalized]
        locations = evidence.get("source_locations") or [{}]
        for index, location in enumerate(locations):
            location = dict(location)
            raw = location.get("original_url") or originals[min(index, len(originals) - 1)]
            comparison = location.get("comparison_url") or comparisons[min(index, len(comparisons) - 1)]
            add("url", str(raw), normalized, location, "mime_url_extractor", "shared HTTP(S) canonicalizer; preserve path/query/fragment", comparison_values=[str(comparison)])
        try:
            host = urlsplit(normalized).hostname
            if host:
                ip_host = normalize_ip(host)
                if ip_host:
                    for location in locations:
                        add_ip(host, {**dict(location), "context": "url_hostname"}, "url_hostname")
                else:
                    normalized_host = normalize_domain(host)
                    if normalized_host:
                        for location in locations:
                            add("domain", host, normalized_host, {**dict(location), "context": "url_hostname"}, "url_hostname", "lowercase IDNA ASCII hostname")
        except ValueError:
            pass

    return list(records.values())


def summarize_iocs(iocs: list[dict]) -> dict:
    summary = {
        "total": 0,
        "ip": 0,
        "ipv4": 0,
        "ipv6": 0,
        "ip:port": 0,
        "url": 0,
        "domain": 0,
        "email": 0,
        "hash": 0,
    }

    for item in iocs or []:
        ioc_type = item.get("ioc_type")

        summary["total"] += 1

        if ioc_type in summary:
            summary[ioc_type] += 1
        if ioc_type == "ip":
            family = "ipv4" if item.get("ip_version") == 4 else "ipv6" if item.get("ip_version") == 6 else None
            if family:
                summary[family] += 1
        elif ioc_type in {"md5", "sha1", "sha256"} or str(ioc_type).startswith("hash_"):
            summary["hash"] += 1

    return summary
