from services.threat_intelligence.ioc_normalizer import extract_iocs, summarize_iocs


def test_typed_indicators_preserve_context_and_normalize_email_domains():
    iocs = extract_iocs(
        "Contact Alice@Exämple.com or Alice@EXÄMPLE.COM; see https://EXÄMPLE.com/a.",
        url_evidence=[{
            "original_url": "https://EXÄMPLE.com/a.",
            "comparison_url": "https://EXÄMPLE.com/a",
            "normalized_url": "https://xn--exmple-cua.com/a",
            "source_locations": [{"mime_part": 2, "body_type": "text/html", "offset": 4}],
        }],
    )

    emails = [item for item in iocs if item["ioc_type"] == "email"]
    assert {item["ioc"] for item in emails} == {"Alice@xn--exmple-cua.com"}
    assert emails[0]["occurrence_count"] == 2
    assert emails[0]["original_values"] == ["Alice@Exämple.com", "Alice@EXÄMPLE.COM"]

    urls = [item for item in iocs if item["ioc_type"] == "url"]
    assert len(urls) == 1
    assert urls[0]["ioc"] == "https://xn--exmple-cua.com/a"


def test_ip_versions_scopes_and_ip_port_are_distinguished_without_lookup():
    iocs = extract_iocs(
        "Private 192.168.1.10 at 192.168.1.10:443; reserved 2001:db8::1 and [2001:db8::1]:8443; malformed 999.999.1.1"
    )
    ips = [item for item in iocs if item["ioc_type"] == "ip"]
    ports = [item for item in iocs if item["ioc_type"] == "ip:port"]

    assert {item["ioc"] for item in ips} == {"192.168.1.10", "2001:db8::1"}
    assert {item["ioc"] for item in ports} == {"192.168.1.10:443", "[2001:db8::1]:8443"}
    assert next(item for item in ips if item["ip_version"] == 4)["ip_scope"] == "private"
    assert next(item for item in ips if item["ip_version"] == 6)["ip_scope"] == "documentation"
    assert all(item["source_locations"] and item["normalization_decision"] for item in ips + ports)


def test_hash_case_variants_and_attachment_sha256_deduplicate_with_sources():
    upper = "A" * 64
    lower = upper.lower()
    iocs = extract_iocs(
        f"SHA256 {upper} repeated {lower}",
        extra_indicators=[{
            "indicator_type": "hash_sha256",
            "value": lower,
            "source": "attachment",
            "mime_part": 4,
            "filename": "proof.bin",
            "field": "sha256",
        }],
    )
    hashes = [item for item in iocs if item["indicator_type"] == "hash"]

    assert len(hashes) == 1
    assert hashes[0]["ioc_type"] == "sha256"
    assert hashes[0]["ioc"] == lower
    assert hashes[0]["occurrence_count"] == 3
    assert {item["source"] for item in hashes[0]["source_locations"]} == {"body.text", "attachment"}
    assert summarize_iocs(iocs)["hash"] == 1


def test_distinct_url_paths_ports_fragments_and_domain_contexts_stay_distinct():
    evidence = [
        {
            "original_url": "https://Example.com:8443/Login?token=A#one",
            "comparison_url": "https://Example.com:8443/Login?token=A#one",
            "normalized_url": "https://example.com:8443/Login?token=A#one",
            "source_locations": [{"source": "html", "offset": 10}],
        },
        {
            "original_url": "https://example.com:8443/login?token=A#two",
            "comparison_url": "https://example.com:8443/login?token=A#two",
            "normalized_url": "https://example.com:8443/login?token=A#two",
            "source_locations": [{"source": "text", "offset": 40}],
        },
    ]
    iocs = extract_iocs("example.com used by person@example.com", url_evidence=evidence)

    urls = [item for item in iocs if item["ioc_type"] == "url"]
    domains = [item for item in iocs if item["ioc_type"] == "domain" and item["ioc"] == "example.com"]
    assert len(urls) == 2
    assert len(domains) == 1
    assert {location.get("context") for location in domains[0]["source_locations"]} >= {None, "email_domain"}


def test_malformed_email_domain_hash_and_ip_candidates_are_rejected():
    iocs = extract_iocs(
        "bad..name@example..com 999.999.0.1 " + "g" * 64 + " https://:invalid/a"
    )
    assert not [item for item in iocs if item["ioc_type"] == "email"]
    assert not [item for item in iocs if item["ioc_type"] == "ip"]
    assert not [item for item in iocs if item["indicator_type"] == "hash"]


def test_private_ip_is_classified_locally_and_skips_public_geo_reputation(monkeypatch):
    import services.ip_intelligence as ip_intelligence

    external_calls = []
    monkeypatch.setattr(ip_intelligence, "get_ip_geolocation", lambda *_: external_calls.append("geo"))
    monkeypatch.setattr(ip_intelligence, "get_network_intelligence", lambda *_: external_calls.append("reputation"))
    monkeypatch.setattr(ip_intelligence.socket, "gethostbyaddr", lambda *_: external_calls.append("reverse_dns"))

    result = ip_intelligence.analyze_ip("10.20.30.40")
    ioc = next(item for item in extract_iocs("10.20.30.40") if item["ioc_type"] == "ip")
    shared_result = ip_intelligence.analyze_ip("100.64.0.1")
    shared_ioc = next(item for item in extract_iocs("100.64.0.1") if item["ioc_type"] == "ip")

    assert result["is_private"] is True
    assert result["country"] is None
    assert ioc["ip_scope"] == "private"
    assert shared_result["type"] == "SPECIAL_USE"
    assert shared_ioc["ip_scope"] == "non_public"
    assert external_calls == []
