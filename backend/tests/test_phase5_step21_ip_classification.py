import pytest

from services.ip_address_policy import classify_ip
from services.email_forensics.ip_extractor import extract_ip_candidates, extract_public_ips
from services.ip_intelligence_v2.engine import analyze_ip_v2
from services import ip_intelligence


@pytest.mark.parametrize(("raw", "kind"), [
    ("10.1.2.3", "PRIVATE"),
    ("172.16.0.1", "PRIVATE"),
    ("192.168.1.1", "PRIVATE"),
    ("127.0.0.1", "LOOPBACK"),
    ("169.254.10.2", "LINK_LOCAL"),
    ("224.0.0.1", "MULTICAST"),
    ("0.0.0.0", "UNSPECIFIED"),
    ("::", "UNSPECIFIED"),
    ("::1", "LOOPBACK"),
    ("fe80::1", "LINK_LOCAL"),
    ("ff02::1", "MULTICAST"),
    ("fc00::1", "PRIVATE"),
    ("192.0.2.10", "DOCUMENTATION"),
    ("198.51.100.8", "DOCUMENTATION"),
    ("203.0.113.9", "DOCUMENTATION"),
    ("2001:db8::1", "DOCUMENTATION"),
    ("100.64.0.1", "SPECIAL_USE"),
    ("198.18.0.1", "SPECIAL_USE"),
    ("192.0.0.9", "SPECIAL_USE"),
    ("240.0.0.1", "RESERVED"),
    ("8.8.8.8", "PUBLIC"),
    ("2606:4700:4700::1111", "PUBLIC"),
])
def test_ip_classification_policy(raw, kind):
    result = classify_ip(raw)
    assert result["valid"] is True
    assert result["classification"] == kind
    assert result["enrichment_status"] == ("ELIGIBLE" if kind == "PUBLIC" else "NOT_PUBLIC")
    assert (result["provider_ip"] is not None) is (kind == "PUBLIC")


@pytest.mark.parametrize("raw", ["", "999.1.1.1", "1.2.3", "2001:::1", "not-an-ip", "1.2.3.4/24"])
def test_malformed_ip_is_rejected(raw):
    result = classify_ip(raw)
    assert result["valid"] is False
    assert result["classification"] == "INVALID"
    assert result["enrichment_status"] == "INVALID_IP"
    assert result["provider_ip"] is None


def test_ipv4_mapped_ipv6_uses_embedded_ipv4_policy():
    private = classify_ip("::ffff:192.168.1.5")
    assert private["valid"] is True
    assert private["is_ipv4_mapped"] is True
    assert private["normalized_ip"] == "::ffff:c0a8:105"
    assert private["classification"] == "PRIVATE"
    assert private["provider_ip"] is None
    public = classify_ip("::ffff:8.8.8.8")
    assert public["classification"] == "PUBLIC"
    assert public["provider_ip"] == "8.8.8.8"


def test_v2_nonpublic_addresses_return_not_applicable_and_skip_all_providers(monkeypatch):
    import services.ip_intelligence_v2.engine as engine
    def forbidden(*args, **kwargs):
        raise AssertionError("provider must not be called for non-public IP")
    for name in ("reverse_dns", "get_geolocation", "query_ipapi_network", "get_reputation"):
        monkeypatch.setattr(engine, name, forbidden)
    for raw in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "100.64.0.1", "::1", "fe80::1", "ff02::1", "::ffff:10.0.0.1"):
        result = analyze_ip_v2(raw)
        assert result["status"] == "NOT_APPLICABLE"
        assert result["enrichment_status"] == "NOT_PUBLIC"
        assert result["provider_ip"] is None
        assert all(item["status"] == "NOT_APPLICABLE" for item in result["provider_status"])


def test_legacy_nonpublic_addresses_skip_reverse_dns_geo_and_network(monkeypatch):
    calls = []
    monkeypatch.setattr(ip_intelligence, "get_ip_geolocation", lambda *a: calls.append("geo"))
    monkeypatch.setattr(ip_intelligence, "get_network_intelligence", lambda *a: calls.append("network"))
    monkeypatch.setattr(ip_intelligence.socket, "gethostbyaddr", lambda *a: calls.append("dns"))
    for raw in ("10.20.30.40", "100.64.0.1", "224.0.0.1", "192.0.2.1", "::1", "::ffff:10.0.0.1"):
        result = ip_intelligence.analyze_ip(raw)
        assert result["status"] == "NOT_APPLICABLE"
        assert result["enrichment_status"] == "NOT_PUBLIC"
        assert result["provider_ip"] is None
    assert calls == []


def test_provider_entry_points_reject_nonpublic_before_network_io(monkeypatch):
    from services.ip_intelligence_v2.providers import geolocation, network, reputation, dns
    def forbidden(*args, **kwargs):
        raise AssertionError("network I/O must not occur for non-public IP")
    monkeypatch.setattr(geolocation, "_request_json", forbidden)
    monkeypatch.setattr(network.urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(reputation.urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(dns.socket, "gethostbyaddr", forbidden)
    assert "NOT_APPLICABLE" in geolocation.query_ipapi("10.0.0.1").error
    assert "NOT_APPLICABLE" in geolocation.query_ipinfo("127.0.0.1").error
    assert "NOT_APPLICABLE" in geolocation.get_geolocation("fe80::1")[0].error
    assert "NOT_APPLICABLE" in network.query_ipapi_network("224.0.0.1").error
    assert "NOT_APPLICABLE" in reputation.query_abuseipdb("192.0.2.1").error
    assert "NOT_APPLICABLE" in reputation.get_reputation("::1")[0].error
    assert "NOT_APPLICABLE" in dns.reverse_dns("169.254.1.1").error


def test_received_header_candidates_preserve_raw_and_normalized_and_only_public_is_eligible():
    headers = ["from mail.example ([10.0.0.1]) by mx.example; 8.8.8.8", "from [::ffff:192.168.1.5] by mx.example", "from [::ffff:8.8.8.8] by mx.example"]
    candidates = extract_ip_candidates(headers)
    by_raw = {item["raw_ip"]: item for item in candidates}
    assert by_raw["10.0.0.1"]["enrichment_status"] == "NOT_PUBLIC"
    assert by_raw["8.8.8.8"]["provider_ip"] == "8.8.8.8"
    assert by_raw["::ffff:192.168.1.5"]["provider_ip"] is None
    assert by_raw["::ffff:8.8.8.8"]["provider_ip"] == "8.8.8.8"
    assert extract_public_ips(headers) == ["8.8.8.8"]


def test_public_ipv4_mapped_ipv6_is_sent_as_canonical_ipv4(monkeypatch):
    import services.ip_intelligence_v2.engine as engine
    from services.ip_intelligence_v2.models import ProviderResult
    calls = []
    def result(provider, ip):
        calls.append((provider, ip))
        return ProviderResult(provider=provider, success=False, error="stubbed")
    monkeypatch.setattr(engine, "reverse_dns", lambda ip: result("dns", ip))
    monkeypatch.setattr(engine, "get_geolocation", lambda ip: [result("geo", ip)])
    monkeypatch.setattr(engine, "query_ipapi_network", lambda ip: result("network", ip))
    monkeypatch.setattr(engine, "get_reputation", lambda ip: [result("reputation", ip)])
    output = analyze_ip_v2("::ffff:8.8.8.8")
    assert output["raw_input"] == "::ffff:8.8.8.8"
    assert output["normalized_ip"] == "::ffff:808:808"
    assert output["provider_ip"] == "8.8.8.8"
    assert output["is_ipv4_mapped"] is True
    assert {ip for _, ip in calls} == {"8.8.8.8"}


def test_legacy_provider_functions_guard_direct_nonpublic_calls(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("provider network I/O must not occur")
    monkeypatch.setattr(ip_intelligence.urllib.request, "urlopen", forbidden)
    assert ip_intelligence.get_ip_geolocation("192.168.1.1")["status"] == "NOT_APPLICABLE"
    assert ip_intelligence.get_network_intelligence("100.64.0.1")["status"] == "NOT_APPLICABLE"


def test_nonpublic_relay_candidate_never_scores_as_public_origin():
    from services.email_forensics.origin_scoring import score_origin_candidates
    chain = [{
        "hop": 1,
        "ips": ["100.64.0.1", "192.0.2.1", "8.8.8.8"],
        "ip_classifications": ["SPECIAL_USE", "DOCUMENTATION", "PUBLIC"],
    }]
    candidates = {item["ip"]: item for item in score_origin_candidates(chain)}
    assert candidates["100.64.0.1"]["score"] == 0
    assert candidates["192.0.2.1"]["score"] == 0
    assert candidates["8.8.8.8"]["score"] > 0
    assert "does not prove sender origin" in " ".join(candidates["8.8.8.8"]["reasons"])


def test_invalid_ip_results_are_explicit_and_never_provider_eligible():
    from services.ip_intelligence_v2.engine import analyze_ip_v2
    result = analyze_ip_v2("999.1.1.1")
    assert result["valid"] is False
    assert result["status"] == "ERROR"
    assert result["enrichment_status"] == "INVALID_IP"
    assert result["provider_ip"] is None


def test_legacy_received_chain_uses_validated_ipv4_and_ipv6_candidates():
    from email.message import EmailMessage
    from services.email_parser import extract_received_chain
    message = EmailMessage()
    message["Received"] = "from [10.0.0.1] by mx.example"
    message["Received"] = "from [2606:4700:4700::1111] by mx.example"
    chain = extract_received_chain(message)
    flattened = [item for hop in chain for item in hop["ip_candidates"]]
    assert {item["normalized_ip"] for item in flattened} == {"10.0.0.1", "2606:4700:4700::1111"}
    assert {item["classification"] for item in flattened} == {"PRIVATE", "PUBLIC"}


def test_ioc_normalizer_uses_shared_scope_for_mapped_ipv6_without_inner_duplicate():
    from services.threat_intelligence.ioc_normalizer import extract_iocs
    items = [item for item in extract_iocs("::ffff:10.0.0.1 and ::ffff:8.8.8.8") if item.get("ioc_type") == "ip"]
    mapped = {item["ioc"]: item["ip_scope"] for item in items}
    assert mapped["::ffff:a00:1"] == "private"
    assert mapped["::ffff:808:808"] == "public"
    assert "10.0.0.1" not in mapped
    assert "8.8.8.8" not in mapped
