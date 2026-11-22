from email.message import EmailMessage

from services.email_parser import parse_email
from services.email_forensics.orchestrator import analyze_email_forensics
from services.threat_intelligence.ioc_normalizer import extract_iocs, summarize_iocs
from services.url_extraction import extract_url_evidence


def test_plain_text_urls_trim_sentence_punctuation_preserve_balanced_parentheses():
    evidence = extract_url_evidence(
        [(3, "Open https://example.test/path(a). Then https://example.test/x, now.")],
        [],
    )

    assert [item["normalized_url"] for item in evidence] == [
        "https://example.test/path(a)",
        "https://example.test/x",
    ]
    assert evidence[0]["source_locations"][0]["mime_part"] == 3
    assert evidence[0]["source_locations"][0]["body_type"] == "text/plain"
    assert evidence[0]["source_locations"][0]["source_fragment"] == "https://example.test/path(a)."


def test_html_href_entity_decoding_retains_raw_evidence_and_normalizes_idn():
    html = '<a href="https&#58;//Exämple.test/a&amp;b?x=1&amp;y=2">Open</a>'
    evidence = extract_url_evidence([], [(7, html)])

    assert len(evidence) == 1
    assert evidence[0]["original_url"] == "https&#58;//Exämple.test/a&amp;b?x=1&amp;y=2"
    assert evidence[0]["comparison_url"] == "https://Exämple.test/a&b?x=1&y=2"
    assert evidence[0]["normalized_url"] == "https://xn--exmple-cua.test/a&b?x=1&y=2"
    assert evidence[0]["source_locations"][0]["mime_part"] == 7
    assert evidence[0]["source_locations"][0]["body_type"] == "text/html"
    assert "href=" in evidence[0]["source_locations"][0]["source_fragment"]


def test_duplicate_plain_and_html_href_share_canonical_count_and_sources():
    evidence = extract_url_evidence(
        [(0, "Read https://example.test/Offer.")],
        [(1, '<a href="https://example.test/Offer">Offer</a>')],
    )

    assert len(evidence) == 1
    assert len(evidence[0]["source_locations"]) == 2
    assert {source["body_type"] for source in evidence[0]["source_locations"]} == {
        "text/plain", "text/html"
    }
    iocs = extract_iocs("https://ignored.example/inside-body", url_evidence=evidence)
    assert summarize_iocs(iocs)["url"] == 1
    url_ioc = next(item for item in iocs if item["ioc_type"] == "url")
    assert url_ioc["original_values"] == ["https://example.test/Offer"]
    assert len(url_ioc["source_locations"]) == 2


def test_deduplicated_host_variants_keep_each_original_url_form():
    evidence = extract_url_evidence(
        [(0, "https://Example.test:443/Path")],
        [(1, '<a href="https://example.test/Path">same</a>')],
    )

    assert len(evidence) == 1
    assert evidence[0]["original_values"] == [
        "https://Example.test:443/Path", "https://example.test/Path"
    ]
    assert len(evidence[0]["source_locations"]) == 2


def test_only_http_href_candidates_are_emitted_and_malformed_values_are_skipped():
    html = (
        '<a href="javascript:alert(1)">bad</a>'
        '<a href="ftp://files.example.test/a">ftp</a>'
        '<a href="https://example.test:99999/a">bad port</a>'
        '<a href="https:///missing-host">missing host</a>'
        '<script>https://script.example.test/not-an-anchor</script>'
        '<a href="https://good.example.test/a?x=1&amp;y=2">good</a>'
    )
    evidence = extract_url_evidence([], [(0, html)])

    assert [item["normalized_url"] for item in evidence] == [
        "https://good.example.test/a?x=1&y=2"
    ]


def test_parser_uses_shared_policy_and_mime_part_offsets_for_safe_fixture():
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Notice"
    message.set_content("Visit https://example.test/Offer.")
    message.add_alternative(
        '<html><a href="https://example.test/Offer">Offer</a>'
        '<a href="https://example.test/html-only">Details</a></html>',
        subtype="html",
    )

    parsed = parse_email(message.as_bytes(), "step12-fixture.eml")

    assert parsed["url_summary"]["unique_count"] == 2
    assert parsed["url_summary"]["occurrence_count"] == 3
    assert {item["normalized_url"] for item in parsed["url_evidence"]} == {
        "https://example.test/Offer", "https://example.test/html-only"
    }
    assert all(
        source["mime_part"] in {1, 2}
        for item in parsed["url_evidence"]
        for source in item["source_locations"]
    )


def test_primary_and_forensic_url_counts_are_identical_for_same_email():
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message.set_content("https://example.test/plain")
    message.add_alternative(
        '<a href="https://example.test/plain">same</a>'
        '<a href="https://example.test/html">html</a>',
        subtype="html",
    )
    raw = message.as_bytes()

    primary = parse_email(raw, "consistent-counts.eml")
    forensic = analyze_email_forensics(raw, verify_authentication=False)

    assert primary["url_summary"]["unique_count"] == 2
    assert forensic["url_analysis"]["url_count"] == 2
    assert {
        item["normalized_url"] for item in primary["url_evidence"]
    } == {
        item["normalized_url"] for item in forensic["url_evidence"]
    }


def test_percent_encoding_and_security_sensitive_components_are_not_removed():
    value = "https://Example.test:443/%2FPath?token=A%2FB#Frag"
    evidence = extract_url_evidence([(0, value)], [])

    assert len(evidence) == 1
    assert evidence[0]["normalized_url"] == "https://example.test/%2FPath?token=A%2FB#Frag"
    assert evidence[0]["original_url"] == value
