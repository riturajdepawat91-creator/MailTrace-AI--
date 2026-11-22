from services.result_states import build_analysis_statuses, state_from_lookup
from services import ip_intelligence


def test_lookup_outcomes_distinguish_zero_matches_error_and_not_run():
    assert state_from_lookup(attempted=True, success=True, matches=0) == "PASS"
    assert state_from_lookup(attempted=True, success=True, matches=2) == "FAIL"
    assert state_from_lookup(attempted=True, success=False) == "ERROR"
    assert state_from_lookup(attempted=False, success=None) == "NOT_RUN"
    assert state_from_lookup(attempted=True, success=None) == "UNKNOWN"
    assert state_from_lookup(attempted=True, success=None, applicable=False) == "NOT_APPLICABLE"


def test_provider_timeout_and_malformed_response_are_bounded_errors(monkeypatch):
    def timeout(*args, **kwargs):
        raise TimeoutError("secret-token C:/private/path")

    monkeypatch.setattr(ip_intelligence.urllib.request, "urlopen", timeout)
    geo = ip_intelligence.get_ip_geolocation("8.8.8.8")
    network = ip_intelligence.get_network_intelligence("8.8.8.8")
    assert geo["status"] == network["status"] == "ERROR"
    assert "secret-token" not in geo["error"]
    assert "C:/private/path" not in network["error"]

    monkeypatch.setattr(ip_intelligence.urllib.request, "urlopen", lambda *a, **k: _Response("[]"))
    assert ip_intelligence.get_ip_geolocation("8.8.8.8")["status"] == "ERROR"
    assert ip_intelligence.get_network_intelligence("8.8.8.8")["status"] == "ERROR"


class _Response:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.body.encode()


def test_private_ip_is_not_applicable_and_skips_external_providers(monkeypatch):
    def should_not_run(*args, **kwargs): raise AssertionError("private IP enrichment must not call providers")
    monkeypatch.setattr(ip_intelligence, "get_ip_geolocation", should_not_run)
    monkeypatch.setattr(ip_intelligence, "get_network_intelligence", should_not_run)
    result = ip_intelligence.analyze_ip("10.1.2.3")
    assert result["status"] == "NOT_APPLICABLE"
    assert result["risk_score"] == 0
    assert result["geolocation_status"]["status"] == "NOT_APPLICABLE"
    assert result["network_intelligence_status"]["status"] == "NOT_APPLICABLE"


def test_analysis_statuses_keep_empty_unknown_and_detector_skipped_distinct():
    result = build_analysis_statuses({
        "parsing": {"status": "PARTIAL"},
        "email_ai": {"status": "MODEL_NOT_READY"},
        "threat_intelligence": {"status": "no_iocs", "coverage_status": "FRESH", "iocs": [], "matches": {}},
        "intelligence_fusion": {"status": "ANALYZED", "unified_risk_score": 0},
        "threat_analysis": {"score": 0, "score_source": "intelligence_fusion", "confidence_basis": "unavailable"},
    })
    assert result["parsing"]["status"] == "UNKNOWN"
    assert result["model_inference"]["status"] == "NOT_RUN"
    assert result["threat_intelligence"]["status"] == "NOT_RUN"
    assert result["risk_fusion"]["status"] == "PASS"
    assert result["score"]["confidence_status"] == "UNKNOWN"


def test_empty_success_is_not_ioc_failure_or_malicious():
    statuses = build_analysis_statuses({
        "parsing": {"status": "COMPLETE"},
        "email_ai": {"status": "MODEL_NOT_READY"},
        "threat_intelligence": {"status": "no_matches", "coverage_status": "FRESH", "iocs": [{"ioc": "example.org"}], "matches": {}},
        "intelligence_fusion": {"status": "ERROR"},
        "threat_analysis": {"score": 0, "score_source": "parser_rules_plus_ioc_fallback"},
    })
    assert statuses["threat_intelligence"]["status"] == "PASS"
    assert statuses["risk_fusion"]["status"] == "ERROR"
    assert statuses["score"]["status"] == "UNKNOWN"


def test_missing_credentials_and_auth_parser_failure_are_not_pass():
    statuses = build_analysis_statuses({
        "parsing": {"status": "ERROR"},
        "email_ai": {"status": "SKIPPED"},
        "threat_intelligence": {"status": "not_configured", "coverage_status": "UNKNOWN", "iocs": ["x"]},
        "intelligence_fusion": {"status": "ANALYZED"},
        "email_forensics": {"authentication_analysis": {"validation": {
            "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
            "dkim": {"status": "TEMPORARY_ERROR_OR_INVALID_KEY"},
            "dmarc": {"status": "DNS_LOOKUP_ERROR"},
        }}},
        "threat_analysis": {},
    })
    assert statuses["parsing"]["status"] == "ERROR"
    assert statuses["threat_intelligence"]["status"] == "NOT_RUN"
    assert statuses["authentication"]["spf"]["status"] == "NOT_RUN"
    assert statuses["authentication"]["dkim"]["status"] == "ERROR"
    assert statuses["authentication"]["dmarc"]["status"] == "ERROR"
