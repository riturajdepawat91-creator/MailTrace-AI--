import json
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

import database.database as database
import main


def test_analysis_dashboard_summary_and_json_report_share_one_result(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "step15-lineage.db")
    monkeypatch.setattr(
        main,
        "analyze_email_forensics",
        lambda *_args, **_kwargs: {
            "ip_intelligence": {"candidates": []},
            "authentication_analysis": {
                "validation": {
                    "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
                    "dkim": {"status": "NOT_PRESENT"},
                    "dmarc": {"status": "UNKNOWN"},
                }
            },
            "url_analysis": {"urls": []},
        },
    )
    monkeypatch.setattr(main, "get_threat_intelligence_source_status", lambda: {
        "coverage_status": "FRESH", "providers": {},
    })
    monkeypatch.setattr(main, "lookup_threat_intelligence_batch", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(main, "_build_evidence_governance", lambda **_kwargs: {
        "integrity_anchor": {
            "created": True,
            "verified": True,
            "independent_verification": False,
            "provider_status": {"status": "LOCAL_TEST_ONLY"},
            "receipt": {"provider": "local", "trust_level": "LOCAL_TEST_ONLY"},
        },
        "retention": None,
    })
    database.initialize_database()

    message = EmailMessage()
    message["From"] = "Ops <sender@example.com>"
    message["To"] = "analyst@example.net"
    message["Subject"] = "Routine notice"
    message["Message-ID"] = "<step15@example.com>"
    message.set_content("See https://example.com/offer once. https://example.com/offer")
    message.add_alternative(
        '<html><a href="https://example.com/offer">Offer</a>'
        '<a href="https://example.net/details">Details</a></html>',
        subtype="html",
    )

    with TestClient(main.app, client=("127.0.0.1", 54325)) as client:
        analyzed_response = client.post(
            "/api/analyze-email",
            files={"file": ("lineage.eml", message.as_bytes(), "message/rfc822")},
        )
        assert analyzed_response.status_code == 200, analyzed_response.text
        analyzed = analyzed_response.json()["analysis"]
        investigation_id = analyzed_response.json()["investigation_id"]

        detail_response = client.get(f"/api/investigations/{investigation_id}")
        dashboard_response = client.get("/api/investigations")

    assert detail_response.status_code == dashboard_response.status_code == 200
    detail_payload = detail_response.json()["investigation"]
    dashboard_rows = dashboard_response.json()["investigations"]
    dashboard_row = next(row for row in dashboard_rows if row["investigation_id"] == investigation_id)
    report = detail_payload["analysis"]

    # API analysis response and report detail are the same persisted canonical object.
    assert report == analyzed
    assert detail_payload["analysis_document_status"] == "PASS"

    # Dashboard/list scalar fields remain projections of that canonical object.
    assert dashboard_row["threat_score"] == report["threat_analysis"]["score"]
    assert dashboard_row["threat_verdict"] == report["threat_analysis"]["verdict"]
    assert dashboard_row["threat_confidence"] == report["threat_analysis"]["confidence"]
    assert dashboard_row["sender"] == report["basic_information"]["from"]

    # URL occurrences are intentionally distinct from unique URL indicators.
    assert report["url_summary"]["occurrence_count"] == 4
    assert report["url_summary"]["unique_count"] == 2
    assert report["threat_intelligence"]["ioc_summary"]["url"] == 2
    assert report["url_summary"]["counts_consistent"] is True
    assert len(report["url_evidence"]) == report["url_summary"]["unique_count"]
    assert sum(len(item["source_locations"]) for item in report["url_evidence"]) == report["url_summary"]["occurrence_count"]

    # Explicit states and trust scope survive JSON persistence without being
    # upgraded into an external immutability claim.
    assert report["result_statuses"]["threat_intelligence"]["outcome"] == "ZERO_MATCHES"
    assert report["evidence_governance"]["integrity_anchor"]["independent_verification"] is False
    assert report["evidence_governance"]["integrity_anchor"]["receipt"]["trust_level"] == "LOCAL_TEST_ONLY"
    assert json.loads(json.dumps(report, ensure_ascii=False)) == report


def test_corrupt_saved_report_is_explicit_error_not_empty_success(monkeypatch):
    from routes import investigations as route

    monkeypatch.setattr(route, "get_investigation", lambda *_args, **_kwargs: {
        "investigation_id": "INV-CORRUPT",
        "analysis_json": "{truncated",
        "threat_score": 0,
        "threat_verdict": "LOW RISK",
        "threat_confidence": "UNKNOWN",
    })
    monkeypatch.setattr(main, "get_investigation", lambda *_args, **_kwargs: {
        "investigation_id": "INV-CORRUPT", "analysis_json": "{truncated",
    })
    with TestClient(main.app, client=("127.0.0.1", 54326)) as client:
        response = client.get("/api/investigations/INV-CORRUPT")
        map_response = client.get("/api/reports/map-view/INV-CORRUPT")
    assert response.status_code == 200
    investigation = response.json()["investigation"]
    assert investigation["analysis_document_status"] == "ERROR"
    assert investigation["analysis"]["threat_analysis"]["score"] is None
    assert investigation["analysis"]["result_statuses"]["report_document"]["status"] == "ERROR"
    assert map_response.status_code == 200
    assert map_response.json()["status"] == "ERROR"
    assert map_response.json()["node_count"] == 0


def test_frontend_result_model_reads_canonical_analysis_collections():
    script = (Path(__file__).resolve().parents[2] / "frontend" / "script.js").read_text(encoding="utf-8")
    assert "analysis.url_summary?.unique_count" in script
    assert "analysis.threat_intelligence" in script
    assert "analysis.result_statuses" in script
    assert "canonicalAuthenticationStates" in script
    assert "Message header:" in script
    assert "analysis.received_chain" in script
    assert "threat.score" in script and "threat.verdict" in script and "threat.confidence" in script


def test_dashboard_summary_does_not_publish_stale_score_for_corrupt_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "corrupt-summary.db")
    database.initialize_database()
    database.save_investigation(
        investigation_id="INV-BAD-DOC",
        filename="broken.eml",
        subject="Broken stored document",
        sender="sender@example.com",
        recipient="analyst@example.net",
        threat_score=0,
        threat_verdict="LOW RISK",
        threat_confidence="UNKNOWN",
        analysis_json="{truncated",
        tenant_id="step15-test",
    )
    row = database.get_all_investigation_summaries("step15-test")[0]
    assert row["analysis_document_status"] == "ERROR"
    assert row["threat_score"] is None
    assert row["threat_verdict"] == "REPORT DATA UNAVAILABLE"
    assert row["threat_confidence"] == "UNKNOWN"
