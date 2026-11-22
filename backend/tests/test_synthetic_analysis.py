from __future__ import annotations

from email.message import EmailMessage
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from services.synthetic_analysis.api import analyze_synthetic_fixture
from services.synthetic_analysis.engine import (
    MAX_SYNTHETIC_BODY_CHARS,
    MAX_SYNTHETIC_MESSAGE_BYTES,
    SyntheticInputError,
    analyze_synthetic_email,
)
from services.synthetic_analysis.scoring import PrototypeScoringPolicy, score_findings
from database import database
from services.synthetic_analysis import api


@pytest.fixture
def isolated_report_database(tmp_path):
    database.DATABASE_PATH = tmp_path / "synthetic-api.sqlite3"
    database.initialize_database()
    database.initialize_email_alerts()
    database.initialize_case_audit()
    from services.synthetic_analysis.store import initialize_synthetic_analysis_reports
    initialize_synthetic_analysis_reports()


def eml(body: str, *, sender: str = "Example Sender <alerts@example.com>",
        subject: str = "Synthetic fixture", content_type: str = "text/plain",
        authentication: str | None = None) -> bytes:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "recipient@example.net"
    message["Subject"] = subject
    if authentication:
        message["Authentication-Results"] = authentication
    message.set_content(body, subtype="html" if content_type == "text/html" else "plain")
    return message.as_bytes()


def all_mock_auth(state: str = "PASS") -> dict[str, str]:
    return {"spf": state, "dkim": state, "dmarc": state, "dmarc_domain": "example.com"}


class FakeUpload:
    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self.data = data
        self.closed = False

    async def read(self, size: int) -> bytes:
        data, self.data = self.data[:size], self.data[size:]
        return data

    async def close(self) -> None:
        self.closed = True


def run_immediate_coroutine(coroutine):
    """Drive this handler's fake-upload-only coroutine without Windows loop startup."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("fake upload coroutine unexpectedly suspended")


def test_attachment_free_synthetic_message_is_processed_without_content_in_report():
    raw = eml("Hello, this is a routine synthetic notice.")
    report = analyze_synthetic_email(raw)
    serialized = str(report)
    assert report["synthetic_test_analysis"] is True
    assert report["processing_status"] == "COMPLETED"
    assert report["analysis_status"] == "ANALYSIS_INCOMPLETE"
    assert report["risk"]["verdict"] == "INDETERMINATE / ANALYSIS_INCOMPLETE"
    assert report["authentication"]["checks"]["spf"]["state"] == "UNAVAILABLE"
    assert report["sender_analysis"]["sender_domain"] == "example.com"
    assert "Hello, this is" not in serialized
    assert "Synthetic fixture" not in serialized
    assert "alerts@example.com" not in serialized


def test_safe_requires_all_mandatory_checks_and_no_findings():
    report = analyze_synthetic_email(
        eml("Routine synthetic notice."), mock_authentication=all_mock_auth()
    )
    assert report["risk"]["verdict"] == "SAFE"
    assert report["analysis_status"] == "COMPLETE"
    assert all(item["source"] == "MOCK_ONLY_NOT_LIVE_VERIFICATION" for item in report["authentication"]["checks"].values())
    assert report["authentication"]["independent_verification"] is False


def test_reported_authentication_results_are_not_independent_passes():
    report = analyze_synthetic_email(eml(
        "Routine.", authentication="mx.example; spf=pass; dkim=pass; dmarc=pass"
    ))
    for check in report["authentication"]["checks"].values():
        assert check["state"] == "UNAVAILABLE"
        assert check["reported_claim"] == "PASS"
    assert report["authentication"]["reported_header_trusted"] is False
    assert report["risk"]["verdict"] == "INDETERMINATE / ANALYSIS_INCOMPLETE"


@pytest.mark.parametrize("state", ["FAIL", "NONE", "UNAVAILABLE", "INVALID"])
def test_nonpassing_mocked_auth_state_cannot_produce_safe(state):
    report = analyze_synthetic_email(
        eml("Routine."), mock_authentication={"spf": state, "dkim": "PASS", "dmarc": "PASS"}
    )
    assert report["risk"]["verdict"] != "SAFE"


def test_unknown_mock_auth_value_is_invalid():
    report = analyze_synthetic_email(
        eml("Routine."), mock_authentication={"spf": "BROKEN", "dkim": "PASS", "dmarc": "PASS"}
    )
    assert report["authentication"]["checks"]["spf"]["state"] == "INVALID"


def test_credential_and_urgency_findings_are_explainable_without_snippets():
    report = analyze_synthetic_email(eml("URGENT: verify your account and enter your password immediately."))
    assert {item["id"] for item in report["findings"]} >= {
        "MT-SYN-CREDENTIAL_REQUEST_LANGUAGE", "MT-SYN-URGENCY_LANGUAGE"
    }
    assert all(item["evidence_ref"] and item["method"] for item in report["findings"])
    assert "enter your password" not in str(report)
    assert report["risk"]["score_is_probability"] is False


def test_sender_display_name_brand_mismatch_is_reported_as_heuristic():
    report = analyze_synthetic_email(eml(
        "Please review this synthetic notice.", sender="PayPal Security <notice@attacker.example>"
    ))
    finding = next(item for item in report["findings"] if item["id"] == "MT-SYN-SENDER_DISPLAY_DOMAIN_MISMATCH")
    assert finding["confidence"] == "LIMITED_HEURISTIC"
    assert "not proof" in finding["explanation"]


def test_plain_text_url_and_ioc_are_normalized_and_sensitive_components_redacted():
    raw = eml("Visit https://user:topsecret@1.1.1.1/login?token=private123 now.")
    report = analyze_synthetic_email(raw)
    rendered = str(report)
    assert report["iocs"]
    assert all("topsecret" not in item["value"] and "private123" not in item["value"] for item in report["iocs"])
    assert all("/login" not in item["value"] for item in report["iocs"] if item["type"] == "url")
    assert "topsecret" not in rendered and "private123" not in rendered
    assert any(item["id"] == "MT-SYN-URL-USERINFO" for item in report["findings"])
    assert any(item["id"] == "MT-SYN-IP-LITERAL-URL" for item in report["findings"])
    assert any(item.get("scope") == "public" for item in report["iocs"] if item["type"] == "ip")


def test_iocs_deduplicate_repeated_indicators():
    report = analyze_synthetic_email(eml("https://example.org/a and https://example.org/a and 8.8.8.8 8.8.8.8"))
    keys = [(item["type"], item["value"]) for item in report["iocs"]]
    assert len(keys) == len(set(keys))
    repeated = next(item for item in report["iocs"] if item["value"] == "https://example.org/[redacted]")
    assert len(repeated["source_locations"]) >= 2
    assert all("source_fragment" not in location and "offset" in location for location in repeated["source_locations"])


def test_html_link_destination_mismatch_is_detected_without_returning_raw_html():
    report = analyze_synthetic_email(eml(
        '<a href="https://evil.example/login?token=hidden">https://paypal.com/login</a>',
        content_type="text/html",
    ))
    assert any(item["id"] == "MT-SYN-DECEPTIVE_LINK" for item in report["findings"])
    assert "token=hidden" not in str(report)
    assert "href=\"https://evil.example" not in str(report)


def test_absent_sender_keeps_sender_check_unavailable():
    message = EmailMessage()
    message["To"] = "x@example.net"
    message.set_content("ordinary")
    report = analyze_synthetic_email(message.as_bytes(), mock_authentication=all_mock_auth())
    assert report["check_states"]["sender_analysis"] == "UNAVAILABLE"
    assert report["risk"]["verdict"] != "SAFE"


def test_multipart_and_attachment_input_are_rejected():
    message = EmailMessage()
    message["From"] = "a@example.com"
    message.set_content("body")
    message.add_attachment(b"synthetic attachment bytes", maintype="application", subtype="octet-stream", filename="sample.bin")
    with pytest.raises(SyntheticInputError, match="Multipart messages"):
        analyze_synthetic_email(message.as_bytes())


def test_single_part_attachment_disposition_is_rejected():
    raw = b"From: a@example.com\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=x.txt\r\n\r\nnot accepted"
    with pytest.raises(SyntheticInputError, match="Attachment-bearing"):
        analyze_synthetic_email(raw)


def test_oversized_message_and_body_are_rejected():
    with pytest.raises(SyntheticInputError, match="1 MiB"):
        analyze_synthetic_email(b"x" * (MAX_SYNTHETIC_MESSAGE_BYTES + 1))
    with pytest.raises(SyntheticInputError, match="body exceeds"):
        analyze_synthetic_email(eml("a" * (MAX_SYNTHETIC_BODY_CHARS + 1)))


def test_bad_input_type_empty_and_unsupported_content_type_are_rejected():
    with pytest.raises(SyntheticInputError):
        analyze_synthetic_email("not bytes")  # type: ignore[arg-type]
    with pytest.raises(SyntheticInputError, match="empty"):
        analyze_synthetic_email(b"")
    with pytest.raises(SyntheticInputError, match="Only single-part"):
        analyze_synthetic_email(b"From: x@example.com\r\nContent-Type: application/octet-stream\r\n\r\nx")


def test_malformed_body_encoding_is_rejected_content_free():
    raw = b"From: x@example.com\r\nContent-Type: text/plain; charset=does-not-exist\r\n\r\nhello"
    with pytest.raises(SyntheticInputError, match="encoding"):
        analyze_synthetic_email(raw)


def test_resource_limits_are_enforced_by_reused_parser():
    from services.email_parsing import EmailParseLimitError, MAX_MIME_DEPTH

    raw = b"From: x@example.com\r\n" + b"X-Test: x\r\n" * 1001 + b"\r\nhello"
    with pytest.raises(SyntheticInputError, match="parser safety limits"):
        analyze_synthetic_email(raw)
    assert MAX_MIME_DEPTH == 20
    assert EmailParseLimitError


def test_excessive_mime_depth_and_part_count_are_rejected():
    from services.email_parsing import MAX_MIME_DEPTH, MAX_MIME_PARTS

    nested = b"Content-Type: text/plain\r\n\r\nbody"
    for index in range(MAX_MIME_DEPTH + 1):
        boundary = f"layer{index}".encode()
        nested = (
            b"Content-Type: multipart/mixed; boundary=\"" + boundary + b"\"\r\n\r\n--"
            + boundary + b"\r\n" + nested + b"\r\n--" + boundary + b"--\r\n"
        )
    with pytest.raises(SyntheticInputError, match="parser safety limits"):
        analyze_synthetic_email(nested)

    boundary = b"many"
    parts = [b"--" + boundary + b"\r\n\r\npart\r\n" for _ in range(MAX_MIME_PARTS + 1)]
    raw = b"Content-Type: multipart/mixed; boundary=many\r\n\r\n" + b"".join(parts) + b"--many--\r\n"
    with pytest.raises(SyntheticInputError, match="parser safety limits"):
        analyze_synthetic_email(raw)


def test_malformed_header_defects_never_produce_safe():
    raw = b"From: Sender <sender@example.com>\r\nMalformed Header Without Colon\r\nContent-Type: text/plain\r\n\r\nRoutine body\r\n"
    report = analyze_synthetic_email(raw, mock_authentication=all_mock_auth())
    assert report["parser_diagnostics"]["defect_count"] > 0
    assert report["check_states"]["parser"] == "UNAVAILABLE"
    assert report["risk"]["verdict"] != "SAFE"


def test_no_body_subject_or_private_url_is_logged(caplog):
    raw = eml("secret-body-text https://example.org/path?token=private-value", subject="secret-subject")
    analyze_synthetic_email(raw)
    rendered_logs = " ".join(record.getMessage() for record in caplog.records)
    assert "secret-body-text" not in rendered_logs
    assert "secret-subject" not in rendered_logs
    assert "private-value" not in rendered_logs


def test_analysis_does_not_write_files_or_call_network(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network or file side effect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    report = analyze_synthetic_email(eml("Check https://example.org/login"))
    assert report["synthetic_test_analysis"]


def test_report_has_no_raw_content_fields_or_persistence_claim():
    report = analyze_synthetic_email(eml("fixture-only body", subject="private subject"))
    serialized = str(report).lower()
    assert "fixture-only body" not in serialized
    assert "private subject" not in serialized
    assert "body_text" not in report
    assert "database" not in report


def test_prototype_scoring_policy_is_configurable_and_validated():
    policy = PrototypeScoringPolicy(
        version="unit-test-policy",
        finding_weights={"URGENCY_LANGUAGE": 2},
        thresholds={"SUSPICIOUS": 2, "HIGH": 5, "CRITICAL": 8},
    )
    result = score_findings(
        [{"id": "MT-SYN-URGENCY_LANGUAGE", "evidence_ref": "body.text.keyword_match"}],
        {"parser": "PASS"},
        policy=policy,
    )
    assert result["policy_version"] == "unit-test-policy"
    assert result["verdict"] == "SUSPICIOUS"
    with pytest.raises(ValueError, match="ordered"):
        PrototypeScoringPolicy(thresholds={"SUSPICIOUS": 50, "HIGH": 20, "CRITICAL": 80})


def test_api_accepts_eml_and_persists_only_sanitized_report(isolated_report_database, monkeypatch):
    monkeypatch.setattr(api, "verify_email_authentication", lambda raw: {
        "checks": {name: {"state": "UNAVAILABLE", "source": "MOCK"} for name in ("spf", "dkim", "dmarc")},
        "sender_domain_alignment": {"state": "UNAVAILABLE", "source": "MOCK"},
    })
    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(
        tenant_id="tenant-api", subject_id="analyst-api", roles={"analyst"}
    )))
    uploaded = FakeUpload("synthetic.eml", eml("safe fixture"))
    response = run_immediate_coroutine(analyze_synthetic_fixture(request, uploaded, "api-test-key"))
    assert response["success"] is True
    assert response["report"]["synthetic_test_analysis"] is True
    assert "safe fixture" not in str(response)
    assert response["persistence"]["status"] == "STORED"
    assert response["soc_delivery"]["status"] == "DELIVERED"


def test_api_rejects_non_eml_and_unauthorized_requests():
    authorized = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(
        tenant_id="tenant-api", subject_id="analyst-api", roles={"analyst"}
    )))
    uploaded = FakeUpload("sample.msg", b"not accepted")
    with pytest.raises(HTTPException) as unsupported:
        run_immediate_coroutine(analyze_synthetic_fixture(authorized, uploaded))
    assert unsupported.value.status_code == 415
    assert uploaded.closed
    unauthorized = SimpleNamespace(state=SimpleNamespace(principal=None))
    uploaded = FakeUpload("sample.eml", eml("test"))
    with pytest.raises(HTTPException) as denied:
        run_immediate_coroutine(analyze_synthetic_fixture(unauthorized, uploaded))
    assert denied.value.status_code == 401
    assert uploaded.closed


def test_api_rejects_oversized_upload_safely():
    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(
        tenant_id="tenant-api", subject_id="analyst-api", roles={"analyst"}
    )))
    uploaded = FakeUpload("oversized.eml", b"x" * (MAX_SYNTHETIC_MESSAGE_BYTES + 1))
    with pytest.raises(HTTPException) as rejected:
        run_immediate_coroutine(analyze_synthetic_fixture(request, uploaded))
    assert rejected.value.status_code == 422
    assert "xxxxxxxx" not in rejected.value.detail
    assert uploaded.closed
