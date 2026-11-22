from __future__ import annotations

from email.message import EmailMessage
from types import SimpleNamespace
import base64
import hashlib
import os

import pytest
from fastapi import HTTPException

from database import database
from services.synthetic_analysis import api, verification
from services.synthetic_analysis.engine import analyze_synthetic_email
from services.synthetic_analysis.store import (
    create_or_get_report, get_report, initialize_synthetic_analysis_reports,
    make_idempotency_hash,
)


class FakeRecord:
    def __init__(self, value: str):
        self.strings = [value.encode()]


class FakeResolver:
    timeout = 1.0
    lifetime = 2.5

    def __init__(self, records=None, failure=None):
        self.records = records or {}
        self.failure = failure
        self.queries = []

    def resolve(self, name, kind, lifetime):
        self.queries.append((name, kind, lifetime))
        if self.failure:
            raise self.failure
        return [FakeRecord(x) for x in self.records.get(name, [])]


def eml(*, from_address="alice@example.com", body="Routine synthetic notice.", dkim=False) -> bytes:
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = "fixture@example.net"
    message["Subject"] = "Synthetic only"
    if dkim:
        message["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.com; s=test; b=abc; bh=abc"
    message.set_content(body)
    return message.as_bytes()


def resolver_for(domain="example.com"):
    return FakeResolver({
        domain: ["v=spf1 ip4:192.0.2.0/24 -all"],
        f"_dmarc.{domain}": ["v=DMARC1; p=reject; adkim=r; aspf=r"],
        "test._domainkey.example.com": ["v=DKIM1; k=rsa; p=ZmFrZQ=="],
    })


def test_spf_policy_and_trusted_smtp_evaluation_are_separate():
    resolver = resolver_for()
    checked = verification.verify_email_authentication(eml(), resolver=resolver)
    assert checked["checks"]["spf"]["policy_state"] == "POLICY_FOUND"
    assert checked["checks"]["spf"]["state"] == "UNAVAILABLE"
    assert checked["checks"]["spf"]["source"] == "TRUSTED_SMTP_CONTEXT_REQUIRED"

    checked = verification.verify_email_authentication(
        eml(), resolver=resolver,
        smtp_context={"client_ip": "192.0.2.10", "mail_from": "alice@example.com", "helo": "mx.example.com"},
        spf_checker=lambda **kwargs: ("pass", "mock DNS evaluation"),
    )
    assert checked["checks"]["spf"]["state"] == "PASS"
    assert checked["checks"]["dmarc"]["state"] == "PASS"
    assert checked["sender_domain_alignment"]["state"] == "PASS"


def test_spf_and_dmarc_alignment_failure_is_not_converted_to_pass():
    checked = verification.verify_email_authentication(
        eml(), resolver=resolver_for(),
        smtp_context={"client_ip": "192.0.2.10", "mail_from": "attacker.invalid", "helo": "mx.invalid"},
        spf_checker=lambda **kwargs: ("pass", "synthetic result"),
    )
    assert checked["checks"]["spf"]["state"] == "PASS"
    assert checked["checks"]["dmarc"]["state"] == "FAIL"
    assert checked["sender_domain_alignment"]["state"] == "FAIL"


@pytest.mark.parametrize("answer,expected,expected_dmarc", [(True, "PASS", "PASS"), (False, "FAIL", "UNAVAILABLE")])
def test_dkim_cryptographic_result_is_verified_and_drives_dmarc(monkeypatch, answer, expected, expected_dmarc):
    class FakeDKIM:
        def __init__(self, raw, timeout):
            assert timeout == 2

        def verify(self, idx, dnsfunc):
            assert dnsfunc(b"test._domainkey.example.com") == b"v=DKIM1; k=rsa; p=ZmFrZQ=="
            return answer

    monkeypatch.setitem(__import__("sys").modules, "dkim", SimpleNamespace(DKIM=FakeDKIM))
    result = verification.verify_email_authentication(eml(dkim=True), resolver=resolver_for())
    assert result["checks"]["dkim"]["state"] == expected
    assert result["checks"]["dmarc"]["state"] == expected_dmarc


def test_real_dkimpy_signature_verifies_with_generated_synthetic_key():
    import dkim
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_text = base64.b64encode(public_der).decode()
    unsigned = eml()
    signature = dkim.sign(unsigned, b"test", b"example.com", private_pem)
    signed = signature + unsigned
    resolver = resolver_for()
    resolver.records["test._domainkey.example.com"] = [f"v=DKIM1; k=rsa; p={key_text}"]
    result = verification.verify_email_authentication(signed, resolver=resolver)
    assert result["checks"]["dkim"]["state"] == "PASS"
    assert result["checks"]["dmarc"]["state"] == "PASS"

    tampered = signed.replace(b"Routine synthetic notice.", b"Tampered synthetic notice.")
    failed = verification.verify_email_authentication(tampered, resolver=resolver_for())
    assert failed["checks"]["dkim"]["state"] == "FAIL"
    assert failed["checks"]["dmarc"]["state"] == "UNAVAILABLE"


def test_dns_errors_are_unavailable_and_untrusted_headers_are_ignored():
    raw = eml().replace(b"Subject: Synthetic only", b"Subject: Synthetic only\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass")
    result = verification.verify_email_authentication(raw, resolver=FakeResolver(failure=TimeoutError()))
    assert result["reported_header_trusted"] is False
    assert result["checks"]["spf"]["state"] == "UNAVAILABLE"
    assert result["checks"]["dmarc"]["state"] == "UNAVAILABLE"


def test_dkim_dns_timeout_is_unavailable_not_a_false_failure(monkeypatch):
    class FakeDKIM:
        def __init__(self, raw, timeout):
            pass

        def verify(self, idx, dnsfunc):
            dnsfunc(b"test._domainkey.example.com")
            return False

    monkeypatch.setitem(__import__("sys").modules, "dkim", SimpleNamespace(DKIM=FakeDKIM))
    result = verification.verify_email_authentication(eml(dkim=True), resolver=FakeResolver(failure=TimeoutError()))
    assert result["checks"]["dkim"]["state"] == "UNAVAILABLE"
    assert result["checks"]["dmarc"]["state"] == "UNAVAILABLE"


@pytest.mark.skipif(os.getenv("MAILTRACE_AUTH_DNS_LIVE", "").lower() != "true", reason="Opt-in live DNS authentication check")
def test_live_auth_dns_smoke_opt_in_only():
    result = verification.verify_email_authentication(eml())
    assert result["checks"]["spf"]["policy_state"] in {"POLICY_FOUND", "NONE", "UNAVAILABLE"}
    assert result["checks"]["dmarc"]["state"] in {"NONE", "UNAVAILABLE", "INVALID"}


def test_authentication_failures_add_evidence_without_removing_phishing_findings():
    result = {
        "checks": {
            "spf": {"state": "FAIL", "source": "INDEPENDENT"},
            "dkim": {"state": "PASS", "source": "INDEPENDENT"},
            "dmarc": {"state": "FAIL", "source": "INDEPENDENT"},
        },
        "sender_domain_alignment": {"state": "FAIL", "source": "INDEPENDENT"},
        "independent_verification": True,
        "reported_header_trusted": False,
    }
    report = analyze_synthetic_email(
        eml(body="Urgent: verify your account and enter your password."),
        verification_results=result,
    )
    ids = {finding["id"] for finding in report["findings"]}
    assert "MT-SYN-AUTH-SPF-FAIL" in ids
    assert "MT-SYN-AUTH-DMARC-FAIL" in ids
    assert "MT-SYN-CREDENTIAL_REQUEST_LANGUAGE" in ids
    assert report["risk"]["score"] >= 50
    assert report["risk"]["verdict"] != "SAFE"


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    database.DATABASE_PATH = tmp_path / "synthetic-soc.sqlite3"
    database.initialize_database()
    database.initialize_email_alerts()
    database.initialize_case_audit()
    initialize_synthetic_analysis_reports()


def test_sanitized_report_idempotency_and_content_field_guard(isolated_database):
    report = analyze_synthetic_email(eml())
    digest = make_idempotency_hash("tenant-a", "request-1")
    saved, created = create_or_get_report("tenant-a", "analyst-a", digest, report)
    duplicate, was_created = create_or_get_report("tenant-a", "analyst-a", digest, report)
    assert created and not was_created
    assert saved["analysis_id"] == duplicate["analysis_id"]
    assert get_report(saved["analysis_id"], "tenant-a", "other-analyst") is None
    assert get_report(saved["analysis_id"], "other-tenant") is None


class FakeUpload:
    filename = "fixture.eml"

    def __init__(self, content):
        self.content = content
        self.closed = False

    async def read(self, count):
        data, self.content = self.content[:count], self.content[count:]
        return data

    async def close(self):
        self.closed = True


def run(coro):
    try:
        coro.send(None)
    except StopIteration as result:
        return result.value
    raise AssertionError("the fake-upload handler unexpectedly suspended")


def test_synthetic_upload_to_soc_and_authenticated_report_retrieval(isolated_database, monkeypatch):
    monkeypatch.setattr(api, "verify_email_authentication", lambda raw: {
        "checks": {
            "spf": {"state": "UNAVAILABLE", "source": "MOCK_DNS"},
            "dkim": {"state": "NONE", "source": "MOCK_DNS"},
            "dmarc": {"state": "NONE", "source": "MOCK_DNS"},
        },
        "sender_domain_alignment": {"state": "UNAVAILABLE", "source": "MOCK_DNS"},
        "independent_verification": True,
        "reported_header_trusted": False,
    })
    analyst = SimpleNamespace(tenant_id="tenant-a", subject_id="analyst-a", roles={"analyst"})
    request = SimpleNamespace(state=SimpleNamespace(principal=analyst))
    uploaded = FakeUpload(eml(body="Urgent: verify your account and enter your password."))
    response = run(api.analyze_synthetic_fixture(request, uploaded, "upload-key-1"))
    report_id = response["report"]["analysis_id"]
    assert uploaded.closed
    assert response["persistence"]["status"] == "STORED"
    assert response["soc_delivery"]["status"] == "DELIVERED"
    assert response["soc_delivery"]["investigation_id"]
    assert response["soc_delivery"]["alert_id"]
    assert response["soc_delivery"]["case_id"]
    assert "Synthetic only" not in str(response)
    assert "Urgent: verify" not in str(response)

    retrieved = api.read_synthetic_report(report_id, request)
    assert retrieved["report"]["risk"]["score"] == response["report"]["risk"]["score"]
    assert retrieved["soc_delivery"]["status"] == "DELIVERED"
    assert database.get_investigation(f"SYN-{report_id}", "tenant-a") is not None

    with pytest.raises(HTTPException) as denied:
        api.read_synthetic_report(report_id, SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(tenant_id="tenant-a", subject_id="different", roles={"analyst"}))))
    assert denied.value.status_code == 404


def test_asgi_end_to_end_authentication_analysis_persistence_soc_and_retrieval(isolated_database, monkeypatch):
    import main
    from fastapi.testclient import TestClient
    from services.access_control import ApiPrincipal

    token = "synthetic-analysis-test-token"
    principal = ApiPrincipal("tenant-asgi", frozenset({"read", "write", "analyst"}), "analyst-asgi")
    monkeypatch.setattr(main, "configured_api_keys", lambda: ((hashlib.sha256(token.encode()).hexdigest(), principal),))
    monkeypatch.setattr(api, "verify_email_authentication", lambda raw: {
        "checks": {
            "spf": {"state": "UNAVAILABLE", "source": "MOCK_DNS"},
            "dkim": {"state": "NONE", "source": "MOCK_DNS"},
            "dmarc": {"state": "NONE", "source": "MOCK_DNS"},
        },
        "sender_domain_alignment": {"state": "UNAVAILABLE", "source": "MOCK_DNS"},
        "independent_verification": True,
        "reported_header_trusted": False,
    })
    with TestClient(main.app) as client:
        response = client.post(
            "/api/synthetic-analysis",
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "asgi-flow"},
            files={"file": ("fixture.eml", eml(body="Urgent: verify your account. body-secret-7419"), "message/rfc822")},
        )
        assert response.status_code == 201
        payload = response.json()
        assert payload["persistence"]["status"] == "STORED"
        assert payload["soc_delivery"]["status"] == "DELIVERED"
        report_id = payload["report"]["analysis_id"]
        assert "Urgent: verify" not in response.text
        assert "body-secret-7419" not in response.text

        retrieved = client.get(f"/api/synthetic-analysis/{report_id}", headers={"Authorization": f"Bearer {token}"})
        assert retrieved.status_code == 200
        assert retrieved.json()["soc_delivery"]["alert_id"] == payload["soc_delivery"]["alert_id"]

        connection = database.get_connection()
        try:
            persisted = " ".join(
                str(tuple(row))
                for table in ("synthetic_analysis_reports", "investigations", "email_alerts", "email_alert_events")
                for row in connection.execute(f"SELECT * FROM {table}").fetchall()
            )
        finally:
            connection.close()
        assert "body-secret-7419" not in persisted
        assert "Synthetic only" not in persisted

        denied = client.get(f"/api/synthetic-analysis/{report_id}")
        assert denied.status_code == 401


def test_soc_failure_preserves_report_for_bounded_retry(isolated_database, monkeypatch):
    monkeypatch.setattr(api, "verify_email_authentication", lambda raw: {
        "checks": {name: {"state": "UNAVAILABLE", "source": "TEST"} for name in ("spf", "dkim", "dmarc")},
        "sender_domain_alignment": {"state": "UNAVAILABLE", "source": "TEST"},
    })
    original = api.create_email_alert
    monkeypatch.setattr(api, "create_email_alert", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic fail")))
    principal = SimpleNamespace(tenant_id="tenant-a", subject_id="analyst-a", roles={"analyst"})
    request = SimpleNamespace(state=SimpleNamespace(principal=principal))
    response = run(api.analyze_synthetic_fixture(request, FakeUpload(eml()), "retry-key"))
    assert response["persistence"]["status"] == "STORED"
    assert response["soc_delivery"]["status"] == "RETRY_PENDING"
    assert api.read_synthetic_report(response["report"]["analysis_id"], request)["report"]
    monkeypatch.setattr(api, "create_email_alert", original)
    retried = api.retry_synthetic_soc_delivery(response["report"]["analysis_id"], request)
    assert retried["soc_delivery"]["status"] == "DELIVERED"

    duplicate = run(api.analyze_synthetic_fixture(request, FakeUpload(eml()), "retry-key"))
    assert duplicate["duplicate"] is True
    assert duplicate["report"]["analysis_id"] == response["report"]["analysis_id"]
    assert duplicate["soc_delivery"]["alert_id"] == retried["soc_delivery"]["alert_id"]
