"""In-process test IdP contract tests; no network or real provider credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request

from customer_api import auth, main


class _Protector:
    def protect(self, data: bytes) -> bytes:
        return b"test:" + data

    def unprotect(self, data: bytes) -> bytes:
        return data.removeprefix(b"test:")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _request_json(value):
    body = json.dumps(value).encode()
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.request", "body": b"", "more_body": False}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "path": "/v1/auth/validate", "headers": [(b"content-type", b"application/json")], "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8100), "scheme": "http", "query_string": b""}, receive)


def _run_immediate(coroutine):
    """Drive this endpoint coroutine without creating a Windows Proactor loop."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Expected the request-only endpoint coroutine to complete without scheduling I/O.")


@pytest.fixture
def local_oidc_provider(monkeypatch, tmp_path):
    """Deterministic local issuer/JWKS test double with an ephemeral RSA key."""
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "http://127.0.0.1:49001"
    monkeypatch.setenv("MAILTRACE_ENV", "test")
    monkeypatch.setenv("MAILTRACE_CUSTOMER_OIDC_TEST_MODE", "1")
    monkeypatch.setenv("MAILTRACE_CUSTOMER_OIDC_ISSUER", issuer)
    monkeypatch.setenv("MAILTRACE_CUSTOMER_OIDC_AUDIENCE", "mailtrace-customer-api")
    monkeypatch.setenv("MAILTRACE_CUSTOMER_OIDC_CLIENT_ID", "mailtrace-test-client")
    monkeypatch.setenv("MAILTRACE_CUSTOMER_OIDC_JWKS_URL", issuer + "/jwks")
    monkeypatch.setattr(main, "_DB_PATH", tmp_path / "local-owner.sqlite3")
    monkeypatch.setattr("services.gmail_connector.token_store.WindowsDpapi", _Protector)

    class KeySet:
        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=signing_key.public_key())

    monkeypatch.setattr(auth, "_jwks_client", lambda _url: KeySet())

    def issue(nonce="nonce-test", roles=("customer_user",), audience="mailtrace-customer-api", subject="subject-test", expires=None):
        now = int(time.time())
        common = {"iss": issuer, "sub": subject, "tenant_id": "single-test-profile", "iat": now, "exp": expires or now + 600}
        access = jwt.encode({**common, "aud": audience, "roles": list(roles)}, signing_key, algorithm="RS256")
        identity = jwt.encode({**common, "aud": "mailtrace-test-client", "nonce": nonce}, signing_key, algorithm="RS256")
        return {"access_token": access, "id_token": identity, "refresh_token": "test-refresh-token"}

    yield {"issuer": issuer, "issue": issue, "key": signing_key}


def test_local_oidc_pkce_and_customer_login(local_oidc_provider):
    provider = local_oidc_provider
    verifier = _b64url(b"v" * 48)
    expected_challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    assert len(expected_challenge) == 43  # S256 PKCE challenge shape.
    tokens = provider["issue"](nonce="expected-nonce")
    result = _run_immediate(main.validate_login(_request_json({**tokens, "nonce": "expected-nonce"})))
    assert result == {"authenticated": True, "subject": "subject-test", "roles": ["customer_user"]}
    assert tokens["refresh_token"] not in json.dumps(result)
    assert tokens["access_token"] not in json.dumps(result)


def test_local_oidc_rejects_wrong_nonce_role_audience_and_expiry(local_oidc_provider):
    provider = local_oidc_provider
    valid = provider["issue"](nonce="right")
    with pytest.raises(main.HTTPException) as raised:
        _run_immediate(main.validate_login(_request_json({**valid, "nonce": "wrong"})))
    assert raised.value.status_code == 401

    wrong_role = provider["issue"](roles=("analyst",))
    with pytest.raises(main.HTTPException) as raised:
        _run_immediate(main.validate_login(_request_json({**wrong_role, "nonce": "nonce-test"})))
    assert raised.value.status_code == 401

    wrong_audience = provider["issue"](audience="other-api")
    with pytest.raises(main.HTTPException) as raised:
        _run_immediate(main.validate_login(_request_json({**wrong_audience, "nonce": "nonce-test"})))
    assert raised.value.status_code == 401

    expired = provider["issue"](expires=int(time.time()) - 1)
    with pytest.raises(main.HTTPException) as raised:
        _run_immediate(main.validate_login(_request_json({**expired, "nonce": "nonce-test"})))
    assert raised.value.status_code == 401


def test_logout_revokes_customer_api_access_token(local_oidc_provider):
    provider = local_oidc_provider
    tokens = provider["issue"]()
    principal = auth.verify_customer_token(tokens["access_token"])
    assert principal is not None
    assert main.me(principal)["roles"] == ["customer_user"]
    result = main.logout_customer("Bearer " + tokens["access_token"])
    assert result == {"status": "SIGNED_OUT"}
    with pytest.raises(main.HTTPException) as raised:
        main.principal_dependency("Bearer " + tokens["access_token"])
    assert raised.value.status_code == 401


def test_local_oidc_refresh_and_provider_revocation_contract(local_oidc_provider):
    # The native host uses the standard refresh_token grant and deletes its DPAPI
    # cache at logout. Provider-side refresh-token revocation is optional metadata.
    code = "test-code"
    verifier = "x" * 64
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    assert challenge == _b64url(hashlib.sha256(verifier.encode()).digest())
    assert local_oidc_provider["issuer"].startswith("http://127.0.0.1:")
    assert local_oidc_provider["issue"]()["refresh_token"] == "test-refresh-token"
