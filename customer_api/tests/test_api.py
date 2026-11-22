from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from customer_api import main
from customer_api.auth import CustomerPrincipal, verify_customer_token


class _TestProtector:
    def protect(self, value):
        return b"test:" + value
    def unprotect(self, value):
        return value.removeprefix(b"test:")


def test_public_health_is_minimal():
    assert main.health() == {"status": "ok", "service": "MailTrace Customer API"}


def test_missing_identity_configuration_fails_closed(monkeypatch):
    for key in ("MAILTRACE_CUSTOMER_OIDC_ISSUER", "MAILTRACE_CUSTOMER_OIDC_AUDIENCE", "MAILTRACE_CUSTOMER_OIDC_JWKS_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(main, "verify_customer_token", verify_customer_token)
    with pytest.raises(HTTPException) as raised:
        main.principal_dependency("Bearer opaque")
    assert raised.value.status_code == 503


def test_protected_routes_require_bearer():
    with pytest.raises(HTTPException) as raised:
        main.principal_dependency(None)
    assert raised.value.status_code == 401


def test_valid_customer_principal_is_bound_to_local_profile(monkeypatch, tmp_path):
    principal = CustomerPrincipal("https://id.example", "subject-a", "tenant-a", frozenset({"customer_user"}))
    monkeypatch.setattr(main, "_DB_PATH", tmp_path / "owner.sqlite3")
    monkeypatch.setattr("services.gmail_connector.token_store.WindowsDpapi", _TestProtector)
    main._bind_owner(principal)
    result = main.me(principal)
    assert result["tenant_scope"] == "single-local-owner"
    assert result["multi_tenant"] is False


def test_profile_rejects_cross_owner_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "_DB_PATH", tmp_path / "owner.sqlite3")
    monkeypatch.setattr("services.gmail_connector.token_store.WindowsDpapi", _TestProtector)
    main._bind_owner(CustomerPrincipal("https://id.example", "subject-a", "tenant-a", frozenset({"customer_user"})))
    with pytest.raises(HTTPException) as raised:
        main._bind_owner(CustomerPrincipal("https://id.example", "subject-b", "tenant-a", frozenset({"customer_user"})))
    assert raised.value.status_code == 403


def test_customer_api_has_no_soc_or_analysis_proxy():
    paths = set(main.app.openapi()["paths"])
    assert not any("soc" in path or "analysis" in path or "reports" in path for path in paths)


def test_disallowed_origin_is_rejected():
    request = SimpleNamespace(headers={"host": "127.0.0.1:8100", "origin": "https://evil.example"}, client=SimpleNamespace(host="127.0.0.1"))
    async def call_next(_request):
        return object()
    coroutine = main.loopback_boundary(request, call_next)
    with pytest.raises(StopIteration) as completed:
        coroutine.send(None)
    response = completed.value.value
    assert response.status_code == 403
