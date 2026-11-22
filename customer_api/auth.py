"""Fail-closed OIDC access-token verification for customer routes."""
from __future__ import annotations

import os
import hmac
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse


@dataclass(frozen=True)
class CustomerPrincipal:
    issuer: str
    subject: str
    tenant_id: str
    roles: frozenset[str]
    expires_at: int = 0


class IdentityUnavailable(RuntimeError):
    pass


def oidc_config() -> dict[str, str] | None:
    names = {
        "issuer": "MAILTRACE_CUSTOMER_OIDC_ISSUER",
        "audience": "MAILTRACE_CUSTOMER_OIDC_AUDIENCE",
        "jwks_url": "MAILTRACE_CUSTOMER_OIDC_JWKS_URL",
        "client_id": "MAILTRACE_CUSTOMER_OIDC_CLIENT_ID",
    }
    values = {key: os.getenv(name, "").strip() for key, name in names.items()}
    if not all(values.values()):
        return None
    if any(urlparse(values[k]).scheme != "https" for k in ("issuer", "jwks_url")):
        parsed_issuer = urlparse(values["issuer"])
        parsed_jwks = urlparse(values["jwks_url"])
        local_test = (
            os.getenv("MAILTRACE_ENV", "").strip().lower() == "test"
            and os.getenv("MAILTRACE_CUSTOMER_OIDC_TEST_MODE", "").strip() == "1"
            and parsed_issuer.scheme == parsed_jwks.scheme == "http"
            and parsed_issuer.hostname in {"127.0.0.1", "localhost"}
            and parsed_jwks.hostname in {"127.0.0.1", "localhost"}
        )
        if not local_test:
            raise IdentityUnavailable("Customer OIDC issuer and JWKS endpoint must use HTTPS.")
    return values


@lru_cache(maxsize=4)
def _jwks_client(url: str):
    try:
        from jwt import PyJWKClient
    except ImportError as exc:
        raise IdentityUnavailable("JWT verification dependency is unavailable.") from exc
    return PyJWKClient(url, cache_jwk_set=True, lifespan=300, timeout=5)


def verify_customer_token(token: str) -> CustomerPrincipal | None:
    config = oidc_config()
    if config is None:
        raise IdentityUnavailable("Customer sign-in is not configured.")
    if not token or len(token) > 16384 or token.count(".") != 2:
        return None
    try:
        import jwt
        from jwt import InvalidTokenError

        key = _jwks_client(config["jwks_url"]).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=config["audience"], issuer=config["issuer"],
            options={"require": ["iss", "aud", "exp", "sub"]},
        )
    except ImportError as exc:
        raise IdentityUnavailable("JWT verification dependency is unavailable.") from exc
    except Exception as exc:
        # Key retrieval errors are availability failures; bad token claims are 401.
        if exc.__class__.__name__ in {"PyJWKClientError", "PyJWKClientConnectionError"}:
            raise IdentityUnavailable("Customer identity keys could not be retrieved.") from None
        if isinstance(exc, InvalidTokenError):
            return None
        raise IdentityUnavailable("Customer identity could not be verified.") from None

    subject = claims.get("sub")
    tenant_claim = os.getenv("MAILTRACE_CUSTOMER_OIDC_TENANT_CLAIM", "tenant_id")
    roles_claim = os.getenv("MAILTRACE_CUSTOMER_OIDC_ROLES_CLAIM", "roles")
    tenant = claims
    for part in tenant_claim.split("."):
        tenant = tenant.get(part) if isinstance(tenant, dict) else None
    roles = claims
    for part in roles_claim.split("."):
        roles = roles.get(part) if isinstance(roles, dict) else None
    if isinstance(roles, str):
        roles = roles.split()
    if not isinstance(subject, str) or not subject or len(subject) > 256:
        return None
    if not isinstance(tenant, str) or not tenant or len(tenant) > 128:
        return None
    if not isinstance(roles, (tuple, list, set)):
        return None
    normalized = frozenset(str(role).strip().lower() for role in roles)
    if "customer_user" not in normalized:
        return None
    # Never map SOC roles into a customer role or grant tenant-wide privileges.
    if normalized & {"analyst", "soc_lead", "tenant_admin", "platform_admin", "admin", "service", "customer_tenant_admin"}:
        return None
    return CustomerPrincipal(config["issuer"], subject, tenant, normalized, int(claims["exp"]))


def verify_customer_login_tokens(id_token: str, access_token: str, nonce: str) -> CustomerPrincipal | None:
    """Verify the OIDC ID-token nonce and separately validate API-scoped access token."""
    config = oidc_config()
    if config is None:
        raise IdentityUnavailable("Customer sign-in is not configured.")
    if not id_token or len(id_token) > 16384 or not nonce or len(nonce) > 256:
        return None
    try:
        import jwt
        from jwt import InvalidTokenError

        key = _jwks_client(config["jwks_url"]).get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(
            id_token, key, algorithms=["RS256", "ES256"], audience=config["client_id"],
            issuer=config["issuer"], options={"require": ["iss", "aud", "exp", "sub", "nonce"]},
        )
    except ImportError as exc:
        raise IdentityUnavailable("JWT verification dependency is unavailable.") from exc
    except Exception as exc:
        if exc.__class__.__name__ in {"PyJWKClientError", "PyJWKClientConnectionError"}:
            raise IdentityUnavailable("Customer identity keys could not be retrieved.") from None
        if isinstance(exc, InvalidTokenError):
            return None
        raise IdentityUnavailable("Customer identity could not be verified.") from None
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        return None
    access_principal = verify_customer_token(access_token)
    if access_principal is None or claims.get("sub") != access_principal.subject:
        return None
    return access_principal
