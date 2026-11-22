"""Loopback Customer API; intentionally has no SOC proxy or content-analysis route."""
from __future__ import annotations

import os
import sys
import hashlib
import time
import json
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from customer_api.auth import CustomerPrincipal, IdentityUnavailable, oidc_config, verify_customer_login_tokens, verify_customer_token

app = FastAPI(title="MailTrace Customer API", version="1.0", docs_url=None, redoc_url=None)
_DB_PATH = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "MailTrace" / "customer" / "ownership.sqlite3"


@app.middleware("http")
async def loopback_boundary(request: Request, call_next):
    host = request.headers.get("host", "").split(":", 1)[0].strip("[]").lower()
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
    client_host = request.client.host if request.client else ""
    if host not in allowed_hosts or client_host not in allowed_hosts:
        return JSONResponse({"detail": "Loopback access only."}, status_code=403)
    origin = request.headers.get("origin")
    if origin and origin not in {"https://mailtrace.invalid", "http://127.0.0.1:4173", "http://localhost:4173"}:
        return JSONResponse({"detail": "Origin is not allowed."}, status_code=403)
    return await call_next(request)


def principal_dependency(authorization: Annotated[str | None, Header()] = None) -> CustomerPrincipal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Customer sign-in is required.", headers={"WWW-Authenticate": "Bearer"})
    try:
        principal = verify_customer_token(authorization[7:].strip())
    except IdentityUnavailable:
        raise HTTPException(503, "Customer identity provider is not configured or unavailable.") from None
    if principal is None:
        raise HTTPException(401, "Customer identity is invalid or expired.", headers={"WWW-Authenticate": "Bearer"})
    if _is_token_revoked(authorization[7:].strip()):
        raise HTTPException(401, "Customer session is signed out.", headers={"WWW-Authenticate": "Bearer"})
    return principal


def _owner_db():
    import sqlite3
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(_DB_PATH, timeout=5)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS local_owner (singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity_cipher BLOB NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS revoked_customer_tokens (token_digest TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")
    return db


def _is_token_revoked(token: str) -> bool:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _owner_db() as db:
        db.execute("DELETE FROM revoked_customer_tokens WHERE expires_at<=?", (int(time.time()),))
        return db.execute("SELECT 1 FROM revoked_customer_tokens WHERE token_digest=?", (digest,)).fetchone() is not None


def _revoke_access_token(token: str, principal: CustomerPrincipal) -> None:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _owner_db() as db:
        db.execute("INSERT OR REPLACE INTO revoked_customer_tokens(token_digest, expires_at) VALUES(?,?)", (digest, principal.expires_at))


def _bind_owner(principal: CustomerPrincipal) -> None:
    # Existing Gmail token/checkpoint stores are per Windows profile, not tenant scoped.
    # Bind the profile to a single principal; reject any subsequent identity.
    try:
        import json
        from services.gmail_connector.token_store import WindowsDpapi
        protector = WindowsDpapi()
        identity = (principal.issuer, principal.tenant_id, principal.subject)
        cipher = protector.protect(json.dumps(identity, separators=(",", ":")).encode("utf-8"))
        with _owner_db() as db:
            row = db.execute("SELECT identity_cipher FROM local_owner WHERE singleton=1").fetchone()
            if row is None:
                db.execute("INSERT INTO local_owner(singleton, identity_cipher) VALUES(1,?)", (cipher,))
                return
            existing = tuple(json.loads(protector.unprotect(bytes(row[0])).decode("utf-8")))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Secure local customer ownership storage is unavailable.") from None
    if existing != identity:
        raise HTTPException(403, "This local MailTrace profile is bound to another customer identity.")


def _gmail_components():
    try:
        from services.gmail_connector.agent import run_agent
        from services.gmail_connector.client import GmailClient
        from services.gmail_connector.config import AgentConfig
        from services.gmail_connector.diagnostics import build_diagnostics
        from services.gmail_connector.oauth import GmailOAuth
        from services.gmail_connector.store import SyncStore
        from services.gmail_connector.sync import GmailSyncEngine
        return run_agent, GmailClient, AgentConfig, build_diagnostics, GmailOAuth, SyncStore, GmailSyncEngine
    except Exception:
        raise HTTPException(503, "Gmail connector dependencies are unavailable.") from None


def _safe_diagnostics():
    _, _, config_type, diagnostics, oauth_type, store_type, _ = _gmail_components()
    try:
        config = config_type.from_env()
        oauth = oauth_type()
        state = store_type(config.state_path).get_state()
        return diagnostics(state, oauth.authorization_status())
    except Exception as exc:
        return {"gmail_authorization": "UNAVAILABLE", "health_status": "NOT_CONFIGURED", "last_error_category": type(exc).__name__, "pending_sync_jobs": 0}


@app.get("/health")
def health():
    return {"status": "ok", "service": "MailTrace Customer API"}


@app.get("/ready")
def ready():
    try:
        configured = oidc_config() is not None
        state = "configured" if configured else "not_configured"
    except IdentityUnavailable:
        configured, state = False, "invalid_configuration"
    return {"status": "ok" if configured else "degraded", "identity_provider": state}


@app.get("/v1/auth/config")
def auth_config():
    try:
        config = oidc_config()
        configuration_error = False
    except IdentityUnavailable:
        config, configuration_error = None, True
    message = (
        "Customer OIDC configuration is ready." if config else
        "Customer OIDC configuration is invalid; use HTTPS issuer and JWKS endpoints." if configuration_error else
        "Set issuer, public client ID, API audience and JWKS URL; register a native public client before sign-in."
    )
    return {
        "enabled": bool(config), "issuer": config["issuer"] if config else None,
        "client_id": config["client_id"] if config else None,
        "audience": config["audience"] if config else None,
        "authorization_endpoint": config.get("authorization_endpoint") if config else None,
        "token_endpoint": config.get("token_endpoint") if config else None,
        "revocation_endpoint": config.get("revocation_endpoint") if config else None,
        "discovery_url": config["issuer"].rstrip("/") + "/.well-known/openid-configuration" if config else None,
        "test_mode": os.getenv("MAILTRACE_ENV", "").strip().lower() == "test" and os.getenv("MAILTRACE_CUSTOMER_OIDC_TEST_MODE", "").strip() == "1",
        "login_supported": bool(config), "flow": "Authorization Code + PKCE (S256), native system browser", "message": message,
    }


@app.post("/v1/auth/validate")
async def validate_login(request: Request):
    """Validate native PKCE results without logging or returning any token."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "OIDC login response is malformed.") from None
    if not isinstance(payload, dict):
        raise HTTPException(400, "OIDC login response is malformed.")
    id_token, access_token, nonce = payload.get("id_token"), payload.get("access_token"), payload.get("nonce")
    if not all(isinstance(item, str) and 0 < len(item) <= 16384 for item in (id_token, access_token, nonce)):
        raise HTTPException(400, "OIDC login response is incomplete.")
    try:
        principal = verify_customer_login_tokens(id_token, access_token, nonce)
    except IdentityUnavailable:
        raise HTTPException(503, "Customer identity provider is not configured or unavailable.") from None
    if principal is None:
        raise HTTPException(401, "OIDC identity, nonce, audience, or customer role is invalid.")
    _bind_owner(principal)
    return {"authenticated": True, "subject": principal.subject, "roles": ["customer_user"]}


@app.post("/v1/auth/logout")
def logout_customer(authorization: Annotated[str | None, Header()] = None):
    principal = principal_dependency(authorization)
    token = authorization[7:].strip()
    try:
        _revoke_access_token(token, principal)
    except Exception:
        raise HTTPException(503, "Customer session could not be durably signed out.") from None
    return {"status": "SIGNED_OUT"}


@app.get("/v1/me")
def me(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    return {"subject": principal.subject, "roles": sorted(role for role in principal.roles if role == "customer_user"), "tenant_scope": "single-local-owner", "multi_tenant": False}


@app.get("/v1/mailboxes")
def mailboxes(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    _, _, _, _, oauth_type, _, _ = _gmail_components()
    oauth = oauth_type()
    status = oauth.authorization_status()
    identity = None
    if status == "CONNECTED":
        try:
            _, client_type, *_ = _gmail_components()
            profile = client_type(oauth).get_profile()
            identity = profile.get("emailAddress") if isinstance(profile.get("emailAddress"), str) else None
        except Exception:
            status = "ERROR"
    return {"items": [{"id": "gmail-primary", "provider": "gmail", "status": status, "identity": identity, "scope": "gmail.readonly" if status == "CONNECTED" else None}]}


@app.post("/v1/mailboxes/gmail-primary/connect")
def connect_gmail(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    _, _, _, _, oauth_type, _, _ = _gmail_components()
    try:
        oauth_type().authorize()
        return {"status": "CONNECTED", "scope": "gmail.readonly"}
    except Exception as exc:
        # Exception messages can include provider details; return category only.
        raise HTTPException(503, f"Gmail authorization did not complete ({type(exc).__name__}).") from None


@app.delete("/v1/mailboxes/gmail-primary")
def disconnect_gmail(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    _, _, _, _, oauth_type, _, _ = _gmail_components()
    try:
        oauth_type().logout()
        return {"status": "DISCONNECTED"}
    except Exception as exc:
        raise HTTPException(503, f"Gmail revocation did not complete ({type(exc).__name__}); local authorization was retained.") from None


@app.get("/v1/protection/status")
def protection_status(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    return {"metadata_only": True, "content_analysis": "BLOCKED", "soc_transfer": "NOT_AVAILABLE", "sync": _safe_diagnostics()}


@app.get("/v1/sync/status")
def sync_status(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    return _safe_diagnostics()


@app.post("/v1/sync")
def sync_once(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    _, client_type, config_type, _, oauth_type, store_type, engine_type = _gmail_components()
    try:
        config = config_type.from_env()
        oauth = oauth_type()
        if oauth.authorization_status() != "CONNECTED":
            raise HTTPException(409, "Connect Gmail before requesting metadata synchronization.")
        store = store_type(config.state_path)
        if not store.get_history_id():
            raise HTTPException(409, "No durable sync checkpoint exists; connect through the configured foreground Agent first.")
        engine = engine_type(client_type(oauth), store, recovery_window_hours=config.recovery_window_hours, recovery_max_messages=config.recovery_max_messages)
        inserted = engine.sync_until_current("poll")
        return {"status": "SYNCED", "new_message_references": inserted, "sync": _safe_diagnostics()}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, f"Metadata synchronization failed ({type(exc).__name__}).") from None


@app.get("/v1/metadata/pending")
def pending_metadata(principal: CustomerPrincipal = Depends(principal_dependency)):
    _bind_owner(principal)
    _, _, config_type, _, _, store_type, _ = _gmail_components()
    try:
        config = config_type.from_env()
        store = store_type(config.state_path)
        return {"pending_count": store.get_state().get("pending_count", 0), "items": [], "message_ids": "withheld", "content_access": "none"}
    except Exception as exc:
        raise HTTPException(503, f"Metadata queue is unavailable ({type(exc).__name__}).") from None
