# Customer API (local prototype)

The Customer API is an allowlisted FastAPI boundary on `127.0.0.1:8100`. It is separate from the SOC backend on `8002` and has no SOC proxy routes.

Run from the repository root using the existing backend virtual environment:

```powershell
backend\venv\Scripts\python.exe -m uvicorn customer_api.main:app --app-dir . --host 127.0.0.1 --port 8100 --no-access-log
```

The native Windows host implements OIDC Authorization Code + PKCE. Configure these values before sign-in; until then the API fails closed and the UI reports sign-in unavailable:

- `MAILTRACE_CUSTOMER_OIDC_ISSUER` — trusted HTTPS issuer.
- `MAILTRACE_CUSTOMER_OIDC_AUDIENCE` — Customer API audience.
- `MAILTRACE_CUSTOMER_OIDC_JWKS_URL` — trusted HTTPS JWKS endpoint.
- `MAILTRACE_CUSTOMER_OIDC_CLIENT_ID` — public/native OIDC client ID.
- Optional claim names: `MAILTRACE_CUSTOMER_OIDC_TENANT_CLAIM` (default `tenant_id`) and `MAILTRACE_CUSTOMER_OIDC_ROLES_CLAIM` (default `roles`).
- Optional `MAILTRACE_CUSTOMER_OIDC_AUTHORIZATION_ENDPOINT`, `MAILTRACE_CUSTOMER_OIDC_TOKEN_ENDPOINT`, and `MAILTRACE_CUSTOMER_OIDC_REVOCATION_ENDPOINT` overrides; otherwise discovery metadata is used.

Protected routes fail closed until a signed token with the `customer_user` role is presented. Native refresh tokens are stored by the WinUI host using Windows DPAPI; access tokens remain in native memory and are not passed into WebView JavaScript. OIDC identity tokens are separate from Gmail OAuth credentials. The API persists only a digest of a logged-out access token until expiry so that API logout invalidates that token. Gmail integration is readonly and metadata-only. The Customer API will not access bodies, MIME, attachments, analysis endpoints or Central SOC routes.

The Windows app starts the customer service only when the configured existing backend directory and its Python virtual environment are available. Configure the real provider according to `CUSTOMER_OIDC_SETUP.md`; no provider values are preconfigured. The service is a local desktop prototype, not a multi-tenant deployment. Automated local-provider tests are explicitly test-only and do not verify a real customer IdP.
