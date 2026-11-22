# Customer OIDC Setup

**Status:** Native OIDC client implemented; external identity-provider configuration is still **PENDING**. No issuer, client ID, audience, signing keys, or secrets are supplied by MailTrace.

## Identity provider registration

Register MailTrace AI as a **public/native OIDC client**. Do not create or distribute a client secret. Enable Authorization Code flow with PKCE (`S256`) and loopback redirect URIs of the form `http://127.0.0.1:{ephemeral-port}/oauth2callback/`. The desktop app chooses an unused loopback port at sign-in. The provider must permit this native-app redirect pattern.

Configure OIDC discovery metadata or provide the authorization and token endpoint overrides. The configured issuer must exactly match the discovery document and signed token `iss` claim. The API requires JWT access tokens whose API audience equals the configured audience and whose trusted claims contain `customer_user` and a stable tenant claim (default `tenant_id`). An access token without those claims is rejected. Do not map SOC roles to `customer_user`.

Use only `openid profile offline_access` in the current native sign-in request. `offline_access` is needed only if the provider supports refresh tokens; refresh tokens are protected by Windows DPAPI. No email-address claim is required for login. Gmail OAuth remains a separate flow and token store.

## Windows environment configuration

Set these as user or machine environment variables before launching MailTrace AI. Use values issued by the selected identity provider:

```powershell
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_ISSUER', '<HTTPS issuer URL>', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_CLIENT_ID', '<public native client ID>', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_AUDIENCE', '<Customer API audience>', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_JWKS_URL', '<HTTPS JWKS URL>', 'User')
```

Optional provider endpoint overrides:

```powershell
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_AUTHORIZATION_ENDPOINT', '<HTTPS authorization endpoint>', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_TOKEN_ENDPOINT', '<HTTPS token endpoint>', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_REVOCATION_ENDPOINT', '<HTTPS revocation endpoint>', 'User')
```

Optional claim paths default to `tenant_id` and `roles`:

```powershell
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_TENANT_CLAIM', 'tenant_id', 'User')
[Environment]::SetEnvironmentVariable('MAILTRACE_CUSTOMER_OIDC_ROLES_CLAIM', 'roles', 'User')
```

Restart the app after setting variables. Never put a client secret, private key, OAuth token, or refresh token into these environment variables. The values above are templates, not working identity-provider configuration.

## What the app does

The WinUI native host discovers the issuer metadata, generates random `state`, `nonce`, and a PKCE verifier, opens the system browser, validates the loopback callback and exchanges the code. The Customer API independently validates the ID-token issuer, signature, audience, expiration and nonce, then validates the access-token issuer, signature, Customer API audience, expiration, subject, tenant and `customer_user` role. API operations are sent only through a native allowlist. Access tokens stay in native memory; refresh tokens are DPAPI-protected under the Windows user profile. Logout revokes the current API access-token digest locally, clears the native tokens, and requests provider refresh-token revocation when the provider advertises it.

## Test-only local HTTP exception

Automated tests use an ephemeral `127.0.0.1` OIDC provider with a generated test key. HTTP issuer/JWKS endpoints are accepted only when both `MAILTRACE_ENV=test` and `MAILTRACE_CUSTOMER_OIDC_TEST_MODE=1` are set. Never set those flags for a normal app run. Test keys and tokens are generated only in memory and are not real credentials.

## Not enabled

No real provider is configured in the current environment. Real sign-in, provider revocation, tenant membership correctness and production issuer availability therefore remain **NOT VERIFIED**. Multi-tenant business/bank access remains disabled; the local profile binds to a single verified identity.
