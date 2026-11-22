# Gmail Desktop OAuth Setup

This describes the user authorization required for the Gmail API. OAuth tokens for Gmail are not Pub/Sub subscriber credentials, MailTrace OTP sessions, or SOC credentials.

## OAuth client and scope

- Create a Google OAuth client with application type **Desktop app** in the dedicated demo Google Cloud project.
- Request only `https://www.googleapis.com/auth/gmail.readonly`.
- Use the Google-installed-app OAuth 2.0 flow with authorization code + PKCE (S256) through the system browser and a loopback redirect. Do not embed a client secret as if a desktop app could keep it confidential; a desktop OAuth client is a public client.
- Request offline access so the installed Agent can refresh tokens without Outlook/Gmail UI or the dashboard open. Avoid unnecessary repeated `prompt=consent` authorizations that issue extra refresh tokens.
- Verify the granted scope returned by the OAuth library. If scope is declined or revoked, stop scanning and show reconnect-required status.

Google's installed-app flow supports PKCE and loopback redirects; the authorization grant is needed before any Gmail API request. See [OAuth 2.0 for Desktop Apps](https://developers.google.com/identity/protocols/oauth2/native-app).

## Sign-in and token lifecycle

1. User selects **Connect Gmail** in a local user-facing control. Do not attempt a browser-less first login from Windows service startup.
2. Agent opens the system browser and redirects to Google with client ID, read-only scope, random state, PKCE challenge, offline access request, and consent prompt on explicit connect/reconnect so a refresh token can be issued.
3. User signs in to the exact demo Gmail mailbox and approves the restricted Gmail read scope. An external/testing app may show a warning; stop if the account/project/permissions differ from the approved test setup.
4. Google returns a one-time authorization code to a loopback listener. Validate state, exchange code with PKCE verifier over TLS, then discard code/verifier.
5. Store refresh-token credentials in a per-Windows-user protected store (DPAPI CurrentUser, Windows Credential Manager, or approved equivalent). Restrict file ACLs if a library cache file is used. Do not store tokens in `backend/mailtrace.db`, a general configuration file, User Backend, dashboard/browser storage, or logs.
6. Request an access token through the Google auth library. Let the library refresh it silently. Never print credentials, token responses, authorization headers, OAuth callback query strings, or exception bodies that may contain them.
7. On invalid/revoked refresh token (`invalid_grant`), removed consent, account policy block, or repeated 401/403, stop Gmail calls, mark authorization `RECONNECT_REQUIRED`, preserve only non-content sync state, and prompt the signed-in Windows user for an interactive reconnect.
8. Logout stops Pub/Sub processing and watch renewal, deletes the local protected Gmail token/cache entry, clears mailbox connection state as policy allows, and shows Disconnected. It should not delete Gmail messages or cloud subscriptions without explicit cleanup policy.
9. Permission revocation is performed by the user in Google Account security / third-party connections or by a Workspace admin. Local cache deletion alone does not revoke server-side consent. Conversely, server-side revocation may take time to affect issued tokens; stop on auth failures immediately.

## Token expiry caveats

Google access tokens expire; the library obtains replacements using the refresh token. Refresh tokens can be revoked, expire after inactivity or policy changes, or become invalid after user/admin actions. **External OAuth projects in Testing status issue refresh tokens that expire after seven days** for restricted Gmail scopes; that can interrupt a demonstration planned beyond the test window. Confirm publishing/test status and account policy before the demo. Do not promise unattended continuity on a test token without monitoring and a reconnect path.

Sources: [Google OAuth token refresh](https://developers.google.com/identity/protocols/oauth2), [OAuth app verification/testing requirements](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification), [Google credential storage guidance](https://developers.google.com/identity/protocols/oauth2/resources/best-practices).

## Windows Agent identity

The Agent must run under a Windows identity that can access the same DPAPI/Windows Credential Manager data used by the interactive connect flow. A Windows service running as `LocalSystem` cannot be assumed to read another user's CurrentUser token store. The installation must explicitly choose and test a same-user service logon/profile or a user-session Agent host. Before first OAuth authorization, show Agent status as `AUTHORIZATION_REQUIRED`; do not assume a token exists merely because service startup succeeded.

Pub/Sub uses a different Google Cloud identity. Prefer Application Default Credentials via a constrained user/service identity or Workload Identity Federation where workable. If a service-account key is unavoidable for the laptop demo, keep it outside the repo in an ACL-protected file and grant only subscriber role; rotate/delete it after the demo. Never reuse Gmail OAuth credentials for Pub/Sub.

# Readiness

Phase 1A implementation is in `backend/services/gmail_connector/oauth.py` and `token_store.py`. It reads the external Desktop credentials file from `MAILTRACE_GMAIL_CREDENTIALS_PATH` when set, otherwise `%LOCALAPPDATA%\mailtrace\secrets\credentials.json`. It requires an `installed` Desktop client with Google HTTPS endpoints, requests exactly Gmail readonly, checks callback state, uses PKCE S256, and stores token state through Windows DPAPI CurrentUser under `%LOCALAPPDATA%\MailTrace\gmail\oauth.dpapi`. Tokens are never written as plaintext by the application. Unit tests use synthetic fixtures and mocked HTTP.

The user subsequently completed browser consent and reported successful real Gmail profile, Inbox metadata, and selected metadata-only calls. Phase 1B reuses this same readonly OAuth connector. Pub/Sub Application Default Credentials remain a separate manual setup and are not stored with the Gmail OAuth token.

