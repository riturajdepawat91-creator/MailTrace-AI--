# Microsoft Entra App Registration Setup

> **Superseded for the SIH automatic email-detection path.** Gmail API is now selected; this Entra registration does not grant Gmail API access. See [GMAIL_OAUTH_SETUP.md](GMAIL_OAUTH_SETUP.md) for Google OAuth Desktop setup.

This guide configures a **native public client** for the MailTrace Windows Agent. It uses the system browser and OAuth 2.0 Authorization Code Flow with PKCE via MSAL.NET. Never create a client secret for this desktop agent.

## Before creating the app

Obtain approval from the Microsoft 365 tenant owner. Confirm tenant ID/domain, test mailbox UPN, app display name/owner, tenant account type, requested delegated scopes (`User.Read`, `Mail.Read`), and who will grant consent. Register in the same workforce tenant as the test mailbox, using a single-tenant account option unless a reviewed requirement says otherwise.

## Register the application

1. Open [Microsoft Entra admin center](https://entra.microsoft.com/).
2. Go to **Identity → Applications → App registrations → New registration**.
3. Set a clear name, for example `MailTrace SIH Test Agent`.
4. Choose **Accounts in this organizational directory only** for the dedicated test tenant.
5. Leave the initial Redirect URI unset if necessary; configure the native platform explicitly in the next step.
6. Create the app. Record the **Application (client) ID** and **Directory (tenant) ID** in an approved local secret/configuration store, not in source control or screenshots.

## Authentication platform and redirect URI

1. In the app registration, open **Authentication → Add a platform → Mobile and desktop applications**.
2. For MSAL.NET using the **system browser**, register `http://localhost`. For supported MSAL .NET desktop setups, `.WithDefaultRedirectUri()` chooses the default. Keep the registered and runtime redirect behavior aligned.
3. If using a separately designed embedded-browser path, Microsoft's documented native redirect is `https://login.microsoftonline.com/common/oauth2/nativeclient`. Do not mix redirect URIs/platform types. Prefer the system browser for the initial SIH prototype.
4. Under **Advanced settings**, set **Allow public client flows** to **Yes** if the chosen native MSAL configuration requires it. Do not enable implicit grant or hybrid flow.
5. Save and verify the redirect URI exactly matches the redirect expected by the Agent/MSAL configuration.

Microsoft documents `http://localhost` for desktop system-browser apps and the native-client URI for embedded browser apps: [desktop app registration](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration), [redirect URI guidance](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url).

## Add Microsoft Graph delegated permissions

1. Open **API permissions → Add a permission → Microsoft Graph → Delegated permissions**.
2. Add `User.Read` and `Mail.Read` only.
3. Do not add `Mail.ReadWrite`, `Mail.Send`, `Mail.ReadWrite.Shared`, application `Mail.Read`, `User.Read.All`, or directory-wide permissions.
4. Request `offline_access` through the MSAL/OIDC sign-in scopes as appropriate; it is an OAuth scope rather than a Microsoft Graph API permission row.
5. Review the actual consent prompt while signed in as the test mailbox user. If the tenant blocks user consent or requests admin approval, stop and ask the tenant administrator to review the exact permission set. Do not create a broader permission to work around a policy.

Adding a permission in App registrations does not itself grant consent. The user/admin consent decision is a separate step. See [Microsoft Graph permission reference](https://learn.microsoft.com/en-us/graph/permissions-reference) and [consent experience](https://learn.microsoft.com/en-us/entra/identity-platform/application-consent-experience).

## User-consent and admin-consent checkpoints

- If user consent is enabled for this app and permission set, the test mailbox owner signs in and accepts the delegated consent prompt.
- If the prompt reports **Need admin approval**, the tenant has a policy/permission restriction. Send the admin this document and the permission matrix; ask them to consent only to `User.Read` and `Mail.Read` for the test app.
- Do not select “consent on behalf of your organization” unless an authorized administrator intentionally grants tenant-wide consent and has reviewed the app and scopes.
- Capture the consent status, consenting identity, tenant, app client ID, permission names, and date in the private demo checklist. Do not capture tokens.

## Test sign-in and Graph access

Use the implemented MSAL client when it exists; until then, Graph Explorer can validate the mailbox and API resource shape only. After consent, the Agent should sign in interactively, call `GET /me`, then read only a test message using the permission matrix. Verify the account/tenant claims are the intended test tenant. Graph Explorer's permission grant is separate from the new app registration.

## App configuration and secret handling

The native app requires a client ID, tenant authority, redirect URI, and scopes; a client secret is not appropriate for a distributed desktop/public client. Keep non-secret IDs in local environment/config if needed, but keep access/refresh tokens in MSAL's user token cache protected with Windows DPAPI or an equivalent credential store. Avoid printing token results, dumping HTTP Authorization headers, or checking token cache files into Git.

## Disable and revoke

1. Stop the local Agent and remove the local account/cache entry on logout.
2. For a user-granted delegated consent, the mailbox owner can review/revoke the app grant in the organization's My Apps experience when available.
3. An Entra administrator can review the app under **Enterprise applications → All applications → Permissions** and revoke user or admin consent as appropriate. User-consent grants may require Graph/PowerShell/admin procedures; the portal's admin-consent view is not a universal user-consent revocation UI.
4. If a device is lost or tokens are suspected exposed, ask the administrator to revoke the user's refresh tokens/sign-in sessions as incident response. That affects other app sessions too, not only MailTrace.

Sources: [review and revoke enterprise app permissions](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions), [update permissions and revoke consent](https://learn.microsoft.com/en-us/entra/identity-platform/howto-update-permissions), [revoke sign-in sessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0).

