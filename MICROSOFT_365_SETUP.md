# Microsoft 365 Test Mailbox Setup

> **Superseded for the SIH automatic email-detection path.** Gmail API is now the selected provider. Use [GMAIL_API_SETUP.md](GMAIL_API_SETUP.md), [GMAIL_OAUTH_SETUP.md](GMAIL_OAUTH_SETUP.md), and [EMAIL_PROVIDER_ARCHITECTURE.md](EMAIL_PROVIDER_ARCHITECTURE.md). This file is retained only as the prior Microsoft Graph setup record.

Phase 1 environment guide for the MailTrace SIH demonstration. This is documentation only: no tenant, mailbox, Outlook profile, Graph request, or Entra registration has been created or changed.

## Required test environment

Use a dedicated Microsoft 365 **work or school account** in a non-production tenant, with an Exchange Online mailbox provisioned and permitted to use Outlook and Microsoft Graph. Use one mailbox for the first live demo; add a second sender/test account only if the demo needs to send controlled messages. Keep the tenant and mailbox under the owner's control and do not use a production mailbox.

Microsoft 365 admin/tenant owner needs to confirm:

- The tenant ID/domain and the test mailbox UPN.
- The mailbox has an Exchange Online service/license and can sign in at Outlook on the web.
- The user can use Outlook desktop (new or classic) and has a Windows profile for the demo.
- Entra app registration is allowed, and who can consent to the requested delegated scopes.
- User consent policies, Conditional Access, MFA, device compliance, and security defaults that may affect token acquisition.
- The target account is approved for a read-only demo and contains only test messages.

A Microsoft account/Outlook.com login or adding an account to Outlook by itself is not sufficient evidence that an Entra app has Graph access. The app must be separately registered, consented, and tested.

## Add the mailbox to Outlook for Windows

1. Open Outlook on the demo laptop. Record whether this is **new Outlook** or **classic Outlook** because the account-management menus differ.
2. New Outlook: open **Settings → Accounts → Your accounts → Add Account**, enter the test UPN, and complete Microsoft sign-in/MFA.
3. Classic Outlook: choose **File → Add Account**, enter the test UPN, choose **Connect**, complete sign-in/MFA, and finish setup.
4. Confirm the expected mailbox is shown and can receive a controlled test email. Keep Outlook delivery normal; MailTrace scanning must not block or delay mail.
5. Do not export the Outlook profile, PST/OST, or account password into the MailTrace repository.

Microsoft Support's current Outlook setup steps: [Add an email account to Outlook for Windows](https://support.microsoft.com/en-us/outlook/getstarted/add-an-email-account-to-outlook-for-windows).

## Verify the mailbox with Microsoft Graph Explorer

Use [Microsoft Graph Explorer](https://aka.ms/ge) while signed in as the test mailbox user. Prefer a non-production test tenant; Microsoft recommends a developer sandbox rather than production when trying requests that might affect tenant data. For this read-only plan, use only GET requests:

```http
GET https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName,mail
GET https://graph.microsoft.com/v1.0/me/mailFolders/inbox
GET https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=5&$select=id,subject,receivedDateTime,from,hasAttachments
```

In Graph Explorer, choose **Modify permissions** to review/consent the required permissions, then re-run the GET. Graph Explorer consent is for Graph Explorer; it does **not** consent the future MailTrace app registration. Do not test POST/PATCH/DELETE calls or alter messages in the test mailbox.

The current user endpoint is `GET /me` and requires a signed-in delegated user. Mail folder listing returns root children, not every nested folder; traverse child folders only if the demo needs them. Sources: [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0), [List mailFolders](https://learn.microsoft.com/en-us/graph/api/user-list-mailfolders?view=graph-rest-1.0), [Graph Explorer overview](https://learn.microsoft.com/en-us/graph/graph-explorer/graph-explorer-overview).

## Prepare safe demo messages

- Use synthetic messages, reserved `.test` domains, and inert links. Do not send malware, real credentials, personal data, or messages to people outside the test tenant.
- Prepare at least one benign message and one clearly marked training phishing message. Document expected verdicts independently of the message content.
- Include attachment cases only with benign test files or the documented EICAR test file if an approved scanner-validation plan exists; do not execute attachments.
- Keep demonstration mailbox scope to Inbox by default. Agree whether Junk/Deleted/Archive folders are out of scope.
- Confirm app owner, mailbox owner, SIH operator, and administrator contact before granting consent.

## Permission baseline and consent

For a full scan (body, headers, and attachment metadata/content) plus incoming-message notification and delta synchronization, the proposed delegated Graph permissions are:

- `User.Read` — show which account connected.
- `Mail.Read` — read the signed-in user's messages and attachments; create/manage message-change subscriptions.
- `offline_access` — request refresh-token capability as part of sign-in scope where applicable. Microsoft documents that delegated permission flows implicitly receive offline access; the MSAL token cache must still be protected.

No application permissions or shared-mailbox permissions are required for a single user's mailbox. See [GRAPH_PERMISSION_MATRIX.md](GRAPH_PERMISSION_MATRIX.md) for why `Mail.ReadBasic` is not enough for full analysis and why write/send/delete scopes are excluded.

Delegated `Mail.Read` is marked as not requiring admin consent in the Graph permission reference, but tenant user-consent policy, Conditional Access, risky-app policy, or administrator settings can still require admin approval. A tenant administrator may grant consent or enable a user admin-consent request workflow. Do not bypass the tenant's consent controls.

## Environment is not yet configured

This repository has no verified tenant ID, test mailbox identity, Entra Application (client) ID, redirect URI, or consent receipt. Those values must come from the mailbox/tenant owner. Keep them out of source control. The docs define a target configuration; they do not prove the mailbox or permission state exists.

