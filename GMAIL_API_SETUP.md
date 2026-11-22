# Gmail API Setup for MailTrace SIH

**Status (2026-11-20):** Phase 1A readonly Gmail API client is implemented, and the user reports successful real OAuth/profile/Inbox/metadata checks. Phase 1B local watch/history/poll/pull/checkpoint code is implemented and mock-tested. Cloud Pub/Sub resources and live automatic detection have not been verified.

## Test Gmail mailbox

Use one dedicated test Gmail mailbox that the demo operator controls. It may be a Google Workspace mailbox or a consumer Gmail account; it must be able to receive real emails and grant this desktop OAuth client the `https://www.googleapis.com/auth/gmail.readonly` scope. Do not use a personal/production mailbox containing private correspondence. Prepare only synthetic benign and training messages addressed to the test account.

For a Google Workspace account, the Workspace administrator must allow the OAuth app/scope under the organization's app access controls. For an external OAuth app in Testing status, add the Gmail test account under the OAuth audience's test users; the user will see an unverified/test warning where applicable. Gmail read scope is classified as **restricted** by Google. A public app using it may require OAuth verification; storing/transmitting restricted-scope user data can invoke additional security assessment requirements. This matters before any distribution beyond a controlled demo. See Google's [Gmail scope classification](https://developers.google.com/workspace/gmail/api/auth/scopes) and [OAuth verification guidance](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).

## Create a Google Cloud project and enable APIs

1. Sign in to [Google Cloud Console](https://console.cloud.google.com/) with an account allowed to configure the SIH project.
2. Create or select a dedicated project, record the exact project ID, and enable **Gmail API** and **Cloud Pub/Sub API**.
3. Configure the OAuth consent screen / Google Auth Platform branding and audience. Use External only for consumer Gmail or accounts outside the owning Workspace; use Internal only when every allowed account is in that Workspace organization.
4. During development, add the demo Gmail account as a test user. Review app verification/test-user limits and token lifetime before scheduling a long live demonstration.
5. Create an OAuth client ID of type **Desktop app**. Save the downloaded `credentials.json` outside the repository in an access-controlled local configuration directory. Do not commit or attach it to support bundles.
6. Configure the only requested Gmail scope as `https://www.googleapis.com/auth/gmail.readonly`. Do not add Gmail send/modify/delete scopes.
7. Create a Pub/Sub topic in this same Google developer project, e.g. `projects/PROJECT_ID/topics/mailtrace-gmail-watch`.
8. Grant the Gmail API's publisher identity `gmail-api-push@system.gserviceaccount.com` the **Pub/Sub Publisher** role on that topic only.
9. Create a **pull** subscription, e.g. `projects/PROJECT_ID/subscriptions/mailtrace-gmail-agent`. Grant the Windows Agent's separate Google Cloud subscriber principal **Pub/Sub Subscriber** on that subscription only.
10. Configure the Agent with the full topic/subscription resource names and a separate Pub/Sub authentication source. Gmail OAuth user tokens and Cloud Pub/Sub subscriber credentials are separate identities and must remain separate.

For `users.watch`, the topic's project identifier must exactly match the Google developer project ID used to call the API. The Gmail push service requires Publisher on the topic. Sources: [Gmail push setup](https://developers.google.com/workspace/gmail/api/guides/push), [`users.watch`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/watch).

## Verify Gmail API manually

After OAuth consent, test only with the dedicated mailbox:

```text
users.getProfile(userId="me")
users.messages.list(userId="me", labelIds=["INBOX"], maxResults=5)
users.messages.get(userId="me", id="<returned-message-id>", format="metadata")
```

Read message body/MIME only when the implementation is ready to apply privacy policy. The `gmail.readonly` scope permits reading messages and settings, including raw message content. Do not use API Playground or console tools against a production mailbox.

## Manual live-test checklist

- [ ] Test Gmail mailbox exists and can receive a real email.
- [ ] Gmail API and Cloud Pub/Sub API are enabled in the same Google developer project.
- [ ] OAuth Desktop client exists; correct account is included in test users if the app is Testing.
- [ ] Workspace policy permits this client and the restricted read-only scope.
- [ ] Pub/Sub topic has Gmail publisher permission.
- [ ] Pull subscription exists and the Agent identity has subscriber permission.
- [ ] `users.watch` returns history ID and expiration; initial notification is received by pull subscriber.
- [ ] Send a real email to the connected mailbox and verify history/list/get using the actual account.

Until a valid Desktop OAuth credentials file is available at the configured external path, OAuth succeeds, and a live message is retrieved, live Gmail connectivity is **not configured or verified**. Automatic detection remains unimplemented.

# Readiness

The API client is implemented but not connected to a live account. A real dedicated Gmail mailbox, a valid Desktop OAuth file at the configured external path, user consent, and configured Google OAuth project are prerequisites for a credentialed integration test. Pub/Sub setup is a later phase.

