# Gmail Push and Google Cloud Pub/Sub Setup

Primary event path: Gmail `users.watch` → Google Cloud Pub/Sub topic → pull subscription → Windows Agent. No publicly exposed local webhook is required. Gmail's `historyId` is a cursor hint; it is not a message ID, message body, or complete event list.

## Cloud resources and IAM

1. Select one dedicated Google Cloud project and enable Gmail API and Cloud Pub/Sub API. The project ID in `topicName` must match the project associated with the Gmail API OAuth client making the `watch` call.
2. Create topic `projects/PROJECT_ID/topics/mailtrace-gmail-watch`.
3. On that topic, grant `gmail-api-push@system.gserviceaccount.com` **roles/pubsub.publisher** (Gmail requires publish permission). Apply the binding at topic scope, not project-wide.
4. Create pull subscription `projects/PROJECT_ID/subscriptions/mailtrace-gmail-agent` attached to that topic.
5. Give the Agent's Google Cloud principal **roles/pubsub.subscriber** on that subscription only. Use separate credentials/ADC from Gmail user OAuth.
6. Configure retries/ack deadline and backlog monitoring. Pub/Sub is at-least-once by default and has no ordering guarantee; implement application idempotency even if exactly-once delivery is enabled.

Google's service identity and topic grant are documented in [Gmail push setup](https://developers.google.com/workspace/gmail/api/guides/push). Pull delivery and subscriber acknowledgements are described in [Pub/Sub pull subscriptions](https://cloud.google.com/pubsub/docs/pull) and [subscription semantics](https://cloud.google.com/pubsub/docs/subscription-overview).

## Gmail watch

After successful user OAuth and verified topic configuration, call:

```http
POST https://gmail.googleapis.com/gmail/v1/users/me/watch
Authorization: Bearer <read-only Gmail OAuth access token>
Content-Type: application/json

{
  "topicName": "projects/PROJECT_ID/topics/mailtrace-gmail-watch",
  "labelIds": ["INBOX"],
  "labelFilterBehavior": "INCLUDE"
}
```

Record the returned `historyId` as a synchronization baseline and `expiration` as a UTC timestamp. A successful `watch` immediately causes an initial notification. Do not interpret that initial notification as a new email. Run the shared history sync from the last committed cursor to discover actual `messagesAdded` events.

## Pull processing and durable acknowledgment

1. Pull a Pub/Sub envelope; base64url-decode `message.data` with strict input limits and parse `emailAddress` and `historyId` only.
2. Verify the mailbox identity matches the connected account. Do not log the full payload or token.
3. Treat Pub/Sub message ID as transport dedupe metadata and notification `historyId` as a wake-up watermark only. A notification can duplicate, arrive late/out of order, or be dropped upstream.
4. Call the common sync engine from its **last committed** Gmail `historyId`. Page through `users.history.list` and collect only `messagesAdded[].message.id` for the Inbox. History entries commonly include only IDs/thread IDs.
5. In one local durable transaction, record unique opaque Gmail message IDs as pending sync-work references and advance the history cursor only after every history page in that batch is committed. Phase 1B does not yet analyze those references.
6. Acknowledge the Pub/Sub delivery only after that transaction commits. If the sync/API/DB step fails, do not ack (or release/nack using the client library) so Pub/Sub can retry. Extend the ack deadline for longer sync work. A pending durable work row allows restart recovery after acknowledgment.
7. A future analysis worker may fetch content only under the approved privacy policy, then record terminal scan status/idempotency. That worker is outside Phase 1B. Duplicate notification/history events resolve to the existing message-ID row.

The notification contains the mailbox email and a new history ID; actual changes come from `history.list`. Gmail notifications are limited to one event per second per user and may be dropped/delayed, so polling remains mandatory. See [Gmail push reliability](https://developers.google.com/workspace/gmail/api/guides/push).

## Watch lifecycle

Gmail watch expires. Gmail documentation says call `watch` at least every seven days and recommends daily renewal. Renew once per day with jitter and a safety margin (for example, attempt when fewer than 48 hours remain); store last successful renewal, returned expiration, renewal error category, and watch status without message content. If renewal fails, preserve the last known cursor, back off for transient errors, keep history polling active, and retry. After OAuth reconnect or watch recovery, call `watch` again and synchronize from the durable cursor.

## Polling fallback and expired history

An independent timer calls the same sync engine, even when Pub/Sub is healthy. It handles missed notifications, network interruption, watch expiration, and backlog reconciliation. Use a configurable interval, jitter, exponential backoff with `Retry-After`/quota handling, and one serialized sync lease per mailbox.

Gmail history IDs are not contiguous. `users.history.list(startHistoryId=...)` can return HTTP 404 when the cursor is invalid/too old (often valid at least a week, sometimes only hours). On 404, do not rescan the entire mailbox. Establish a fresh watch/baseline, enumerate a bounded Inbox result set (maximum configured item count) with a coarse `newer_than:Nd` search and transiently inspect metadata timestamps to enforce the exact configured recovery-hours cutoff, dedupe through opaque message IDs, then query history from the watch baseline to cover changes during that bounded recovery. Expose recovery/coverage status in diagnostics.

Sources: [Gmail History API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list), [Gmail sync strategies](https://developers.google.com/workspace/gmail/api/guides/sync), [`users.watch`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/watch).

# Phase 1B implementation status (2026-11-20)

Local Phase 1B code includes Inbox watch calls, a shared History synchronization engine, bounded expired-cursor recovery, Pub/Sub pull, SQLite cursor/message-ID persistence, and a foreground Agent runner. The user reports the project/topic/subscription and Gmail Watch are configured; read-only subscription validation and an immediate empty pull previously succeeded. This notification-validation fix is mocked-test verified only; the pending integer notification has not been processed or acknowledged, and a newly delivered email has not been verified end to end. Automatic detection is therefore **not yet live-verified**.

Install backend dependencies, then set `MAILTRACE_GMAIL_GCP_PROJECT`, `MAILTRACE_GMAIL_PUBSUB_TOPIC`, `MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION`; ADC must be configured separately for the Agent's Windows user. Run from `backend` with `python -m services.gmail_connector.agent`. This runs in the foreground only; Windows service/auto-start registration is not part of Phase 1B. Checkpoint path defaults to `%LOCALAPPDATA%\MailTrace\gmail\sync.sqlite3` and may be overridden with `MAILTRACE_GMAIL_STATE_PATH`.

For setup of another project, the manual steps are:

1. In Google Cloud Console select the exact project used for the Gmail API OAuth app and enable **Gmail API** and **Cloud Pub/Sub API** (or run `gcloud services enable gmail.googleapis.com pubsub.googleapis.com --project=PROJECT_ID`).
2. Create topic `mailtrace-gmail-watch`: `gcloud pubsub topics create mailtrace-gmail-watch --project=PROJECT_ID`.
3. Grant Gmail's publisher identity the topic-level role: `gcloud pubsub topics add-iam-policy-binding mailtrace-gmail-watch --project=PROJECT_ID --member=serviceAccount:gmail-api-push@system.gserviceaccount.com --role=roles/pubsub.publisher`.
4. Create the pull subscription: `gcloud pubsub subscriptions create mailtrace-gmail-agent --project=PROJECT_ID --topic=mailtrace-gmail-watch`.
5. Configure ADC as the Windows user who runs the Agent (`gcloud auth application-default login` for a local demo, or an approved service identity). Grant that principal `roles/pubsub.subscriber` on the subscription only: `gcloud pubsub subscriptions add-iam-policy-binding mailtrace-gmail-agent --project=PROJECT_ID --member=user:YOUR_GOOGLE_ACCOUNT --role=roles/pubsub.subscriber`. For service accounts use `serviceAccount:NAME@PROJECT_ID.iam.gserviceaccount.com`. Keep this identity separate from Gmail OAuth tokens.
6. Set `MAILTRACE_GMAIL_GCP_PROJECT=PROJECT_ID`, `MAILTRACE_GMAIL_PUBSUB_TOPIC=projects/PROJECT_ID/topics/mailtrace-gmail-watch`, and `MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION=projects/PROJECT_ID/subscriptions/mailtrace-gmail-agent`. Optionally tune `MAILTRACE_GMAIL_POLL_SECONDS`, `MAILTRACE_GMAIL_WATCH_RENEW_BEFORE_SECONDS`, `MAILTRACE_GMAIL_RECOVERY_WINDOW_HOURS`, and `MAILTRACE_GMAIL_RECOVERY_MAX_MESSAGES`.
7. From `backend`, install dependencies (`python -m pip install -r requirements.txt`), complete Gmail Desktop OAuth separately using the existing readonly connector, run `python -m services.gmail_connector.agent --diagnostics`, then start `python -m services.gmail_connector.agent`. Send a real email to the connected mailbox to perform E2E verification.

Do not claim Pub/Sub or real-time detection works until the subscription validation, `users.watch`, actual delivered Pub/Sub message, History API retrieval, and newly delivered real email have all succeeded. No public local webhook is used.

## One-shot notification verification

The following manual command handles at most one pending Pub/Sub delivery. It requires an existing durable Gmail history checkpoint and will refuse to register a watch if one is missing. An empty pull reports `EMPTY` and acknowledges nothing. A valid notification syncs History from the stored cursor and acknowledges only after the message references and cursor commit. A malformed or wrong-mailbox notification is durably recorded by category before its delivery is acknowledged. A synchronization failure leaves the delivery unacknowledged for redelivery. Output contains only status and counts.

Run only when the next delivery on this dedicated subscription is intended for MailTrace; do not run while unrelated publishers may be writing to it. From PowerShell:

```powershell
$env:MAILTRACE_GMAIL_GCP_PROJECT = "clear-eye-515310-g2"
$env:MAILTRACE_GMAIL_PUBSUB_TOPIC = "projects/clear-eye-515310-g2/topics/mailtrace-gmail-events"
$env:MAILTRACE_GMAIL_PUBSUB_SUBSCRIPTION = "projects/clear-eye-515310-g2/subscriptions/mailtrace-gmail-pull"
Set-Location "<repo-root>\backend"
.\venv\Scripts\python.exe -m services.gmail_connector.agent --verify-once
```

This command was not run during the history-ID validation fix. It does not start the continuous Agent or register/renew Gmail Watch.


## Phase 1B operational-hardening verification (2026-11-20)

The current repository implementation includes a foreground continuous Agent loop, bounded Pub/Sub pull, periodic Gmail History polling through the same serialized cursor engine, watch renewal checks before the configured expiry safety window, reconnect handling, exponential retry backoff, signal-driven clean exit, and durable SQLite cursor/message-reference state. Detected message references remain `DETECTED` until a later processing milestone; Phase 1B does not fetch message bodies or run threat analysis.

Validation performed for this closure review:

- Focused Gmail connector and Agent suites: `50 passed, 0 failed`.
- Python compilation of `services/gmail_connector`: passed.
- Foreground Agent real-credential one-cycle run (`run_agent(stop_after=1)`): completed and closed the subscriber cleanly.
- Real Pub/Sub one-shot verification: `SYNCED_AND_ACKED`, one delivery pulled, two new opaque message references committed, one delivery acknowledged.
- Post-run diagnostics: Gmail authorization/API/Pub/Sub connected, health `HEALTHY`, coverage `COMPLETE`, failed sync count `0`.
- Reopened the configured SQLite store in a fresh `SyncStore` instance: durable history checkpoint and pending-reference count survived restart. Three references remain pending for the later analysis/processing milestone.

Limitations / operator requirements:

- The Agent is foreground-only. Start it manually in the intended Windows user session with `python -m services.gmail_connector.agent`; it is not currently running continuously after this validation and no Windows service/task/auto-start was installed.
- The currently registered Gmail Watch had ample remaining lifetime, so a real cloud-side renewal was not forced solely for testing. Renewal scheduling and safety-window behavior are covered by automated tests; the next actual renewal must be observed during normal operation.
- Restart durability of the cursor and pending references was verified. The pending references are intentionally not consumed in Phase 1B; their analysis/terminal state worker is a separate milestone.
- No email body, subject, attachment, or full message was fetched during this operational-hardening verification.

Phase 1B status: **core ingestion and foreground operational lifecycle implemented; focused tests and live Pub/Sub ingestion passed.** Continuous unattended operation still requires the operator to keep the foreground process running. Windows service/auto-start packaging is intentionally out of scope.
