# Gmail Synchronization Design

## Shared synchronization engine

**Readiness (2026-11-20):** Phase 1B provides Gmail History synchronization and the foreground Pub/Sub pull Agent. Phase 1C adds a metadata-only durable reference worker. This worker never calls `messages.get` and never fetches MIME, bodies, attachments, or attachment bytes. It does not analyze emails or transfer evidence. Live content processing is not claimed.

Pub/Sub notifications and timed polling must call the same `sync_until_current()` operation. Neither input directly creates a scan or provides message data. The durable Gmail `historyId` is the single checkpoint for the connected mailbox.

```text
Pub/Sub pull ──┐
               ├─> coalesced sync trigger ─> history.list(startHistoryId=committed cursor)
Polling timer ─┘                                  │
                                                  ├─ messagesAdded IDs (INBOX only)
                                                  ├─ unique durable scan-work rows
                                                  └─ committed response historyId
                                                       │
                                   acknowledge Pub/Sub after durable commit
                                                       │
                                    fetch message → in-memory analysis → policy
```

## Cursor and idempotency model

Store one mailbox synchronization record containing a non-reversible mailbox identity key, committed `historyId`, watch expiration, last sync/renewal, health, and status. Keep Google OAuth and Pub/Sub credentials out of this database. History IDs are ordered opaque decimal strings with gaps; never increment them or assume adjacency. Use Gmail's returned `historyId` and page token exactly as specified.

The existing `gmail_detected_messages` table is the only durable work store. Its unique `message_id` remains the idempotency key. Phase 1C stores lifecycle state, attempts, retry availability, claim timestamp, and a sanitized failure category alongside discovery metadata. Do not persist body, subject, sender, headers, MIME, attachment bytes, or Pub/Sub notification data. The separate `gmail_sync_state.history_id` remains the synchronization checkpoint.

## Notification ordering and acknowledgment

- Treat any valid notification as “sync now”; coalesce bursts and run history from the last **committed** cursor. A stale or out-of-order hint may cause an extra history query but cannot move the cursor backward.
- Validate the notification account matches the connected user. The Pub/Sub envelope's own `messageId` is transport identity, not Gmail identity.
- Page all `history.list` results before committing new `messagesAdded` jobs and the final response `historyId` atomically. Use message-specific change lists to avoid duplicate `messages[]` entries.
- Acknowledge Pub/Sub only after the work rows and cursor commit. If a crash happens after commit but before ack, replay is harmless because of unique constraints. If a crash happens before commit, Pub/Sub redelivers and the cursor has not advanced.
- Pub/Sub delivery is not globally ordered and can repeat. Gmail history is the source of truth. Exactly-once Pub/Sub is optional transport hardening, not a replacement for transaction/idempotency logic.

## Polling, backoff and reconnection

Run a configurable poll (starting default 60 seconds for a laptop demo, adjustable) even when push is healthy. Serialize with the same per-mailbox lease. On 429/quota/5xx/network errors, respect `Retry-After`, use capped exponential backoff with jitter, and keep the committed cursor unchanged. On reconnect, immediately run history sync. On invalid history ID/404, report `RESYNC_REQUIRED`, reestablish watch, and run a bounded recovery scan; never silently scan the entire mailbox.

## Phase 1C metadata-only boundary

The reference worker consumes only opaque message IDs from the existing SQLite store. It must not call `users.messages.get` in any format, fetch MIME/body/attachment bytes, invoke `parse_email_bytes` or `parse_email`, perform threat analysis or external lookups, assign a threat tier, quarantine evidence, or send evidence to Central SOC. `COMPLETED` means only that metadata-only reference handling completed. Content processing is future work requiring separate approval and privacy design.

The existing `backend/main.py` upload path persists `analysis_json` and is not used by this worker. No SAFE/LOW/HIGH/CRITICAL behavior is applied here because no email content is inspected and this phase defines no classification.

Phase 1C produces no delivery time, subject, sender, body, attachment, or threat verdict. Scan timestamps and dashboard alerts remain future work.

## History expiration recovery

History is typically available at least a week but can expire sooner. If `history.list` returns 404:

1. Keep the previous cursor for diagnostics but mark it unusable; do not repeatedly retry it.
2. Call `users.watch` to get a fresh baseline history ID and expiration.
3. Run a bounded Inbox backfill based on an explicit horizon and maximum message count, with the normal unique message constraint.
4. Call `history.list` from the new watch baseline to catch messages arriving during the backfill.
5. Commit the new cursor only after the bounded backfill and follow-up history are durably represented.
6. Expose the recovery window, coverage status, and any omitted range to the user/SOC diagnostics.

The exact time horizon and count are operational settings to agree for the SIH mailbox; a bounded resync must not be represented as complete historical mailbox coverage.

## Privacy behavior

Phase 1C does not inspect email content and does not assign SAFE/LOW/MODERATE/HIGH/CRITICAL. It stores only message-reference lifecycle metadata. Any future tier-specific retention, quarantine, or SOC transfer requires a separately approved design.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) and [EMAIL_PROVIDER_ARCHITECTURE.md](EMAIL_PROVIDER_ARCHITECTURE.md).

## Diagnostics contract

Expose authorization state, Gmail API connectivity, Pub/Sub subscription connectivity, watch expiration, last successful renewal, next expiration, last successful synchronization, last committed history ID, pending durable work count, last scan timestamp, failed synchronization count, last sanitized error category, and current recovery state. Diagnostics must not expose email body, subject, sender, headers, attachment names/bytes, OAuth tokens, Pub/Sub payload, or raw exception text.

## Required test matrix

These are implementation requirements, not tests executed by this documentation update:

- Pub/Sub notification produces a History API sync and a real message ID work item.
- Polling fallback discovers a newly added message through `users.history.list`.
- Duplicate, delayed and out-of-order notifications do not skip work or cause duplicate scans.
- Duplicate `messagesAdded` entries and retries dedupe by mailbox/message key.
- Pub/Sub ack happens after durable job/cursor commit; crash before commit causes retry; crash after commit is idempotent.
- Network interruption, quota/429, transient 5xx and reconnect preserve the cursor and recover.
- Agent restart recovers durable pending work and token cache under the configured Windows identity.
- Gmail OAuth revocation and `invalid_grant` stop requests and show reconnect-required status.
- Watch renewal occurs before expiration; renewal failure keeps polling and retries.
- Expired history ID (404) initiates bounded recovery, not uncontrolled full mailbox scan.
- SAFE content is transient and absent from DB/files/logs/browser storage/external AI/SOC payload.
- Rate-limited API errors honor `Retry-After` and backoff.
- Existing Central SOC regression tests remain green.
- Real E2E requires the dedicated Gmail mailbox, OAuth client, Pub/Sub topic/subscription, IAM grants and actual delivered message; CRITICAL requires the configured SOC evidence path and independently observed SOC receipt/acknowledgment.

