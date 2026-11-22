# Phase 1C — Metadata-Only Gmail Reference Worker

## Scope and boundary

Phase 1C consumes only opaque Gmail message references already committed by the Phase 1B synchronization engine. It does not call Gmail `messages.get`, fetch MIME, bodies, attachments, or attachment bytes, invoke either email parser, perform threat analysis or external lookups, assign SAFE/LOW/MODERATE/HIGH/CRITICAL, quarantine evidence, or transfer data to Central SOC. Content processing and all later analysis stages remain out of scope.

The worker accepts the existing `SyncStore` only. It has no Gmail client, parser, threat-intelligence, analysis-engine, frontend, or SOC dependency. A successful completion means the reference lifecycle step completed; it does not mean the email was scanned or found safe.

## Durable work lifecycle

The existing `gmail_detected_messages` table remains the only queue and its unique `message_id` remains the deduplication key. Existing `DETECTED` rows migrate to `PENDING`. The metadata-only states are:

```text
PENDING → PROCESSING → COMPLETED
              ├──────→ RETRY_PENDING → PROCESSING
              └──────→ FAILED
```

`POLICY_BLOCKED` is intentionally not used: this phase does not evaluate email content or assign policy outcomes. Claims use SQLite `BEGIN IMMEDIATE`, a bounded batch, a processing timestamp lease, and an attempt counter. Expired claims become retryable; attempts are capped. Retry delay is exponential and capped. Permanent validation/type failures transition directly to `FAILED`; other worker failures retry until the attempt limit. State transitions commit transactionally. A unique primary key prevents duplicate jobs. SQLite WAL and FULL synchronous mode continue to provide durable local state.

On graceful stop, unprocessed references from the claimed batch are released to `RETRY_PENDING` immediately. On process crash, stale `PROCESSING` rows return to retry through lease recovery. The foreground agent lifecycle remains separate; no Windows service or auto-start was added.

## Stored data and diagnostics

Only the existing opaque message ID, discovery metadata and worker lifecycle metadata are stored. No email content, subject, sender, headers, MIME, attachment data, Pub/Sub payload, OAuth tokens, or analysis result is added to the table. Worker logs contain only fixed safe messages and exception class categories, never message IDs or exception text.

## Verification boundary

Unit tests use local SQLite and failure injection. The focused run passed **64 tests** across the Phase 1C worker and Phase 1A/1B Gmail regression suites; Python compilation passed for the worker, store, and worker tests. Tests cover state transitions, idempotency, bounded/concurrent claims, retry exhaustion, stale-lease recovery, restart durability, graceful stop, DB rollback, and absence of content retrieval dependencies/schema fields. They do not verify live Gmail processing; this phase makes no Gmail content request.
