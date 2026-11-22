# MailTrace AI Gmail Integration — Security and Privacy Audit

**Review type:** design/source inspection and mocked Phase 1A code review on 2026-11-20. No live Google OAuth or Gmail/Pub/Sub connection was exercised. This is not an OAuth verification, penetration test, or production security certification.

## Current state

- Existing SOC has API-key/OIDC controls, case/tenant guards, evidence custody/integrity and retention code. Its analysis route persists `analysis_json`; in development without encryption key configured, protected-field helper may store plaintext.
- Phase 1A now includes a standalone read-only Gmail connector at `backend/services/gmail_connector/`: Desktop OAuth/PKCE, Windows DPAPI CurrentUser token storage, refresh/reconnect/logout, and profile/list/get REST methods. Mocked tests pass, including an actual synthetic-data Windows DPAPI round-trip.
- The configured external Desktop OAuth credentials file was absent when checked; its JSON was not inspected or validated. No user consent, live token, or Gmail API connectivity has been tested. Google auth/API packages are absent, but the implementation currently uses the Python standard library and adds no such dependency.
- Pub/Sub pull subscriber, Gmail watch lifecycle, separate User Backend, automatic detection and Windows Agent still do not exist. `.NET` SDK is not installed in this environment, so a Windows Worker Service cannot be built or run here.
- `backend/main.py` is not an acceptable SAFE/LOW Gmail ingestion endpoint because its current analysis path persists investigations/evidence. A user-side analysis wrapper must be isolated from those persistence hooks.

## Google scope and consent risks

The required `gmail.readonly` scope is classified as **restricted**. It can read Gmail message content and settings. A real distributed/production OAuth app may require Google's restricted-scope verification and, where restricted data is stored/transmitted through a server, a security assessment. Testing mode has test-user limits and refresh tokens for external apps expire after seven days for scopes beyond basic identity. Workspace administrators can block/untrust the app. These conditions can interrupt live operation even if a test consent initially succeeds.

Mitigations: single demo mailbox, minimal `gmail.readonly` scope, no send/modify/delete permission, OAuth Desktop public client, test-user allowlist, clear user consent, controlled project, visible auth state and reconnect flow, and pre-demo verification of refresh-token/publishing status.

Sources: [Gmail scope classifications](https://developers.google.com/workspace/gmail/api/auth/scopes), [Google OAuth token/testing behavior](https://developers.google.com/identity/protocols/oauth2), [restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).

## Pub/Sub and checkpoint risks

Gmail notifications contain mailbox email and history ID, not complete messages. They can be duplicated, delayed, reordered, or dropped (Gmail documents a maximum notification rate of one per second per watched user). Pub/Sub defaults to at-least-once delivery without ordering. Incorrectly acknowledging before durable sync recording can lose work; blindly retrying can duplicate scans.

Mitigations: topic-only `roles/pubsub.publisher` for `gmail-api-push@system.gserviceaccount.com`; subscription-only `roles/pubsub.subscriber` for the Agent; separate Cloud credentials from user Gmail OAuth; decode/validate bounded notification JSON; mailbox binding; single per-mailbox sync lock; unique opaque message ID jobs; atomic history checkpoint + job insert; ack only after transaction commit; dead-letter/quarantine metadata must exclude email body; continuous History API poll and recovery alerting.

Gmail `historyId` can expire and `history.list` may return 404, sometimes after a short period. A blind full mailbox rescan risks broad content access, duplicate work and excessive data retention.

Mitigations: bounded/configured recovery horizon and max message count; create a new watch baseline; dedupe, reconcile from baseline; show incomplete coverage instead of claiming full recovery; require explicit operator choice before widening backfill.

## Token and Windows Agent risks

The desktop OAuth client is a public client. `credentials.json` contains app configuration and must not be committed. Refresh tokens are long-lived access credentials. A Windows service under `LocalSystem` cannot be assumed to access a DPAPI CurrentUser or Credential Manager entry created by the interactive user. Pub/Sub key JSON can independently compromise the cloud subscription if exposed.

Mitigations: DPAPI CurrentUser/Windows Credential Manager; same Windows identity/profile for authorization and Agent; no plaintext fallback; restrict cache ACL; never log auth codes/tokens/headers; clear/reconnect on `invalid_grant`; separate least-privilege ADC for Pub/Sub; prefer federation/managed identity where feasible; if a service-account key is required locally, store outside repo, ACL-protect, scope subscription role only, rotate and delete after demo; document service logon identity and test token recovery after restart.

## Email-content privacy risks

Existing parser and enrichment code may perform DNS/reputation lookups and SOC persistence. SAFE/LOW content must not enter logs, exception reports, temp files, database rows, queues, browser storage, backups, external AI services, or the SOC webhook. Pub/Sub's message should remain a small synchronization hint. Message IDs are sensitive correlators and still need a retention bound.

Mitigations: shared analysis adapter with explicit side-effect policy; in-memory only content path for SAFE/LOW; bounded fetch/read; disable external enrichment that sends message-derived identifiers until tier policy authorizes it; redact errors; persist only a keyed mailbox identity, opaque message ID, cursor and job status with short TTL; no content in diagnostic endpoints; HIGH/CRITICAL only in approved encrypted evidence store; CRITICAL transfer only after policy authorization and evidence encryption/integrity checks.

Existing sensitive-field AES-GCM encryption is configuration-dependent and does not make the current database a safe default for SAFE/LOW email. Do not share the SOC database or its evidence vault with the user backend without an explicit privacy design.

## Risk-status and SOC acknowledgment integrity

The existing risk system distinguishes model probability, confidence, evidence completeness and unified score. Gmail integration must use the existing canonical validated score, expose unavailable checks, and avoid assigning an invented SAFE/LOW verdict when analysis is incomplete. A local HTTP `2xx` only confirms transport response; it does not prove SOC case creation or analyst acknowledgment.

Mitigations: persist scan statuses `PENDING/ANALYZING/ANALYZED/PARTIAL/UNAVAILABLE/FAILED`; do not map unavailable to benign; preserve actual delivery timestamp from Gmail separately from local detection/scan timestamps; use idempotency key for transfer; record transfer initiated/received, evidence verified, case ID, and analyst acknowledgment as separate verified events.

## Required validation before live use

- Static/unit tests for parser, cursor transactions, Pub/Sub envelope validation, deduplication, privacy and authorization expiry.
- Restart/recovery tests for pending sync work, watch renewal and invalid history.
- Real dedicated Gmail/Google Cloud test: deliver a real message, observe Pub/Sub pull, retrieve actual Gmail history/message, run actual analysis, and prove no SAFE content persistence.
- CRITICAL test with authorized evidence transfer and actual Central SOC receipt/case; verify analyst acknowledgment independently.
- Confirm token cache uses intended Windows account and survives service restart; verify revocation stops processing.

No such Gmail test ran in this documentation update.

