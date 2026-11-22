# MailTrace AI — Gmail SIH Implementation Plan

**Status (2026-11-21):** Phase 1A/1B live-verification details remain historical/user-reported claims, not reverified by Phase 2B. Phase 1C remains metadata-only. Phase 2B synthetic-only analysis, independent auth verification, sanitized report persistence, SOC integration, retrieval, and bounded retry are implemented and regression-tested. Gmail body/MIME/attachment acquisition and analysis remain blocked. Phase 3 has not begun.

**Historical Phase 2A.2 readiness decision:** synthetic-only Phase 2B was **READY WITH RESTRICTIONS** pending explicit approval; approval was later granted and the restricted implementation is recorded below. Gmail content analysis remains **BLOCKED**. See [PHASE_2A_2_PROTOTYPE_READINESS.md](PHASE_2A_2_PROTOTYPE_READINESS.md) for the audit record.

## Current confirmed state

- Existing Central SOC backend is FastAPI at port **8002**; preserve its routes, auth, database, case assignment, SLA, investigation and evidence workflows.
- Confirmed supported SOC frontend port is **5503**: `START_MAILTRACE.ps1` sets it and README documents it. CORS already allows both 5503 and 5504, but changing the port later requires updating launcher/docs and the offline prompt; no port/config changes were made. SIH recommendation: adopt 5504 only in an approved later change.
- `backend/main.py` also has a legacy `if __name__ == "__main__"` entry point configured for 8000. Do not invoke it; normal README/launcher path uses 8002. Port 8000 was not used or changed.
- Proposed User Backend port **8100** had no listener at the time checked.
- Phase 1A connector code exists at `backend/services/gmail_connector/`: desktop OAuth + PKCE, DPAPI CurrentUser token cache, refresh/reconnect/revocation handling, profile/list/get Gmail REST calls and pagination. User confirmed real readonly authorization, profile, Inbox and metadata retrieval; the original 16 mocked tests passed.
- The external OAuth credentials and DPAPI token are never copied into the repository. Pub/Sub resources/ADC are absent in this environment. The Google Cloud client is added as a pinned backend dependency but was not installed or exercised here. No real Pub/Sub notification or new-email E2E test has run.
- Targeted pytest diagnosis is documented in `PHASE_0_1_VALIDATION.md`: with the backend venv, the isolated tenant test blocks while AnyIO starts TestClient's portal at `socket.socketpair`; no route assertion runs. The initial attempt with system Python could not import `tldextract`; pytest's default `.pytest-tmp` is inaccessible in this environment. Full suite remains unverified.
- The existing analysis/upload path persists `analysis_json`; SAFE/LOW Gmail messages must not flow through that persistence path.

## Phase 1C — Metadata-only durable reference worker

- Consume opaque IDs from the existing `gmail_detected_messages` table; do not create a second queue.
- Preserve `message_id` primary-key deduplication and add transactional lifecycle state, bounded batch claiming, attempt counter, lease recovery, capped exponential retry, and terminal failure.
- Migrate legacy `DETECTED` rows to `PENDING`; supported states are `PENDING`, `PROCESSING`, `RETRY_PENDING`, `COMPLETED`, and `FAILED`.
- The worker has no Gmail client or parser dependency. It must never call `messages.get`, fetch MIME/body/attachments, invoke the existing parsers, run external lookups, assign threat tiers, quarantine evidence, or transfer to Central SOC.
- `COMPLETED` records only completion of metadata-only reference handling, not email scanning or a safe verdict. No `POLICY_BLOCKED` or SAFE/HIGH/CRITICAL status is inferred.
- Refer to [PHASE_1C_WORKER.md](PHASE_1C_WORKER.md) for behavior and verification boundary. Threat analysis/content preparation remains future approved work.

## Phase 2A.1 — Privacy policy finalization (documentation complete; controls not implemented)

- **APPROVED:** Gmail metadata-only synchronization. Do not fetch body, full MIME, attachment names or bytes; do not execute Gmail content analysis.
- **APPROVED:** store message ID only as required; thread ID only if necessary; internal date may be stored; sender/recipient only for documented need with encryption and restricted access; never persist subject, full headers, body, attachment names or bytes.
- **VERIFIED (source inspection only):** Phase 1B/1C SQLite stores the opaque Gmail resource ID and worker lifecycle metadata. It does not store internal date, sender or recipient. The current Phase 1A metadata getter requests `From`, `To`, `Date`, RFC `Message-ID` and `Authentication-Results`; correction/field-level enforcement is **NOT IMPLEMENTED**.
- **PROPOSED / PENDING APPROVAL:** AES-256-GCM envelope encryption, OS-protected key storage separate from SQLite, key recovery/rotation, decryption authorization, access audit, retention periods and external-service data allowlists. Existing SOC AES-GCM helpers are conditional and are not verified as Gmail storage encryption.
- **APPROVED:** no external service calls in Phase 2A.1; missing authorization, keys, tenant ownership or privacy controls must fail closed.
- **PENDING APPROVAL:** SAFE/HIGH/CRITICAL evidence criteria and thresholds; `INDETERMINATE / ANALYSIS_INCOMPLETE` must remain distinct from SAFE. No final numeric risk thresholds are set.
- **BLOCKED:** content acquisition remains disallowed unless a later static design proves attachment-byte exclusion and receives separate explicit approval. No Gmail content was fetched or analyzed in Phase 2A.1.
- Exact decisions, proposed retention values and code-verification caveats: [PHASE_2A_1_PRIVACY_POLICY.md](PHASE_2A_1_PRIVACY_POLICY.md).

## Phase 1A — Local Gmail OAuth/API connector (implemented; user-reported live verification complete)

- Gmail API is the chosen provider; Microsoft Graph/Outlook plans are superseded by the Gmail docs.
- Implemented Desktop Application OAuth code flow with PKCE S256 and exact `gmail.readonly` scope, callback state check, and secure token exchange.
- Implemented Windows DPAPI CurrentUser encrypted token persistence at `%LOCALAPPDATA%\\MailTrace\\gmail\\oauth.dpapi`; no plaintext fallback. OAuth client configuration is read only from the configured external path `C:\\Users\\ritur\\AppData\\Local\\mailtrace\\secrets\\credentials.json`.
- Implemented refresh, invalid-grant/revocation handling, reconnect status, explicit logout/revoke, Gmail profile, Inbox list with pagination, and metadata-default message retrieval. Error messages omit response bodies and token data.
- Added 16 mocked tests. User reports successful real readonly OAuth, profile, Inbox metadata page, and selected metadata-only retrieval.
- User confirmed browser OAuth callback completion. No credentials/token/email data is recorded in this plan.

## Phase 1B — Push and continuous synchronization (local implementation complete; cloud verification blocked)

- Implemented: Inbox `users.watch`, lazy Pub/Sub pull adapter with subscription/topic validation, one serialized History engine shared by Pub/Sub/poll, duplicate message ID prevention, durable cursor and pending opaque-ID records, bounded expired-cursor recovery, watch renewal, and foreground Agent restart recovery.
- Implemented tests use fakes/mocks only. The Agent stores no message body, subject, sender, raw headers, attachment bytes, or Pub/Sub payload.
- Not implemented in Phase 1B: analysis engine invocation, scanning pipeline, User Backend/dashboard, Windows notifications/service auto-start, and Central SOC evidence transfer.
- Manual Cloud prerequisites for that phase include same-project Gmail/Pub/Sub APIs, topic publisher identity, pull subscription and a least-privilege Agent subscriber identity.

## Manual prerequisites before live Phase 1B verification

1. Dedicated Gmail test mailbox that can receive real messages.
2. Google Cloud project with Gmail API and Pub/Sub API enabled, exact project ID recorded.
3. Desktop OAuth client file at the configured external path, OAuth audience/test-user configuration, and approved `gmail.readonly` consent. For restricted scope, resolve Workspace admin policy and Google's testing/verification implications.
4. Pub/Sub topic and pull subscription created.
5. Topic-level `roles/pubsub.publisher` for `gmail-api-push@system.gserviceaccount.com`.
6. Subscription-level `roles/pubsub.subscriber` for the Agent's separate Cloud identity.
7. Choose the Windows user that runs the foreground Agent so DPAPI and Pub/Sub ADC resolve under the same account.

## Phase 2B — Synthetic threat-analysis prototype (complete; restricted)

- **IMPLEMENTED:** local `.eml` endpoint at `/api/synthetic-analysis`; bounded parser adapter, single-part text input gate, local phishing/link heuristics, structured auth states, IOC extraction, sanitized report, and prototype-only evidence weights.
- **IMPLEMENTED:** sanitized report persistence under tenant/owner scope, idempotency-key digest, authenticated report retrieval, and bounded SOC delivery retries using existing investigation/case/alert functions. Raw `.eml`, subject, body, full headers, and attachment data are never stored.
- **IMPLEMENTED:** injectable bounded TXT DNS checks, `dkimpy` signature verification, DMARC policy/alignment evaluation, and explicit PASS/FAIL/NONE/UNAVAILABLE/INVALID states. Authentication-Results remains untrusted. SPF message PASS requires trusted SMTP ingress facts and is unavailable for `.eml` uploads that lack them.
- **NOT IMPLEMENTED:** Gmail/Phase 1C integration, external reputation services, attachment scanning, evidence vault, and SOC evidence transfer. The broad `parse_email` orchestrator is not used.
- **IMPLEMENTED:** versioned score weights/cutoffs are isolated in an injectable policy object, so unit tests can verify alternate configurations without changing SOC scoring.
- **TESTED:** see [PHASE_2B_TEST_REPORT.md](PHASE_2B_TEST_REPORT.md) and [PHASE_2B_COMPLETION_REPORT.md](PHASE_2B_COMPLETION_REPORT.md) for focused auth/persistence/SOC tests, the native-Windows full offline backend suite, compilation, and diff validation.
- **LIMITATION:** SPF cannot be authenticated from a standalone EML without trusted SMTP client IP/HELO/MAIL FROM; policy DNS lookup remains separately visible. Authentication and prototype scores are not calibrated probabilities. Do not use the outcomes for automatic mail actions.
- **BLOCKED:** Gmail content processing remains prohibited. This implementation is synthetic-only and is not connected to Phase 1C.

See [PHASE_2B_THREAT_ANALYSIS_ENGINE.md](PHASE_2B_THREAT_ANALYSIS_ENGINE.md) for the data flow, reused modules, policy weights, endpoint, privacy controls and limitations.

## Shared analysis boundary (future; BLOCKED pending separate approval)

- Extract a side-effect-free message-analysis contract around the existing parser, forensics, URL/IP/domain/TI/attachment/ML/risk services.
- Preserve existing SOC endpoint contracts by adapting them to the shared analysis service without altering their persistence behavior.
- Create a separate in-memory user-side invocation; SAFE/LOW must not call `save_investigation`, evidence custody, SOC webhook, or raw-content logging.
- Make DNS/provider lookups explicit, bounded and policy-gated. Report unavailable checks instead of inventing results.
- Add privacy tests proving SAFE content does not appear in SQLite, files, logs, queues, browser storage or SOC requests.

## Phase 3 — User Backend and dashboard (future; BLOCKED pending separate approval)

- Add independent FastAPI User Backend on port 8100 with separate database and local-only binding.
- Persist minimal opaque mailbox/message IDs, history cursor, watch diagnostics, scan state/timestamps, risk tier, user alert and transfer status. Do not persist SAFE/LOW raw message/body/attachment/header/subject content.
- Add a local dashboard with authorization, Gmail connection state, sync/watch health, scan timestamps and actual analysis results.
- Add Windows notifications from actual completed scans; unavailable/partial checks stay explicit.

## Phase 4 — Windows service packaging and analysis handoff (future; not authorized)

- Package the current foreground Python Agent for Windows background/service auto-start with an explicit run-as identity, lifecycle/restart behavior, credential redaction, and health reporting.
- Add durable work leasing/terminal scan state and connect opaque message IDs to the approved analysis boundary.
- Keep Pub/Sub ADC separate from Gmail OAuth DPAPI tokens; no credentials in source control.

## Phase 5 — Evidence and Central SOC escalation (future; BLOCKED pending privacy/evidence approval)

- Apply SAFE/LOW/MODERATE/HIGH/CRITICAL privacy policy; no SAFE content leaves RAM.
- Preserve HIGH/CRITICAL evidence only under the approved encrypted local evidence workflow.
- For authorized CRITICAL only, send signed/idempotent evidence through the existing secure SOC transfer workflow.
- Distinguish transfer attempt, transport receipt, evidence verification, SOC case creation, and analyst acknowledgment. Do not fabricate success.

## Phase 6 — Validation and SIH rehearsal

- Unit tests with mocks for Pub/Sub envelope processing, cursor transaction, dedupe, ordering/delay, network failure, restart, token revocation, watch renewal, expired history, API rate limits and privacy.
- Existing SOC regression suites run isolated from production data.
- Live integration tests with the dedicated Gmail mailbox and configured Google Cloud project; deliver actual synthetic emails and verify real detection/analysis.
- CRITICAL end-to-end test must verify actual evidence transfer and separately observed SOC acknowledgment.
- Demonstrate actual provider delivery, Agent detection, scan start/completion, risk result and dashboard alert while Outlook/Gmail UI and dashboard can be closed.
- **Completion gate:** do not call detection operational until a real email is received and processed through the real Gmail → Pub/Sub/History → Agent → analysis → dashboard path.

## Proposed folders

```text
backend/                         # existing SOC app; preserve
shared_analysis/                 # future side-effect-free analysis contract
user_backend/                    # future local API/database, port 8100
windows_agent/                   # future Windows service packaging for Python Agent
docs/                             # Gmail provider setup/design/security/runbook
```

