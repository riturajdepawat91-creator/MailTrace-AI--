# MailTrace AI — Phase 2A.1 Privacy Policy & Security Baseline

**Policy version:** 1.0 baseline, 2026-11-20

**Scope:** Gmail metadata synchronization and future, separately approved analysis/evidence processing.
**Implementation state:** documentation only; no application code, database, key store, Gmail content, or external service was changed or used in this phase.

## Status labels

- **APPROVED** — decision explicitly supplied by the project owner in Phase 2A.1.
- **PROPOSED** — recommended control/period not yet approved by the policy owner.
- **PENDING APPROVAL** — a decision cannot be made from the supplied authorization.
- **BLOCKED** — must not proceed until named dependency/approval is met.
- **NOT IMPLEMENTED** — source audit found no enforcing implementation; documentation is not proof of control.
- **VERIFIED** — source inspection or a prior explicitly reported test proves only the stated fact. This does not imply a security certification.

## 1. Decision summary

| Item | Status | Decision / current condition |
|---|---|---|
| Metadata-only Gmail synchronization | **APPROVED** | May continue under existing Phase 1A/1B/1C behavior and `gmail.readonly`. |
| Gmail body, full MIME, attachment acquisition | **APPROVED: PROHIBITED** | Do not fetch message body, `format=full`/`raw`, MIME payload, attachment metadata/names, or attachment bytes. No real Gmail content processing is authorized. |
| Gmail message ID | **APPROVED** | Store only as required for synchronization, deduplication and lifecycle; restrict access and never write it to ordinary logs. |
| Gmail thread ID | **APPROVED, CONDITIONAL** | Store only if an operational requirement is documented; currently no need established. |
| Gmail internal date | **APPROVED** | May store the provider's `internalDate` for operational chronology. It is not the RFC `Date` header and does not establish message authenticity. Current Gmail store does not persist it. |
| Sender/recipient addresses | **APPROVED, CONDITIONAL** | May be collected only when a documented operational requirement exists; must be authenticated-encrypted at rest and have restricted access. Current Gmail store does not collect or encrypt these fields. |
| Subject, full headers, body, attachment names/bytes | **APPROVED: PROHIBITED** | Subject and full headers must not be persisted. Body must not be fetched or persisted. Attachment names and bytes must not be fetched or persisted. |
| Gmail threat analysis/content processing | **BLOCKED** | Requires separate policy approval and a reliable attachment-exclusion acquisition design; no analysis may run on Gmail message content now. |
| Restricted metadata encryption | **PROPOSED / NOT IMPLEMENTED for Gmail** | AES-256-GCM and an OS-protected key-encryption key are proposed. No Gmail metadata encryption or key-management implementation was verified. |
| Threat outcomes and thresholds | **PENDING APPROVAL / NOT IMPLEMENTED for Gmail** | SAFE, HIGH, CRITICAL and INDETERMINATE are defined as future outcome concepts below. No numeric thresholds or executable Gmail mapping are approved. |
| External threat-intelligence disclosure | **APPROVED: DISABLED IN THIS PHASE** | No provider calls are permitted by Phase 2A.1. Future provider-specific fields and purposes remain pending approval. |

## 2. Approved metadata-minimal policy

| Data | Policy | Current source status |
|---|---|---|
| Gmail message ID | **APPROVED:** store only while needed for synchronization, idempotency and job state; restrict DB/file access and do not log. | **VERIFIED:** Phase 1B/1C SQLite stores `message_id` as the primary key in `gmail_detected_messages`. It is not encrypted in this table. The project-approved policy permits this minimal operational reference; no broader use is approved. |
| Thread ID | **APPROVED, CONDITIONAL:** store only with documented operational need. | **VERIFIED:** list API can return `threadId`; the sync store does not store it. No operational requirement established. |
| Internal date | **APPROVED:** may store Gmail `internalDate` for chronology only. | **NOT IMPLEMENTED:** current sync store has no internal-date field and Phase 1C does not retrieve message metadata. Future implementation must use Gmail's provider timestamp, not trust the message `Date` header. |
| Sender address | **APPROVED, CONDITIONAL:** collect only if operationally necessary; encrypt at rest; restricted read/decrypt authorization; delete per approved retention. | **NOT IMPLEMENTED:** not stored by Phase 1B/1C. The existing metadata client selects `From`, but this phase made no Gmail API call and did not change that client. |
| Recipient address | **APPROVED, CONDITIONAL:** same controls as sender. | **NOT IMPLEMENTED:** not stored by Phase 1B/1C. The metadata client selects `To`; no API call was made here. |
| Subject | **APPROVED: DO NOT PERSIST.** | **VERIFIED for Phase 1C store:** no subject column. Do not add to logs, DB, queue or diagnostics. |
| Full email headers | **APPROVED: DO NOT PERSIST.** | **VERIFIED for Phase 1C store:** no headers column. The existing Phase 1A metadata getter requests selected header values including `Authentication-Results`; that is not a complete-header download, but that header is not approved by this policy. **NOT IMPLEMENTED:** client field allowlist has not been changed. |
| Email body | **APPROVED: DO NOT FETCH OR PERSIST.** | **VERIFIED for Phase 1C worker:** no content request/parser dependency. This phase did not make Gmail requests. |
| Attachment names | **APPROVED: DO NOT FETCH OR PERSIST.** | **VERIFIED for Phase 1C store:** no attachment field. No Gmail content request made. |
| Attachment bytes | **APPROVED: DO NOT FETCH OR PERSIST.** | **VERIFIED for Phase 1C worker:** no content/attachment fetch path. No content request made. |

**Data-minimization rule (APPROVED):** collect no additional personal information without a documented operational purpose, least-privilege field list and policy-owner approval. A field being available in the Graph/Gmail response is not sufficient reason to collect it.

## 3. Gmail acquisition and fail-closed baseline

- **APPROVED:** only metadata-only operations already required for OAuth/profile/list/watch/history synchronization may continue. `gmail.readonly` remains the only Gmail scope.
- **APPROVED:** do not call Gmail `messages.get(format="full")` or `raw`; do not retrieve bodies, MIME or attachment data; do not execute the existing parser or threat engine on Gmail data.
- **APPROVED:** selected message metadata must be allowlisted. `Authentication-Results` and other unapproved header fields are not authorized merely because the current `metadataHeaders` list includes them.
- **BLOCKED:** content acquisition remains prohibited until a static design proves that the selected acquisition method reliably excludes attachment bytes before they reach the local process. No acquisition experiment or live request is authorized by this document.
- **APPROVED:** if attachment-byte exclusion cannot be proven, content acquisition remains blocked.
- **PROPOSED:** treat any ambiguous response shape, unrecognized field, auth state, policy version, oversized metadata response, or owner-binding failure as `BLOCKED`/`NOT_PROCESSED`, never as an implicit permission to continue.

## 4. Encryption and key-management architecture

### 4.1 Current implementation audit

- **VERIFIED (source only):** `backend/services/data_protection.py` uses `cryptography`'s `AESGCM` and requires 32-byte keys for the existing AES-256-GCM helper. The key ring and active key ID are read from environment variables.
- **VERIFIED (source only):** when no key is present in development, `protect_sensitive_value` and `protect_evidence_bytes` return the original value/bytes unchanged. Production key requirements do not prove a key is configured in this workspace or that all existing SQLite files are encrypted.
- **PROPOSED:** the existing SOC environment-variable keyring is not an approved Gmail KEK store. Do not put a new Gmail key in `.env`, ordinary configuration or source; use a separately protected OS credential facility or approved managed secret store.
- **NOT IMPLEMENTED:** Gmail sender/recipient metadata encryption, a Gmail-specific database, a Gmail key store, Gmail decryption authorization and per-record key deletion were not found.
- **NOT VERIFIED:** the actual runtime key configuration and the encryption state of any existing SQLite/evidence files were not inspected or tested in this documentation task. No key or credential was read.
- **VERIFIED (source only):** Gmail OAuth refresh-token protection uses Windows DPAPI CurrentUser in its token store. This protects the OAuth token cache only; it is not a Gmail metadata encryption-key service and does not imply SQLite encryption.

### 4.2 Proposed encryption envelope — PENDING APPROVAL

| Control | Status | Proposal |
|---|---|---|
| Data cipher | **PROPOSED / PENDING APPROVAL** | AES-256-GCM, 96-bit unique nonce per encryption under a key, 128-bit authentication tag, and authenticated additional data (AAD). No algorithm/key migration is part of this phase. |
| Per-record data key | **PROPOSED / PENDING APPROVAL** | Generate a random per-record or per-field DEK from the OS CSPRNG; encrypt each restricted field separately. Persist only ciphertext/envelope and a wrapped DEK, never the plaintext DEK. |
| Key-encryption key (KEK) storage | **PROPOSED / PENDING APPROVAL** | Keep KEK outside SQLite and ordinary configuration/source files, preferably Windows Credential Manager or a DPAPI-protected secret blob scoped to the dedicated authorized Windows identity. Evaluate enterprise KMS only if deployment requires it. |
| Envelope fields | **PROPOSED / PENDING APPROVAL** | Version, key ID, algorithm identifier, nonce, ciphertext/tag, and wrapped DEK. Bind AAD to tenant/mailbox, record ID, field name and schema version to prevent ciphertext swapping. Do not put plaintext addresses or IDs in logs. |
| Key generation | **PROPOSED / PENDING APPROVAL** | Generate keys with Windows CNG/OS cryptographic RNG; never hardcode, commit, log, expose in `.env`, or place keys beside the SQLite DB. |
| Rotation | **PROPOSED / PENDING APPROVAL** | Version keys. New writes use active KEK/DEK. Keep old KEKs decrypt-only while records/backups still need them; rewrap DEKs or re-encrypt records in a separately approved, transactional migration with audit and verified counts. Retire old keys only after recovery/backup coverage is proven. |
| Recovery | **PROPOSED / PENDING APPROVAL** | Define a protected recovery/escrow route independent of the workstation and repository; test restore under an approved recovery identity. DPAPI CurrentUser alone can make data unrecoverable if its user profile is lost. Do not create or escrow a key in Phase 2A.1. |
| Decryption authorization | **PROPOSED / PENDING APPROVAL** | Application service must authorize the principal, tenant/mailbox ownership, record, purpose and role before obtaining a short-lived key handle. The sync worker must not have address-decryption permission. Audit every decrypt/read/export. |
| Integrity failure | **PROPOSED / PENDING APPROVAL** | Missing/wrong key, invalid envelope/tag, unsupported version, corrupt ciphertext or unavailable authorization fails closed: no plaintext fallback, no write, no analysis, no provider call; emit a safe error category and require operator recovery. |
| Deletion/cryptographic erase | **PROPOSED / PENDING APPROVAL** | Per-record DEKs permit deleting a wrapped DEK for cryptographic erasure, but backups/replicas must also be covered. Verify deletion and key inventory without exposing the protected field. |

**Key conclusion:** Encryption architecture is **PROPOSED**, not implemented for Gmail. Do not claim SQLite, restricted metadata, or future evidence is encrypted merely because AES-GCM helper functions exist.

## 5. Access control and auditability

### 5.1 Proposed roles and least privilege

| Role | Proposed access | Explicit restrictions | Status |
|---|---|---|---|
| Mailbox Owner | Own mailbox connection status and minimum operational metadata; may request own permitted report. | No access to another mailbox/tenant. Sender/recipient reveal requires a documented need and explicit access grant. | **PROPOSED / PENDING APPROVAL** |
| Sync Agent | OAuth readonly and Pub/Sub sync functions; message IDs/cursor/state only. | No subject/body/attachment access and no decryption key for sender/recipient fields. | **PROPOSED**; existing agent is metadata-only, but no field-encryption key boundary exists. |
| Authorized Analyst | Investigation summary/indicators for assigned authorized case. | No blanket mailbox access; no restricted-address decryption unless explicitly authorized for the case and purpose. | **PROPOSED / PENDING APPROVAL** |
| Evidence Custodian | Authorized evidence custody/verification/decryption for a specifically approved case. | No bulk browse/export; decryption is individually authorized and audited. | **PROPOSED / PENDING APPROVAL** |
| SOC Analyst | Existing SOC case access through current SOC authorization and tenant controls. | No automatic access to Gmail mailbox metadata/evidence; transfer must be separately approved and acknowledged. | **PROPOSED / PENDING APPROVAL** |
| Tenant Administrator | Manage users, tenant policy and access grants. | Administrative role alone does not grant message-content or decryption rights. | **PROPOSED / PENDING APPROVAL** |
| Privacy/Security Auditor | Access sanitized access/retention/audit events. | No message content or decryption capability by default. | **PROPOSED / PENDING APPROVAL** |

### 5.2 Enforcement and audit requirements

- **APPROVED baseline:** least privilege, explicit authorization, mailbox/tenant ownership checks, and content-free audit logs are required before sensitive metadata or future evidence access.
- **PROPOSED:** bind each mailbox, message reference, metadata row and evidence record to a stable tenant and mailbox owner; apply authorization in every query and action, not only in UI/API routing. Do not rely on a globally unique message ID as a tenant boundary.
- **PROPOSED:** log timestamp, pseudonymous actor, action, object category, allow/deny result, purpose, policy version and a keyed/HMAC object reference. Keep HMAC key outside SQLite. Avoid raw Gmail IDs unless a separately approved incident response need requires them.
- **APPROVED:** audit logs must never contain bodies, subjects, credentials, OAuth tokens, private URLs or unnecessary personal information. Sender/recipient values are restricted metadata, not log fields.
- **PROPOSED:** log decrypt, view, export, policy change, retention hold, deletion, denied access and key rotation. Prevent audit-log modification or keep tamper evidence; monitor repeated denials without recording the protected value.
- **APPROVED fail-closed behavior:** unverifiable identity, missing tenant/mailbox binding, invalid role, invalid purpose, missing authorization or decryption failure means deny access and record a content-free event.
- **NOT IMPLEMENTED:** Gmail mailbox ownership RBAC, restricted metadata decryption authorization and associated audit events are not present in Phase 1C. Existing SOC OIDC/API-key, role and tenant controls do not implement this Gmail-specific model.

## 6. Retention and deletion framework

No legally mandated period is inferred. All proposed durations below require a policy owner and legal/security review where applicable. A retention setting is not proof that a scheduled deletion exists.

| Category | Purpose / minimum | Proposed period | Deletion trigger | Verification | Dependencies / status |
|---|---|---|---|---|---|
| Gmail synchronization metadata (history cursor, watch expiry, health) | Continue sync and recover after interruption; retain only while mailbox is connected. | While connected; delete within **30 days** after disconnect/revocation. **PROPOSED / PENDING APPROVAL.** | User disconnect, authorization revocation or mailbox removal, subject to approved incident hold. | Verify row removal by scoped counts; verify no sync process can recreate state after disconnect; retain only content-free deletion receipt. | **NOT IMPLEMENTED** Gmail disconnect purge/verification. |
| Message references and dedupe tombstones | Prevent repeated synchronization/worker handling. | **30 days after completion** proposed. Existing config default `MAILTRACE_GMAIL_DEDUPE_RETENTION_DAYS=30` is only a setting; automatic invocation of `prune_dedupe_records` was not found. **PENDING APPROVAL.** | Completion + expiry; immediately remove pending/retry rows after mailbox disconnect only if replay/recovery obligations are met. | Count before/after by status; sample opaque hashes only; verify backups expire. | **PARTIAL/NOT IMPLEMENTED:** setting and callable prune exist; scheduled deletion not found. |
| Thread ID | Operational grouping only if documented necessary. | Same as message-reference lifetime; do not retain if no demonstrated use. **PROPOSED.** | Need ends or mailbox disconnect. | Scoped deletion check. | **NOT IMPLEMENTED:** no thread requirement or stored field. |
| Internal date | Timeline/synchronization diagnostics, not authenticity proof. | Same as associated message reference: proposed **30 days after completion**. **PENDING APPROVAL.** | Associated reference expires or mailbox disconnect. | Scoped deletion count; ensure derived copies are purged. | **NOT IMPLEMENTED:** not stored by worker. |
| Sender/recipient addresses | User-facing/analyst context only if operationally necessary. | Proposed **30 days after completion**; shorter if purpose ends. **PENDING APPROVAL.** | Processing complete, user disconnect, owner request, or case closure when no approved hold remains. | Verify encrypted field and wrapped DEK removed, derived copies/cache purged, backup expiry recorded; no plaintext in logs. | **NOT IMPLEMENTED:** no Gmail address persistence/encryption. |
| Future encrypted investigation evidence | Approved forensic purpose only. | Proposed **90 days after case closure** pending formal policy and applicable legal review. **PROPOSED / PENDING APPROVAL.** | Case closure + expiry; approved hold suspends only the specifically scoped records. | Verify ciphertext, custody/hash state, deletion of object/DEK and replicas, and content-free custody/deletion receipt. | **BLOCKED:** no Gmail evidence authorization, store or approved key system. Existing SOC evidence retention is separate. |
| Quarantine record/metadata | Record an authorized hold/action and its status without duplicating the message. | Proposed **90 days after release/deletion of evidence**; only minimal action/status metadata. **PROPOSED / PENDING APPROVAL.** | Hold released and evidence retention expires; legal/forensic hold supersedes. | Verify content/evidence and wrapped keys are removed; retain a content-free signed audit event. | **BLOCKED / NOT IMPLEMENTED** for Gmail; no quarantine action is authorized. |
| Access audit logs | Accountability for view/decrypt/export/deny/delete. | Proposed **365 days**; review with privacy owner. **PROPOSED / PENDING APPROVAL.** | Period expiry unless a separately scoped legal/security hold exists. | Verify deletion through append-only event counts and backup expiry, preserving no raw identifiers/content. | **NOT IMPLEMENTED** as Gmail-specific access audit. No legally mandated term assumed. |

These candidate periods are retention proposals, not approved/legal requirements. **BLOCKED:** policy owner approval is required before enforcing Gmail-specific retention. Do not apply the SOC's separate data-classification defaults (or configured SOC retention values) to Gmail automatically.

## 7. External-service data-sharing policy

**Phase 2A.1 rule: no external calls are permitted.** The categories below are a future review matrix, not an allowlist. Current code presence in the SOC path is not authorization to use a provider for Gmail.

| Provider / service | Permitted data category | Prohibited data | Purpose | Exposure | Authorization | Current status |
|---|---|---|---|---|---|---|
| VirusTotal | **PENDING APPROVAL:** possibly public IP/domain or approved sanitized URL/hash only. | Complete body, credentials/tokens, sensitive headers, private/authenticated URLs, unapproved personal data, attachment bytes. | Reputation lookup for approved IOC. | Provider sees indicator, source IP, timing and account/API key; URL/path or hash can reveal identity/activity. | Per-indicator consent/terms/security review and exact allowlist; no Gmail use now. | Adapter exists in SOC provider client; **DISABLED for Phase 2A.1 Gmail**. |
| AbuseIPDB | **PENDING APPROVAL:** possibly public IP only. | Email content, addresses, private URLs, headers, tokens, unapproved personal data. | IP reputation. | Discloses IP and query timing/account. | Per-provider/field approval and confirmation public IP policy permits disclosure. | Adapter exists; **DISABLED for Phase 2A.1 Gmail**. |
| DNS resolver | **PENDING APPROVAL:** only approved domain/selector query names. | Body, headers, full URLs, credentials, arbitrary personal data. | SPF/DKIM/DMARC/domain record validation. | DNS operator sees queried domain/selector and timing; can reveal mailbox relationships. | Resolver/egress policy and domain-data approval. | DNS lookups exist in SOC path; **NOT AUTHORIZED for Gmail Phase 2A.1**. |
| WHOIS | No data authorized. | All message-derived data absent later approval. | Registration context if a future implementation is approved. | Query reveals domain interest and may route to a third party. | Provider, purpose, terms and privacy review. | **NOT IMPLEMENTED** in inspected email path; keep NOT_RUN. |
| RDAP | No data authorized. | All message-derived data absent later approval. | Registration data if a future implementation is approved. | Registry/registrar sees queried domain/IP and time. | Provider, purpose, jurisdiction and privacy review. | **NOT IMPLEMENTED** in inspected email path; keep NOT_RUN. |
| IP geolocation (ipapi.co, ip-api.com, ipinfo) | **PENDING APPROVAL:** possibly public relay IP only. | Bodies, headers, private/internal IPs, credentials, private URLs, unapproved personal data. | Approximate infrastructure context only. | Provider learns public IP, request source/time; location can be misleading and sensitive. | Explicit per-provider approval, public-IP filter, privacy notice and terms review. | Providers exist in SOC IP intelligence; **DISABLED for Gmail Phase 2A.1**. |
| ThreatFox | **PENDING APPROVAL:** possible public IP/domain/hash typed IOC only. | Full email, credentials, private/authenticated URL, headers and unapproved personal data. | Threat indicator lookup. | IOC and request timing disclosed to provider. | Exact typed IOC allowlist, terms and authorization. | Adapter exists in SOC threat-intel path; **DISABLED for Gmail Phase 2A.1**. |
| URLhaus | **PENDING APPROVAL:** possible sanitized public URL only after removing/denying private path/query/userinfo by an approved policy. | Full/private URLs, query tokens, body, headers, credentials, attachments. | URL malware/reputation lookup. | Submitted URL can include user IDs, reset tokens or private resource paths. | Specific URL normalization/consent and provider-terms review. | Adapter exists; **DISABLED for Gmail Phase 2A.1**. |
| ipapi network/reputation endpoints | **PENDING APPROVAL:** possible public relay IP. | Private IPs, body/header contents, unapproved identifiers. | Network/ASN/proxy context. | IP and timing disclosed to network provider. | Separate exact endpoint/data approval; do not conflate with geolocation approval. | Existing SOC IP code; **DISABLED for Gmail Phase 2A.1**. |
| Local model/runtime | No remote content sharing authorized. | Hosted inference, runtime telemetry or model service access to Gmail content. | Local-only inference may be assessed in a later phase. | Local content remains sensitive; possible telemetry/download/cache/crash exposure. | Artifact provenance, local-only network test, logging/crash review and separate approval. | Model code exists; Gmail inference **NOT IMPLEMENTED**. |

**Universal external-sharing prohibition (APPROVED):** never transmit complete email bodies, credentials, OAuth tokens, sensitive headers, private URLs containing personal/authentication parameters, attachment bytes, or unapproved personal information. No external calls were made in Phase 2A.1.

## 8. Future outcome classification

Four outcomes must remain distinct. Concepts below are **PROPOSED / PENDING APPROVAL**, not an implemented policy and not numeric thresholds.

| Outcome | Proposed meaning | Must not mean | Status |
|---|---|---|---|
| `SAFE` | All required, approved checks completed with sufficient evidence/coverage and no adverse evidence under the approved policy version. | Low score, absent indicators, unavailable providers, skipped checks, or failure to parse. | **PENDING APPROVAL / NOT IMPLEMENTED** |
| `HIGH` | Credible evidence of materially elevated threat requiring user/analyst action under approved evidence and confidence criteria. | A score threshold copied from the SOC or one uncorroborated heuristic/model output. | **PENDING APPROVAL / NOT IMPLEMENTED** |
| `CRITICAL` | Strong, corroborated evidence meeting a policy-defined highest-severity condition and separately authorized escalation criteria. | A parser/gateway threshold alone, or permission to retain/transfer evidence automatically. | **PENDING APPROVAL / NOT IMPLEMENTED** |
| `INDETERMINATE / ANALYSIS_INCOMPLETE` | Required checks were not run, failed, were unavailable, parsing was partial, authorization/policy was unresolved, or evidence is insufficient/conflicting. | SAFE or a clean result. | **APPROVED as a distinct required future outcome; exact rules PENDING APPROVAL; NOT IMPLEMENTED for Gmail** |

- **APPROVED:** missing checks must never be treated as `PASS`; unavailable/failed checks cannot produce `SAFE`.
- **APPROVED:** technical failures remain distinguishable from clean results, and every future threat finding must cite supporting evidence/provenance.
- **PENDING APPROVAL:** required-check set, evidence sufficiency, confidence, conflict resolution, model treatment, thresholds and mapping to alerts/actions.
- **NOT IMPLEMENTED:** no Gmail result/classification is produced by Phase 1C. No final risk threshold is approved here.

## 9. Fail-closed rules

The following are **APPROVED** for future Gmail content processing and restricted metadata operations:

1. Content acquisition is not explicitly authorized or attachment-byte exclusion is not proven → do not fetch/process content.
2. Required key is absent, unavailable, wrong, expired, or envelope authentication fails → no restricted-metadata persistence/decryption; no plaintext fallback.
3. Principal, role, purpose, tenant or mailbox ownership cannot be verified → deny and do not enumerate protected records.
4. Required privacy controls, allowlist, retention policy or security configuration are missing → stop before collection, analysis, egress or persistence.
5. Evidence store is not encrypted/authorized or retention/deletion is unresolved → do not preserve evidence or quarantine content.
6. Policy is ambiguous or version is not approved → no processing; record only a content-free blocked status.
7. Provider is not explicitly approved for the exact IOC type/fields → no DNS/reputation/geolocation/TI call.
8. A technical failure, missing check or unavailable result → preserve an error/unavailable/indeterminate state; never silently downgrade to SAFE.

No failure path may retry by widening scopes, requesting `full`/`raw`, bypassing encryption, changing tenants, or sending data to another provider.

## 10. Remaining policy decisions and implementation gates

| Gate | Status | Required approval/evidence |
|---|---|---|
| Metadata field allowlist and data-owner purpose per field | **PARTIALLY APPROVED / PENDING** | Existing `metadataHeaders` includes `Authentication-Results`; approve or remove it in a later implementation authorization. Confirm `From`, `To`, `internalDate`, IDs and diagnostics handling. |
| Encryption/key architecture | **PROPOSED / PENDING APPROVAL** | Approve AES-256-GCM envelope, Credential Manager/DPAPI or managed key source, recovery, rotation, access audit, AAD schema and rollout. |
| Sender/recipient encryption implementation | **NOT IMPLEMENTED / BLOCKED** | Implement only after storage schema, key source and migration policy are separately authorized. No migration was run here. |
| Retention periods | **PROPOSED / PENDING APPROVAL** | Name policy owner; approve each period, trigger, legal-hold dependency, backup expiry and deletion evidence. |
| Role/tenant/mailbox authorization | **PROPOSED / PENDING APPROVAL** | Approve principal binding, roles, decryption authorization and audit content. |
| External provider allowlist | **APPROVED disabled now / PENDING future** | Approve each provider and exact field types, purpose, consent, terms and failure handling. |
| Threat outcome policy | **PENDING APPROVAL / BLOCKED** | Approve required checks, SAFE/HIGH/CRITICAL evidence criteria, indeterminate handling, threshold calibration and action mapping. |
| Body/MIME/attachment acquisition | **APPROVED prohibited now / BLOCKED** | Remains blocked unless later approval provides reliable attachment-byte exclusion. |

## 11. Change and verification record

- **VERIFIED (source inspection only):** Phase 1C store persists message IDs and worker lifecycle metadata, not sender/recipient, subject, body, headers or attachment data.
- **VERIFIED (source inspection only):** Phase 1C worker has no Gmail client/parser dependency. Its previous focused test run was reported as 64 passed; that result was not rerun for this documentation-only phase.
- **VERIFIED (source inspection only):** `GmailClient.get_message(format="metadata")` currently requests selected `From`, `To`, `Date`, `Message-ID`, and `Authentication-Results` header fields. No request was made in this phase. The field allowlist needs a future authorized implementation change.
- **VERIFIED (source inspection only):** Gmail dedupe config defaults to 30 days and a prune method exists; no scheduled prune call was found. Therefore expiry is not claimed as operational.
- No application code, frontend, database file/schema/records, `.env`, OAuth credentials/token cache or production data were modified.
- No Gmail message body/MIME/attachment was fetched; no email analysis or external service call was executed; no tests were required or run.

**Phase status:** privacy baseline documented; content processing remains **BLOCKED**. Phase 2B/Phase 3 implementation has not started.
