# MailTrace AI — Database and Evidence Audit

## Storage architecture

The active SOC persistence layer is `backend/database/database.py`. It uses Python's standard `sqlite3` module directly, with a module-level `DATABASE_PATH` defaulting to `backend/mailtrace.db`; no SQLAlchemy model layer or Alembic migration framework was found in the active project. Table creation and incremental `ALTER TABLE` migrations are implemented in Python initialization functions. The `backend/models/` directory currently contains email-AI model manifests, not relational database models.

Additional state lives outside SQLite: evidence custody ledger JSONL, evidence vault files, integrity anchor SQLite database, runtime artifacts, and test/runtime directories under `backend/runtime_data/` and related paths. Database/evidence contents were not read during this audit.

## Main SQLite entities

| Table | Role / sensitive content |
|---|---|
| `investigations` | Uploaded message identity fields, threat score/verdict/confidence, and serialized `analysis_json`; the analysis JSON can include message-derived content. |
| `cases` | SOC incident/case metadata, severity/status/score and tenant ID. |
| `case_investigations` | Case-to-investigation relation. |
| `campaigns`, `campaign_investigations` | Campaign aggregation and investigation relation. |
| `case_notes` | Analyst notes. |
| `evidence` | Evidence references/content values associated to a case or investigation. |
| `email_webhook_events` | Webhook idempotency, payload fingerprint, processing/lease/policy state. |
| `email_gateway_action_receipts` | Gateway action result/receipt chain linked to webhook event. |
| `email_alerts`, `email_alert_events` | SOC alert state, user notice, acknowledgements/resolutions and event history. |
| `employee_email_reports`, `employee_email_report_events` | Employee reports and immutable status/event history. |
| `case_claims`, `case_claim_events`, `case_claim_rate_limits`, `case_claim_idempotency` | Analyst claim/lease, audit/event, rate limiting, and retry replay state. |
| `case_audit_events` | Tenant/case audit-chain events. |
| `evidence_retention_events` | Retention holds and retention decision audit chain. |
| `threat_intelligence`, `threat_intelligence_sync_runs`, `threat_intelligence_sync_lease` | Local indicators, sync provenance and sync locking. |
| `soc_queues`, `employee_region_assignments`, `soc_analysts`, `case_routing`, `soc_sla_alerts`, `soc_sla_alert_events`, `case_routing_events`, `soc_routing_config_events` | Queue, region, analyst, assignment, SLA and routing audit state. |

## Sensitive-data handling

`services/data_protection.py` can AES-GCM encrypt investigation fields (filename, subject, sender, recipients, and `analysis_json`) using a configured key or key ring. If no key is configured in development, `protect_sensitive_value()` returns the value unchanged. Production requires a key. Do not assume local DB content is encrypted without checking the active environment configuration.

The existing upload analysis saves investigation rows. This conflicts with the SIH requirement that SAFE and LOW email bodies/attachments are never persisted. The new local user flow must not call this persistence path for SAFE/LOW messages. Policy-driven HIGH/CRITICAL preservation should be separate, encrypted, access-controlled, auditable, and limited to authorized evidence.

`backend/main.py` initializes file-backed evidence services under `backend/runtime_data/`: `evidence_vault/`, `evidence_ledger.jsonl`, and `integrity_anchors.sqlite3`. Existing preservation copies may be encrypted when keys exist; assess the actual path/policy before using it for local user quarantine. File-backed stores are also part of the current single-tenant production restriction.

## Tenant boundaries and migrations

Tenant IDs appear in investigation/case/alert/routing operations and production configuration deliberately restricts to one tenant while old/global/file-backed stores remain incompletely scoped. Several schema additions are applied by startup-time `ALTER TABLE` calls rather than versioned migrations. Preserve the single-tenant guard; the SIH user backend should have a distinct local database and ownership boundary rather than reusing or modifying the SOC database.

## SIH database recommendation

Create a separate user-side SQLite database for mailbox connection metadata (never access/refresh tokens in plaintext), scan metadata, risk/status, privacy preferences, and quarantine metadata. Do not store SAFE/LOW message text, raw MIME, or attachment bytes. Keep Graph tokens in Windows DPAPI/Credential Manager owned by the Agent where practical. Put encrypted HIGH/CRITICAL evidence into a dedicated local vault with authenticated metadata and explicit retention. Store only the minimum signed escalation reference/summary in Central SOC for CRITICAL.

The user asked for SQLAlchemy/Alembic as preferred, not mandatory; for the short SIH prototype, choose either a small SQLAlchemy/Alembic schema or deliberate SQLite repository functions and document migration behavior. Do not point the new service at `backend/mailtrace.db`.

