# MailTrace AI — System Audit (Phase 0)

**Audit type:** inspection-only repository review  
**Repository:** `MailTrace-AI`  
**Date:** 2026-11-20  
**Scope:** architecture, active code paths, integrations, security/privacy boundaries, and a safe test attempt. This is a source audit, not a deployment or penetration-test certification.

## Current email-provider update — Gmail (2026-11-20)

The project owner selected Gmail API as the SIH mailbox provider, superseding Microsoft Graph/Outlook as the implementation path. The Phase 0 repository inspection had no Gmail code. Phase 1A now provides OAuth/API client code, documented below; no `users.watch`/History integration, Pub/Sub subscriber, User Backend, or Windows Agent exists. Do not describe automatic Gmail detection as operational. The design is documented in [EMAIL_PROVIDER_ARCHITECTURE.md](EMAIL_PROVIDER_ARCHITECTURE.md), [GMAIL_SYNC_DESIGN.md](GMAIL_SYNC_DESIGN.md), and related setup docs.

At this inspection, port 8100 had no listening socket. The local environment had no `dotnet` command and no root `credentials.json`, `token.json`, or `google-cloud-key.json`. The supported launcher/README frontend port is **5503**; CORS also permits 5504. The SIH target 5504 is feasible but needs a coordinated launcher/README/offline-prompt update. No port was changed. A legacy `backend/main.py` direct-run block still specifies port 8000; do not invoke it. The documented/launcher path uses backend 8002. No service was started on 8000.

## Phase 1A implementation status (2026-11-20)

`backend/services/gmail_connector/` now contains the approved Phase 1A-only Gmail desktop OAuth + PKCE flow, DPAPI CurrentUser protected token store, refresh/reconnect/logout handling, and read-only Gmail profile/list/get client with pagination. `backend/tests/test_gmail_connector.py` has 16 passing mocked/DPAPI tests. The configured external credentials path `%LOCALAPPDATA%\mailtrace\secrets\credentials.json` was absent at verification; its JSON could not be validated and no live OAuth or Gmail request was attempted. Pub/Sub, Windows Agent, User Backend and automatic detection remain unimplemented. See `GMAIL_OAUTH_SETUP.md` and `IMPLEMENTATION_PLAN.md`.

## Executive summary

MailTrace already contains a substantial FastAPI SOC application, a large browser dashboard, an email analysis pipeline, SQLite persistence, case routing and claims, alerting, retention controls, evidence custody/integrity services, threat-intelligence enrichment, and local AI/ML inference. It is an existing system to extend, not a blank project.

The requested SIH workflow is **not yet end-to-end implemented**. Repository search found no Gmail mailbox client, desktop OAuth, Gmail History/watch client, Pub/Sub pull worker, dedicated user backend/dashboard, passwordless OTP service, or C#/.NET Windows Worker Service. The existing mail webhook and provider-neutral gateway contract are useful integration seams, but the default gateway adapter is explicitly unconfigured and cannot perform actions. Existing analysis and SOC workflows can be reused after privacy-aware extraction of a shared analysis entry point.

## Repository map

| Area | Active location | Notes |
|---|---|---|
| Existing SOC API | `backend/main.py`, `backend/routes/` | FastAPI app; primary runtime port is 8002 in the launcher. |
| Database and persistence | `backend/database/database.py`, `backend/runtime_data/` | Direct SQLite, schema initialization/migrations in Python, plus JSONL/file-backed evidence stores. |
| Analysis services | `backend/services/` | Parser, forensics, auth evidence, URL/IP/domain intelligence, TI, ML, scoring/fusion, attachments, response and evidence services. |
| SOC UI | `frontend/index.html`, `frontend/script.js`, `frontend/style.css`, supporting JS files | Existing SOC dashboard calls the API at `127.0.0.1:8002`. Supported launcher/README serve port 5503; offline prompt also says 5503. CORS already allows 5503 and 5504. |
| Bridge utilities | `bridge/` | Python FastAPI/PowerShell bridge tooling; not a Windows service or Gmail Agent. |
| Tests | `backend/tests/`, selected `backend/services/*/tests/` | Backend pytest config discovers `tests` and `services`; archives/backups also exist and should not be treated as active tests. |
| Configuration | `.env.example`, `backend/.env.example`, requirements files, launcher | Secret values were not inspected. Root `.env` was deliberately not read. |
| Documentation/audits | root and `backend/*.md`, `backend/reports/` | Contains phase reports and prior readiness findings; historical test results are dated evidence, not a current run. |
| Historical/recovery material | `mailtrace v 10/`, `.mailtrace_bridge/`, `snapshots/`, `soc-map-backups/`, `backend/backups/`, `backend/services/*_backup*` | Keep separate from active source; avoid recursive test collection or cleanup. |

The checkout also contains generated/runtime directories, test artifacts, local datasets, and many existing modified/untracked files. The audit did not inspect local database contents or email/evidence contents. Working-tree changes predate this audit; no attribution to this audit is implied beyond the six new audit documents.

## Entrypoints and ports

- SOC backend ASGI application: `backend/main.py` → `app`; normal local command documented by README is `uvicorn main:app --host 127.0.0.1 --port 8002` from `backend`.
- Windows launcher: `START_MAILTRACE.ps1`; it configures backend port **8002** and frontend port **5503**, and expects the current dashboard health marker. `backend/main.py`'s legacy `__main__` block specifies 8000; use the launcher/README Uvicorn command instead. SIH's 5504 target requires a later coordinated change; no port change was made.
- Dashboard: `frontend/index.html`; hardcodes API base `http://127.0.0.1:8002`. `frontend/script.js` refers to dashboard port 5503 in its offline prompt.
- Test runner: `backend/pytest.ini` (tests and services; importlib mode); root `pytest.ini` also exists.
- No `.sln`, `.csproj`, `.cs`, Dockerfile, Alembic configuration, or project-owned Graph integration was found in the inspected active tree.

## Existing SOC platform

The FastAPI app exposes analysis, investigation, case, campaign, alert, employee-report, routing, threat-intelligence, IP-intelligence, evidence, privacy/retention, response-management, recommendation, IOC timeline, and threat-hunting APIs. See [API_INVENTORY.md](API_INVENTORY.md).

Authentication is shared at the API middleware boundary: local development permits loopback use without a configured key; configured API keys carry tenant/role/subject claims; hosted OIDC validates signed tokens using issuer/audience/JWKS and configured role/claim mapping. Production mode deliberately enforces one tenant while legacy and file-backed stores remain incompletely scoped. SOC analyst/lead routes apply additional role and identity checks. This is **not** the requested independent passwordless OTP auth system, and no OTP send/verify/session workflow was found.

Cases, analyst assignment/routing, claim leases, SLA alerts/escalations, audit chains, employee reports, and evidence/retention APIs are implemented. They have isolated regression tests and local documentation. Operational integrations still need verification: real OIDC settings, mail gateway action execution, external attachment detonation, and deployment controls.

## Email analysis path

`POST /api/analyze-email` accepts `.eml` and `.msg`, applies byte limits, calls `services.email_parser.parse_email`, then enriches and composes the result with forensics, AI inference, IOC/TI, correlation, and intelligence fusion in the existing backend. The analysis pathway is currently coordinated within the large `main.py` endpoint and `email_parser.py`; a user-backend-ready, stable shared-core service contract is not yet separated.

`parse_email_bytes` uses Python's email package and bounds message bytes, MIME parts, nesting depth, and header count. `.msg` support uses `extract-msg` to normalize the message to an email representation. Header multiplicity and parse diagnostics are preserved by the parser path. SPF/DKIM/DMARC observations in uploaded headers are explicitly marked untrusted. A separate forensic validator can recompute SPF only with trusted signed SMTP context, cryptographically verify selected DKIM signatures, and look up DMARC policy; policy lookup is not full alignment evaluation. Treat these outputs as evidence with explicit status, not proof of sender identity.

URL extraction and link deception, IP/relay analysis, domain intelligence, IOC normalization, local threat-intelligence lookup, attachment metadata/static analysis, optional ClamAV scanning, and risk fusion are present. Dynamic attachment detonation is not configured. Geolocation/provider lookups can make outbound queries when enabled; provider policy and approval flags exist. Model inference can return unavailable states; ML probability and unified risk are separate. Dataset rights and independent label review block retraining, per Step 27 documentation.

## Persistence and privacy findings

The existing SOC path persists investigation rows, including `analysis_json`, and stores evidence/custody artifacts under `backend/runtime_data/`. Sensitive investigation fields can be AES-GCM protected when an encryption key is configured; in development without a configured key, the helper returns plaintext. This existing retention/evidence design must **not** be carried wholesale into the new SAFE-email path. SIH's SAFE/LOW no-persistent-raw-content requirement calls for an explicit data-minimizing user-side analysis mode, with SAFE requests never passed into existing persistence hooks. HIGH/CRITICAL retention should use a narrowly scoped encrypted quarantine/evidence boundary.

The SOC webhook persists an idempotency/lease record and investigation for submitted mail; it is not an implementation of the requested Microsoft Graph local-user workflow. Do not send SAFE email to this webhook. The webhook's HMAC protects intake authenticity; signed gateway receipts are assertions from the external gateway and do not independently prove provider action.

## External dependencies and environment configuration

Python dependency groups include FastAPI/Pydantic/Uvicorn, SQLite in the standard library, cryptography, MIME/MSG parsing (`extract-msg`), DNS/SPF/DKIM libraries, scikit-learn/joblib, HTML parsers, and optional Redis/geolocation packages. Optional external systems include DNS resolution, AbuseIPDB, VirusTotal, ThreatFox, URLhaus, geolocation providers, Redis, ClamAV, OIDC/JWKS, and a future mail gateway. Gmail API, Google OAuth, and Pub/Sub libraries/configuration are not currently present.

Environment variable **names** found in source/config are cataloged in [SYSTEM_AUDIT.md's configuration appendix](#configuration-name-catalog). Values/secrets were not read. Key groups: `MAILTRACE_ENV`, `MAILTRACE_SINGLE_TENANT_ID`, `MAILTRACE_API_KEYS_JSON`, `MAILTRACE_OIDC_*`, `MAILTRACE_DATA_ENCRYPTION_*`, `MAILTRACE_WEBHOOK_*`, `MAILTRACE_GATEWAY_ACK_SECRET`, `MAILTRACE_GATEWAY_ENFORCEMENT_MODE`, `MAILTRACE_ROUTING_EMAIL_HMAC_KEY`, retention/SLA settings, `MAILTRACE_GEOLOCATION_*`, `MAILTRACE_DOMAIN_INTELLIGENCE_ENABLED`, `MAILTRACE_BRAND_DOMAIN_LIST`, `MAILTRACE_CLAMD_*`, and provider keys/endpoints for AbuseIPDB, VirusTotal, ThreatFox, URLhaus and IPinfo. Bridge uses `MAILTRACE_BRIDGE_TOKEN` and `MAILTRACE_PROJECT_ROOT`.

### Configuration name catalog

The list above is intentionally grouped rather than reproducing every OIDC claim override. Full names include `MAILTRACE_OIDC_ISSUER`, `AUDIENCE`, `JWKS_URL`, `CLIENT_ID`, `AUTHORIZATION_ENDPOINT`, `TOKEN_ENDPOINT`, `REDIRECT_URI`, `SCOPES`, `ROLE_MAP_JSON`, and tenant/role/email-verified/region/team/skills claim selectors. Provider credentials remain unset/unverified until deployment configuration is inspected by an authorized operator.

## Test execution record

On 2026-11-20, the backend venv's pytest discovered **647 items** using `-vv -p no:cacheprovider` and an isolated `.phase0-pytest-basetemp`; `backend/conftest.py` also redirected the app DB to a per-process temporary SQLite file and disabled background workers. Eight OIDC authentication tests passed. Execution then stopped producing progress at `tests/test_alert_tenant_isolation.py::test_alert_listing_is_tenant_scoped_and_contains_no_other_tenant_email`; the run was interrupted after the same test remained blocked for over a minute. Phase 0.1 reran only this test. With the backend venv and a fresh writable basetemp, it again stalled before the HTTP request; the 12-second faulthandler stack was in `TestClient.__enter__` → AnyIO portal → Windows asyncio loop initialization → `socket.socketpair`. The worker was disabled. This does not establish a SQLite, route, tenant assertion, or network-call root cause; a host/runtime socket issue is suspected but unconfirmed. A system-Python attempt failed collection because `tldextract` was not installed there. The repository default basetemp `.pytest-tmp` also raised `WinError 5` during pytest cleanup; contents of that protected directory could not be inspected, so no claim is made about its artifacts. See [PHASE_0_1_VALIDATION.md](PHASE_0_1_VALIDATION.md) for full diagnostics. Therefore:

- Current-run passed: 8 tests.
- Current-run failed assertions: none observed before interruption.
- Current-run blocked/interrupted: the named tenant test in TestClient startup before request; host/runtime trigger not established.
- Current full-suite result: **incomplete / unverified**, not a pass.

Existing dated reports record earlier passing suites (including 502 passed, 1 skipped, and 16 subtests in the 2026-10-16 report, and other historical counts). Those runs are not substituted for today's interrupted run. No production server was started and no production DB was used intentionally by the test configuration.

## Proposed direction

Keep the existing SOC platform in place. Add an independent `user_backend/` (FastAPI/local SQLite), a small side-effect-free analysis contract around reusable services, and a C# Windows Worker Service that owns Gmail OAuth, Pub/Sub pull, Gmail History sync, watch renewal and DPAPI-protected token handling. The user backend should analyze SAFE/LOW in memory without invoking SOC persistence, and only policy-approved CRITICAL evidence should cross a signed, authenticated, idempotent SOC integration. Port 8100 was free at the check; preserve SOC backend 8002. The supported SOC frontend port is 5503; SIH recommendation is 5504 after a coordinated, explicitly approved config change. See [PHASE_0_1_VALIDATION.md](PHASE_0_1_VALIDATION.md).

