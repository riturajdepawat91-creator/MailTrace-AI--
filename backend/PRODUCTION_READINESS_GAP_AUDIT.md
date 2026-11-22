# MailTrace AI - Production Readiness Gap Audit

Audit date: 2026-10-11
Scope: static inspection of the active backend workspace and execution of existing tests. This is not a production certification.

## Verified implementation evidence

- `main.py` exposes a provider-neutral RFC822 email webhook at `POST /api/webhooks/email`; the endpoint is disabled until `MAILTRACE_WEBHOOK_SECRET` is configured.
- Webhook verification includes timestamp validity and HMAC signature validation. Event processing uses persisted idempotency/lease state and gateway action receipts.
- `/api/ready` explicitly reports `mail_gateway.vendor_adapter` as `NOT_CONFIGURED`; a generic webhook endpoint is not the same as a vendor-specific production connector.
- Gateway policy supports monitoring-only and enforcement decisions; tests cover risk/confidence policy, signed action receipts, duplicate/idempotency conflicts, and tamper detection.
- Employee report handling, urgent incident escalation, report status views, SOC case assignment/claiming, SLA escalation, routing, tenant-scoped alert access, and audit chains have dedicated tests.
- Production access-control code intentionally restricts the current deployment to one configured tenant while legacy/global stores remain unscoped. Do not remove this guard until every persisted and file-backed store is tenant-isolated and tested.
- `/api/ready` checks database connectivity and reports optional integration states for attachment scanning, regional routing, integrity anchoring, OIDC, and gateway setup.

## Test evidence collected

- `backend/tests`: 103 passed.
- Additional service and security tests (OIDC, campaign correlation, CORS, evidence error handling, routing, threat-intelligence sync, provenance, integrity anchoring and intelligence fusion): 85 passed.
- A combined recursive collection of service tests encountered duplicate test module basenames (`test_soc.py`) across package directories. The package suites were run separately in the passing run above; the failed combined collection is a test naming/collection issue.

## Release blockers and unverified capabilities

1. Gateway vendor integration: no provider-specific adapter was found in the active workspace. Select/configure the institutional gateway and verify delivery-before-interaction quarantine, release, retries, and real action acknowledgements in a test tenant.
2. Multi-tenancy: current production guard is single-tenant. Full multi-tenant rollout is blocked until all legacy investigation, evidence, report, campaign, attachment and file-backed stores enforce tenant boundaries.
3. External identity: OIDC implementation and tests exist, but a real institution's issuer, audience, JWKS endpoint, role mapping and login flow are not verified by unit tests alone.
4. Attachment containment: scanner integration health can be reported, but isolated detonation/sandbox deployment and its failure behavior must be independently configured and tested.
5. Operational readiness: validate production TLS/reverse proxy, secrets management/rotation, database backup and restore, queue durability, ingress rate limiting, metrics/alerting, load tests, disaster recovery and penetration testing.
6. Forensic attribution: preserve confidence and source provenance; IP geolocation is approximate infrastructure context, not proof of an individual's identity or physical location.

## Next implementation order

1. Choose the target mail gateway and build/test its adapter against the existing normalized webhook and signed action-receipt contract.
2. Inventory every persistent/file-backed store and close tenant-scope gaps before enabling multiple tenants.
3. Run a staging end-to-end test from message arrival through policy decision, gateway action acknowledgement, employee report, SOC case assignment and evidence audit.
4. Validate real OIDC and isolated attachment scanning integrations, then exercise dependency failure and recovery.
5. Run load, backup/restore, security and deployment acceptance tests before making a production-readiness claim.

## Status semantics

A passing unit test proves the tested code path under test conditions. It does not prove a live provider integration, production configuration, regulatory compliance, or deployment certification. Mark an integration VERIFIED only after recording its environment, test evidence, and failure/recovery result.

## Follow-up verification (2026-10-11)

- Added package marker files to the active `services/analysis_provenance/tests` and `services/privacy_governance/tests` folders to make their same-named test modules importable as packages.
- Combined active backend tests and selected active service suites: 162 passed in 23.56 seconds.
- A broad `pytest tests services` collection still fails because archived `analysis_provenance_backup_before_v1.1_*` snapshots contain repeated `test_soc.py` modules. Those archived snapshots should be excluded from the canonical test command; they were not deleted or modified.

## Test-runner maintenance

- Added `pytest.ini` to define the canonical active test suite and exclude archived/backup directories from default discovery. This makes `python -m pytest -q` reproducible without accidentally collecting historical duplicate test modules.
- Verified the configured default command: 162 passed in 22.89 seconds.

## Webhook resource-exhaustion hardening

- Reordered webhook validation so the signed timestamp format and five-minute freshness window are checked before the request body is consumed.
- Added an early `Content-Length` rejection when the declared body exceeds the existing upload limit. The streaming size limit remains in place as the authoritative check for chunked requests and incorrect/missing length headers.
- `main.py` passes `py_compile`; the canonical configured suite passes: 162 passed in 23.31 seconds.

## Additional receipt hardening tests (2026-10-11)

- Added regression coverage that stale gateway receipts and invalid HMAC signatures are rejected before any gateway-action record is written.
- Latest verification: security module 21 passed; canonical backend suite 166 passed; Python compilation passed for main.py and the security test module.
- Vendor-specific gateway enforcement is still NOT_CONFIGURED; receipt endpoints verify acknowledgements but do not themselves quarantine mail.


## Explicit release gate (2026-10-11)

- /api/ready now reports production_release_gate separately from process/database readiness, with named blockers and no secret values exposed.
- The gate remains BLOCKED while the vendor adapter is absent or required gateway/identity configuration is missing; even after configuration it requires external staging validation.


## Explicit release gate (2026-10-11)

- The readiness response now reports a production release gate separately from database readiness, with named blockers and no secret values exposed.
- The gate remains blocked while the vendor adapter is absent or required gateway/identity configuration is missing; external staging validation is still required.


## Provider-neutral gateway adapter contract (2026-10-11)

- Added services/mail_gateway/adapter.py with a provider-neutral action/result contract, typed not-configured error, and a default adapter that fails closed without attempting a mail action.
- Added contract tests proving the default adapter is explicitly unconfigured and cannot claim quarantine was applied.
- This is an integration seam only, not a live Microsoft 365/Exchange/Gmail connector. Vendor authentication, provider API calls, message identity mapping, retries and staging verification remain release blockers.
- Latest verification: adapter plus security tests 23 passed; full backend suite 168 passed; Python compilation passed.


- Readiness now queries the adapter contract and reports its configured state/name dynamically instead of hard-coding the vendor adapter status.


## Response execution and verification hardening (2026-10-11)

- Added regression tests for the response execution/verification engines and fixed two `_build_check` calls that supplied too few arguments and could crash verification at runtime.
- Verification now parses explicit string success values instead of treating any non-empty string (including `"false"`) as success.
- IOC observation checks now require an observation for each exact IOC, rather than accepting an unrelated observation merely because the counts match.
- Case closure recommendation now requires zero unknown IOCs as well as zero residual active IOCs and verified action completion.
- Added regression coverage for untrusted false-success values, unrelated IOC observations, invalid operations, and simulation/no-side-effect guarantees.
- Verification: focused response tests 5 passed; canonical backend suite 173 passed; Python compilation passed.
- These engines remain simulated/non-persistent; they do not prove a vendor action occurred in a real mail tenant.

## Response API routing and audit identity (2026-10-11)

- Corrected FastAPI decorator placement so `/api/response-management/transition` and `/api/response-management/verification` resolve to their intended handlers; previously these decorators were attached to the recommendations handler.
- Added route-registration regression coverage for both paths and the recommendations endpoint.
- Transition audit actor is now taken from the authenticated request principal rather than trusting a caller-supplied `actor` field, preventing easy audit identity spoofing.
- Verification: response workflow tests 7 passed; canonical backend suite 175 passed; main.py and response engine modules compile.

## SOC SLA escalation regression coverage (2026-10-11)

- Added an isolated SQLite regression test for overdue P1 cases: an overdue open case produces one tenant-scoped SLA alert and audit event, repeat processing inside the escalation cooldown does not duplicate it, a closed case is ignored, and another tenant's case is not touched.
- Verification: SLA escalation regression test passed; canonical backend suite passed (176 tests); compilation passed for the SLA database, routing, API, and new test modules.

## SOC SLA alert lifecycle and tenant isolation (2026-10-11)

- Added isolated API tests for authenticated SLA alert listing, OPEN -> ACKNOWLEDGED -> RESOLVED transitions, rejection of duplicate/out-of-order transitions (409), and audit entries bound to the authenticated principal.
- Added cross-tenant transition/listing coverage: tenant A cannot mutate tenant B's alert, and failed cross-tenant mutation leaves status and audit history unchanged.
- Added escalation lifecycle coverage proving a previously resolved alert reopens only when a new overdue escalation is eligible after its cooldown; escalation count advances to two.
- Verification: SLA lifecycle/escalation tests 4 passed; full backend suite 179 passed; Python compilation passed for touched modules.
- These checks use isolated synthetic SQLite data. They do not restart or mutate live services, and do not validate a real mail-provider action.

## Live frontend/backend identity and launcher validation (2026-10-11)

- Found the listener on port 5504 was serving a temporary frontend copy with older cache-busting asset versions and glyph differences, not the current `frontend/` project files. Port 5503 was not listening.
- Updated `START_MAILTRACE.ps1` to use port 5503 for the project frontend and require the current `script.js?v=20261010-sla-workflow` marker before calling the frontend ready.
- Tightened backend startup validation to require `production_release_gate` in `/api/ready`, so an older backend process cannot be reported as current/ready solely because it answers HTTP 200.
- Started the current project frontend on `127.0.0.1:5503` without stopping or changing the existing listeners on ports 8000, 8002, or 5504. Verified index, JS, auth JS, and CSS all return HTTP 200; backend `/api/ready` and tenant-scoped SLA alert listing on port 8002 also returned HTTP 200.
- Important live mismatch: the current project source exposes `production_release_gate` in `/api/ready`, but the already-running process on port 8002 does not. Its `/api/auth/config` also reports OIDC disabled. The running backend was not restarted because its loaded source/workdir and data impact have not been verified; port 8000 was left untouched.
- Launcher syntax passed. Production release remains unverified until the current backend build is safely brought online and external OIDC/vendor gateway integrations are configured.
- Follow-up evidence: port 8002 process started at 15:39 on 2026-10-11, while the current project `backend/main.py` was modified at 19:51. The running `/api/ready` payload lacks the source-defined `production_release_gate`, confirming it is not serving the current source revision. Its process environment/workdir could not be verified safely, so it was deliberately left running rather than risk switching databases or dropping runtime configuration.
