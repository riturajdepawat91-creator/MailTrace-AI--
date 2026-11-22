# MailTrace Customer API and Authorization Design

**Status:** APPROVED DESIGN — Phase 3 local Customer API and native OIDC client are now implemented with the restrictions recorded in `PHASE_3_FINALIZATION_REPORT.md`; real provider configuration remains pending.
**Scope:** Customer-facing authentication, tenant/user isolation, API contract, and the boundary from the existing SOC backend.
**Preservation:** This design does not change the existing FastAPI/SOC backend, database, routes, authentication configuration, or ports.

## 1. Decision summary

**Proposed:** Add a dedicated customer-facing local API/BFF on `127.0.0.1:8100`. The customer desktop app talks only to this API through its native WebView2 bridge. The existing SOC backend remains on `127.0.0.1:8002`; the internal SOC dashboard remains on port `5503`.

The customer API is an allowlisted product boundary, not a generic proxy to port 8002. It must never forward arbitrary paths, user-selected URLs, or customer bearer tokens to SOC routes. Existing SOC routes and analyst permissions are not customer permissions.

**Current readiness:** `BLOCKED` for authenticated customer data access. The desktop app currently performs a health/readiness check only. No customer login/session, customer API, mailbox API, scan API, or customer report feed exists yet.

## 2. What exists today (verified in source)

| Existing component | Current behavior | Customer-app decision |
|---|---|---|
| `GET /api/auth/config` | Publishes public OIDC client metadata when configured. It does not itself implement login. | Do not use as proof that customer login is ready. A separate customer OIDC client/configuration is required. |
| `GET /api/auth/me` | Returns authenticated subject, tenant, roles, auth method and optional team/region. | Internal identity endpoint; do not expose directly as the customer profile contract. |
| `/api/health`, `/api/ready` | Unauthenticated health/readiness routes. Readiness can expose optional integration configuration details. | Customer app may use only sanitized service/database readiness fields. |
| `backend/services/access_control.py` | Supports OIDC bearer validation and digest-checked API keys. Production currently requires a configured single tenant until legacy stores are tenant-scoped. | OIDC is the only proposed end-user sign-in. Do not ship API keys in the desktop app. Production multi-tenant use remains blocked. |
| `backend/main.py` middleware | In development, loopback callers outside `/api/employee/reports` are assigned `local-dev-analyst` with analyst access. | Critical reason not to call SOC/analysis routes directly from the desktop app. Loopback is not customer authentication. |
| `POST /api/synthetic-analysis` | Requires analyst-class role, persists sanitized synthetic reports, and attempts Central SOC delivery in the request. | Not a customer scan API. Do not call from the customer app. Its analysis and SOC-delivery effects are coupled. |
| `GET /api/synthetic-analysis/{analysis_id}` | Analyst-class route; ownership is enforced for ordinary analyst users, while privileged SOC roles can read across owners in the tenant. | Not a customer report API or a customer-role contract. |
| `POST /api/synthetic-analysis/{analysis_id}/soc-retry` | Retries SOC delivery. | Internal operational action; never expose to customers. |
| `/api/employee/reports` | Employee self-service report status, scoped by tenant and subject; submission can create/rout a SOC case. | Not analysis-result retrieval; do not present it as the customer reports API. |
| `/api/alerts`, `/api/cases`, `/api/evidence`, `/api/investigations`, `/api/reports`, `/api/response-management`, `/api/soc/routing` | Existing SOC/analyst workflows protected by SOC roles and mixed legacy stores. | Explicitly deny to customer principals. |
| `customer-app` | Health-only integration through the C# loopback bridge. No OIDC login or customer-data endpoint is called. | Keep this boundary until the new customer API and auth controls pass their gates. |

The synthetic report store has tenant and owner columns and can enforce an owner filter, but the public route is analyst-only and couples a new analysis to SOC delivery. It is therefore not safe to expose by simply loosening its role check.

## 3. Proposed architecture

```text
MailTrace Customer WinUI app
  ├─ System browser: OIDC Authorization Code + PKCE (S256)
  ├─ Windows native bridge: in-memory access token; DPAPI/Credential Manager refresh token
  └─ Allowlisted customer calls only
          │ loopback HTTP, bearer token, strict route allowlist
          ▼
Customer API / BFF (future, 127.0.0.1:8100)
  ├─ OIDC issuer/audience/signature/expiry validation
  ├─ Customer role and tenant/subject authorization on every operation
  ├─ Customer-scoped mailbox/sync/report metadata store
  └─ Narrow application-service adapter (future; no generic SOC proxy)
          │ explicitly approved service contract only
          ▼
Existing MailTrace analysis/SOC components (8002)
  SOC routes remain internal; transfer is a separate authorized workflow.
```

Port `8100` is proposed in the project plan; its availability and service deployment have not been validated in this design task. The customer API must bind to loopback for this desktop prototype. A loopback-only service is not a shared multi-user/business/bank deployment; centralized deployment requires a separately designed and reviewed hosting model.

### Service integration rule

The customer BFF may call only a small, versioned application-service contract with explicit identity and tenant arguments. It must not:

- Accept an arbitrary `path`, URL, HTTP method, or SOC route from the UI.
- Give the UI a bearer token/key with analyst, SOC, service, tenant-admin, or platform-admin permissions.
- Reuse the development `local-dev-analyst` principal.
- Query the SOC SQLite database directly or infer authorization from a message/report identifier.
- Retry, route, resolve, acknowledge, or create SOC cases on a customer’s behalf.

The present backend has no customer-scoped service-to-service API contract. Report retrieval/analysis integration therefore remains a blocker until a narrow contract is implemented and tested. Preferred boundary: customer services call approved shared application-layer use cases; internal SOC delivery is invoked separately only after its own policy/authorization gate.

## 4. Authentication and token lifecycle

### Proposed customer login

1. The native app gets only public identity-provider metadata for a separately registered **public/native OIDC client**.
2. Open the system browser for Authorization Code flow with PKCE using `S256`, random `state`, and `nonce`.
3. Use a registered loopback redirect URI with an ephemeral local callback listener (or an explicitly supported native-app redirect). Validate exact state, issuer, audience, nonce, signature, expiry, and token type.
4. Exchange the authorization code from the native host; never embed a client secret in the desktop app.
5. Request only OIDC identity scopes needed for sign-in (`openid`, `profile`, and verified `email` only if an approved feature requires it). Gmail authorization remains a separate OAuth client/token store and uses the already approved Gmail read-only scope.
6. Keep access tokens in memory. If a refresh token is issued and offline access is separately approved, protect it with Windows DPAPI/Credential Manager. Never put tokens in WebView `localStorage`, ordinary config, logs, crash reports, or URLs.
7. On logout, clear in-memory state and the protected local refresh token; call provider revocation when supported. Handle expiry/revocation as signed-out and require interactive login again.

**Identity provider:** `PENDING APPROVAL`. The code is IdP-agnostic OIDC; choose and register the actual customer IdP before implementation. Do not reuse Gmail OAuth credentials or confuse Gmail mailbox authorization with customer identity.

### API request authorization

- Every customer data route requires a bearer token whose issuer and audience are specifically configured for the Customer API.
- Customer API validates signature and standard claims, then maps trusted claims to an internal principal. User-provided `tenant_id`, role, owner, or email fields are never authoritative.
- Missing/invalid/expired token returns `401`; valid identity without required customer role returns `403`.
- Customer identity is `{issuer, subject}`; tenant comes from a trusted, allowlisted claim or server-side membership lookup. Email is an attribute, never the stable identity key.
- No API key or static shared secret is shipped to the customer app.

## 5. Authorization model and isolation

### Proposed roles

| Customer role | Allowed scope | Must not receive |
|---|---|---|
| `customer_user` | Own linked mailboxes, own sync state, own scan jobs, own sanitized reports and authorized aggregate counts. | Another user’s messages/reports, raw SAFE records, SOC alert/case internals, evidence by guessed ID. |
| `customer_tenant_admin` | Tenant-level mailbox inventory and aggregate operational status only, if separately approved and backed by complete tenant scoping. | Individual user mailbox content, unrestricted report bodies, SOC analyst actions, decryption authority by default. |
| `customer_support` | No default data access. Any break-glass support needs separate time-bounded approval and audit design. | Persistent impersonation, hidden access, automatic cross-tenant lookup. |

These are **proposed customer roles** and are not currently accepted by the backend auth role allowlist. They must not be mapped to `analyst`, `soc_lead`, `tenant_admin`, `admin`, `service`, or `platform_admin` merely to reuse an existing endpoint.

### Required object-scope rule

For every database lookup/update, derive `tenant_id` and `subject_id` from the verified principal and enforce them in the storage query/constraint. Example:

```sql
SELECT ... FROM customer_reports
WHERE report_id = ? AND tenant_id = ? AND owner_subject = ?
```

Never fetch by object ID alone and authorize afterward. Use composite ownership keys/constraints for tenant-owned records. Cross-owner tenant-admin access, where approved, must use a separate explicit path and audited policy. Return `404` for non-owned object identifiers where revealing existence would disclose another user’s data.

Current production backend is deliberately single-tenant until all legacy/file-backed stores are tenant-scoped. Therefore multiple business/bank tenants must remain disabled until an isolation inventory, migration plan, and cross-tenant tests pass.

## 6. Proposed Customer API route contract (not implemented)

All routes below are versioned under `/v1` on the future Customer API, not existing SOC routes.

| Route | Auth | Intended behavior / boundary |
|---|---|---|
| `GET /health` | Public, loopback only | Minimal process status, no dependency/configuration inventory. |
| `GET /ready` | Public, loopback only | Sanitized database/readiness state only; no secrets, tenant data, or optional integration configuration. |
| `GET /v1/me` | `customer_user` | Return opaque subject, tenant display identifier if allowed, and permitted role names; never return token claims wholesale. |
| `GET /v1/mailboxes` | `customer_user` | Current user’s provider and connection status only; no email content. |
| `POST /v1/mailboxes/{id}/connect` | `customer_user` + explicit consent | Start provider-specific OAuth; enforce one user/tenant ownership binding. Gmail and OIDC token material remain separate. |
| `DELETE /v1/mailboxes/{id}` | `customer_user` + explicit confirmation in later implementation | Disconnect/revoke the local provider grant and disable sync; no remote mail deletion. Not implemented now. |
| `GET /v1/protection/status` | `customer_user` | Actual local Agent/sync/watch status. Unknown stays unknown; no fabricated running status. |
| `POST /v1/scans` | `customer_user` + approved scan policy | Create an idempotent scan job only when a real authorized scan worker exists. Not available now. |
| `GET /v1/scans/{id}` | Owner-scoped `customer_user` | Return only the owner’s job state/timestamps/counts and analysis completeness. |
| `GET /v1/reports` | Owner-scoped `customer_user` | List sanitized reports owned by the subject; aggregate SAFE counts only. |
| `GET /v1/reports/{id}` | Owner-scoped `customer_user` | Return approved sanitized structured report fields; no raw body/MIME/attachments/full headers or SOC internals. |
| `POST /v1/reports/{id}/soc-transfer` | Not enabled by default | No customer route until evidence policy, explicit authorization, and secure transfer acknowledgment semantics are approved. |

Unsupported operations return a clear `404/501` or typed unavailable state. They must not call an analyst endpoint as a fallback.

## 7. Loopback and WebView2 boundary

- Bind the future Customer API to `127.0.0.1`, not `0.0.0.0`.
- Customer app continues to use the native bridge for API calls and token handling; the WebView must not receive refresh tokens or a broad SOC credential.
- The bridge must have a compile-time allowlist of API host, port, methods, and `/v1` paths; reject arbitrary URLs, redirects, and methods. Validate `Origin`/`Host` on the local service and require bearer auth on all data routes.
- Restrict local CORS to the packaged app/preview origins required by the integration. Do not broadly enable `*` or credentials.
- Health endpoints disclose no auth configuration, tenant, user, mailbox, or optional-integration secrets.
- Request IDs may be logged; bearer tokens, email addresses, message IDs, subjects, private URLs, and request bodies may not.
- Rate-limit login/session exchange and state-changing operations. Use idempotency keys for connect/disconnect and scan creation.

## 8. Explicit denylist for Customer API

Do not proxy or expose these existing paths to customer principals:

- `/api/alerts*`, `/api/cases*`, `/api/evidence*`, `/api/investigations*`, `/api/reports*`
- `/api/analyze-email`, `/api/analyze-thread`, `/api/synthetic-analysis*`
- `/api/employee/reports*` as a substitute for customer scan reports
- `/api/response-management*`, `/api/soc/routing*`, `/api/threat-hunting*`
- Any acknowledgement, resolution, assignment, retention-hold, evidence decrypt/download, SOC retry, or gateway action route

The current `synthetic-analysis` endpoint stores a report and attempts SOC delivery as part of its upload request. It is analyst-gated and its report read authorization is not the proposed customer role model. It must remain separate from a customer scan/report API until analysis and SOC transfer are decoupled behind approved application services.

## 9. Blockers before implementation

1. **Identity provider:** Choose the customer OIDC provider, native redirect registration, audience, required claims, membership source, and verified-email behavior.
2. **Role model:** Add and approve customer-specific roles and claims; do not reinterpret analyst/SOC roles.
3. **Tenant boundary:** Production backend currently requires one configured tenant while legacy stores are not comprehensively tenant-scoped. True multi-tenant/business/bank service is blocked.
4. **Customer API deployment:** Decide local-only desktop prototype (8100) versus centrally hosted multi-user service; verify port and lifecycle. Existing app auto-start only knows backend 8002 today.
5. **Service adapter:** No least-privilege 8100-to-8002 customer service contract exists. Do not solve this by using a broad analyst API key or direct SQLite access.
6. **Customer data contract:** Define report fields, retention, SAFE aggregate handling, mailbox ownership, disconnect/revocation, and tenant-admin aggregates.
7. **Privacy and evidence:** Gmail content remains blocked by approved policy. Quarantine, decryption, and SOC transfer stay disabled until separately approved.

## 10. Required verification gates for a future implementation

- OIDC tests: PKCE state/nonce/callback validation, issuer/audience/signature/expiry, bad/missing roles, revocation/expiry and logout.
- Authorization tests: user A cannot list/read/update user B’s mailbox, scan, or report; tenant A cannot access tenant B; guessed IDs return no data.
- Route matrix tests: customer roles receive `403` for every SOC/analyst/employee-only route; no fallback proxy exists.
- API key tests: packaged client contains no static credential; customer API rejects API-key auth.
- Loopback tests: remote bind denied; strict Origin/Host; redirects and arbitrary proxy paths rejected.
- Privacy tests: tokens and personal data absent from logs, browser storage, exception text, health output, and reports.
- Integration tests: temporary customer DB; mocked IdP and service adapter; separate SOC regression tests; no production database or real Gmail data.
- Fail-closed tests: missing tenant, membership, role, adapter credential, or privacy policy yields unavailable/denied, never implicit analyst access.

## 11. Current conclusion

The current customer app is safely limited to local backend health/readiness. The current backend has useful OIDC and owner-scoping building blocks, but does not provide the required customer role, tenant-wide multi-tenant readiness, customer login flow, or customer API boundary. Keep mailbox and customer-data screens unavailable until the blockers above are resolved and a separate implementation phase is approved.
