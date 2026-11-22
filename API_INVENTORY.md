# MailTrace AI — Existing API Inventory

Static route inventory from `backend/main.py` and `backend/routes/`. Auth details are policy-level; actual access depends on configured environment and middleware. Health/readiness and OIDC metadata have explicit public exceptions; webhook endpoints use their own signature contract.

## Core endpoints in `backend/main.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service identity/version. |
| GET | `/api/auth/config` | Public OIDC client metadata. |
| GET | `/api/auth/me` | Current authenticated principal. |
| GET | `/api/health` | Process/service health. |
| GET | `/api/ready` | Database/integration/readiness and release-gate status. |
| GET | `/api/reports/map-view/{investigation_id}` | Investigation map/intelligence view. |
| GET | `/api/cases/derived-high-risk` | Derived high-risk cases view. |
| GET | `/api/campaigns` | List campaigns. |
| GET | `/api/campaigns/{campaign_id}` | Campaign detail. |
| POST | `/api/response-management/plan` | Build response plan. |
| POST | `/api/recommendations/build` | Build recommended actions. |
| POST | `/api/ioc-timeline/build` | Build IOC timeline. |
| POST | `/api/threat-hunting/hunt` | Run local threat-hunt query. |
| POST | `/api/response-management/verification` | Evaluate response evidence. |
| POST | `/api/response-management/transition` | Simulated response workflow transition. |
| POST | `/api/analyze-thread` | Analyze a message thread. |
| POST | `/api/webhooks/email` | Signed generic RFC822 webhook intake, policy decision and SOC analysis path. |
| POST | `/api/webhooks/email/{event_id}/action-receipt` | Record signed gateway action receipt. |
| POST | `/api/employee/reports` | Employee suspicious-email report. |
| GET | `/api/employee/reports` | List permitted employee reports. |
| GET | `/api/employee/reports/{report_id}` | Employee report detail/status. |
| GET | `/api/alerts` | List SOC alerts. |
| POST | `/api/alerts/{alert_id}/acknowledge` | Acknowledge alert. |
| GET | `/api/alerts/{alert_id}/history` | Alert event history. |
| GET | `/api/alerts/{alert_id}/gateway-action-integrity` | Verify associated action receipt chain. |
| POST | `/api/alerts/{alert_id}/resolve` | Resolve alert. |
| POST | `/api/analyze-email` | Upload and analyze EML/MSG; existing SOC persistence path. |
| GET | `/api/privacy/retention/{investigation_id}` | Read retention decision/state. |
| PUT | `/api/privacy/retention/{investigation_id}/holds` | Apply/remove configured retention holds. |
| GET | `/api/evidence/{evidence_id}` | Read evidence metadata/content per policy. |
| GET | `/api/evidence/{evidence_id}/integrity` | Read evidence integrity status. |
| POST | `/api/privacy/redact` | Redact configured sensitive data. |
| GET | `/api/threat-intelligence/live` | Read live/local TI status or stream snapshot. |
| GET | `/api/threat-intelligence/stream` | Server-sent TI updates. |

## Router endpoints

### Investigations (`/api/investigations`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/investigations` | List investigation summaries. |
| GET | `/api/investigations/{investigation_id}` | Investigation detail. |

### Cases (`/api/cases`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/cases` | List tenant-scoped cases. |
| POST | `/api/cases` | Create case. |
| GET | `/api/cases/{case_id}` | Case detail. |
| PATCH | `/api/cases/{case_id}` | Update case fields/state. |
| POST | `/api/cases/{case_id}/claim` | Claim case for analyst. |
| POST | `/api/cases/{case_id}/renew` | Renew claim lease. |
| POST | `/api/cases/{case_id}/release` | Release claim lease. |
| GET | `/api/cases/{case_id}/history` | Case history. |
| GET | `/api/cases/{case_id}/audit` | Case audit chain/events. |
| POST | `/api/cases/{case_id}/investigations/{investigation_id}` | Link investigation to case. |
| POST | `/api/cases/{case_id}/notes` | Add analyst note. |

### SOC routing (`/api/soc/routing`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/soc/routing/queue` | Read queue and reconcile pending routing. |
| GET | `/api/soc/routing/alerts` | List SOC routing alerts. |
| POST | `/api/soc/routing/alerts/{alert_id}/acknowledge` | Acknowledge routing alert. |
| POST | `/api/soc/routing/alerts/{alert_id}/resolve` | Resolve routing alert. |
| GET | `/api/soc/routing/analysts` | Read analyst roster. |
| GET | `/api/soc/routing/cases/{case_id}` | Read case route. |
| GET | `/api/soc/routing/cases/{case_id}/history` | Read routing events. |
| POST | `/api/soc/routing/queues` | Configure queue. |
| PUT | `/api/soc/routing/employee-regions/{subject_id}` | Configure employee region. |
| PUT | `/api/soc/routing/analysts/{subject_id}` | Configure analyst skills/capacity. |
| POST | `/api/soc/routing/cases/{case_id}/assign` | Assign analyst. |
| POST | `/api/soc/routing/cases/{case_id}/route` | Re-route case. |

### IP intelligence (`/api/ip-intelligence`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ip-intelligence` | Analyze one IP. |
| POST | `/api/ip-intelligence/batch` | Analyze a bounded set of IPs. |
| GET | `/api/ip-intelligence/health` | Provider/service health. |

### Threat intelligence (`/api/threat-intelligence`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/threat-intelligence/status` | Source/provider sync status. |
| POST | `/api/threat-intelligence/sync` | Trigger feed sync. |
| GET | `/api/threat-intelligence/indicators` | Query indicators. |

## SIH integration implications

There is no Graph mailbox endpoint, user mailbox registration API, local user scan-history API, user OTP API, or user-dashboard API in the current inventory. `/api/webhooks/email` is a backend intake seam and should be treated as SOC persistence/escalation until a separate minimal, signed CRITICAL-only intake contract is agreed. Keep existing SOC routes and port intact.

