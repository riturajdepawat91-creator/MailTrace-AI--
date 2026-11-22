# MailTrace AI — Feature Inventory

**Phase:** 0 repository audit  
**Inventory rule:** “Present” means source is present; it does not mean a live provider, external tenant, or production deployment was validated.

| Feature | Existing implementation | Readiness / boundaries |
|---|---|---|
| SOC FastAPI API | `backend/main.py`, `backend/routes/` | Active local app; 8002 in launcher and README. |
| SOC browser dashboard | `frontend/` | Existing dashboard; current repo serves on 5503, while SIH context identifies 5504. |
| Investigation history | `backend/database/database.py`, investigation routes | SQLite persistence includes serialized analysis data. |
| Case and incident workflow | `routes/cases.py`, `services/case_management/`, DB | Create/update, notes, investigation links, claim/renew/release, audit trail; role/claim guards exist. |
| SOC routing and assignment | `routes/soc_routing.py`, `services/case_routing.py`, DB | Queues, regional mappings, analyst roster/capacity, central fallback, manual assignment and reconciliation. |
| SLA/escalation | DB routines and background worker | Persisted deadlines, alert lifecycle, cooldown/escalation tests. |
| Employee reporting/alerts | `main.py`, DB, frontend | Employee report intake/status, alerts, acknowledge/resolve; local identity integration remains incomplete. |
| API authentication | `services/access_control.py`, middleware | Loopback dev mode, hashed API-key configuration, OIDC JWT/JWKS verification and role mapping; no OTP. Production is single-tenant. |
| EML and MIME | `email_parser.py`, `email_parsing.py` | Python email parser; bounded bytes/parts/depth/headers; partial parse status. |
| Outlook MSG parsing | `email_parser.py` | `extract-msg` normalization; this parses files and does not connect to Outlook mailbox. |
| Header/auth evidence | `email_parser.py`, `email_forensics/authentication_analyzer.py` | Observed header claims untrusted. Independent SPF requires authenticated SMTP context; DKIM validation and DMARC policy lookup exist with scope limits. |
| URL/HTML link analysis | `url_extraction.py`, `url_analysis.py`, `advanced_url_intelligence.py`, `link_deception_intelligence.py` | URL evidence, static URL/deception checks, displayed-vs-target link inspection; no browser detonation implied. |
| IOC extraction/normalization | `threat_intelligence/ioc_normalizer.py` | IP/domain/URL/hash extraction and normalized result structures. |
| IP intelligence | legacy `ip_intelligence.py`; v2 `ip_intelligence_v2/` | Address policy, network/reputation/DNS/geolocation context; enrichment is context, not identity proof. |
| Domain intelligence | `domain_intelligence.py`, `brand_registry.py`, domain alignment | DNS/MX/age/lookalike and alignment context; DNS/domain egress is opt-in/configuration-sensitive. |
| Threat intelligence | local store, v2 engine, provider adapters and sync routes | Local feed sync and optional provider adapters. Credentials and live responses are not confirmed; historical report says provider adapters were not all production-wired at that time. |
| Attachment analysis | `attachment_intelligence/` | Metadata/type/static analysis; optional ClamAV scan. Detonation/sandbox is explicitly not configured. |
| Rule-based detection | parser rules, visual phishing, threat hunting, campaign correlation | Evidence-producing engines are present; verification is code/test based, not a field-accuracy claim. |
| AI/ML inference | `email_ai/` | TF-IDF/logistic model loaders, feature pipeline, explainability, risk fusion, missing-model states. Training readiness requires hash-bound external approvals. |
| Unified risk | `email_ai/intelligence_fusion.py` | Canonical score, evidence groups, confidence/reliability and explanation; score is not a probability. |
| Evidence custody/integrity | `evidence_custody/`, `integrity_anchoring/`, API | File-backed vault/ledger and integrity status. Existing path can persist raw evidence; do not apply to SAFE/LOW user emails. |
| Privacy/retention | `privacy_governance/`, `data_protection.py`, routes | Retention decisions/holds and optional AES-GCM field protection; development without key leaves sensitive DB values unencrypted. |
| Gateway policy and receipts | webhook, `email_alerting.py`, `mail_gateway/adapter.py` | Signed webhook intake and action-receipt contract; default vendor adapter is unconfigured and does no real quarantine. |
| Microsoft Graph connector | None found | New development: OAuth app/mailbox, subscription and delta fallback, retry/state cursor, message fetch policy. |
| User-side backend/dashboard | None found | New development: independent user API/UI, scan history without SAFE raw content, privacy controls and policy-bound quarantine. |
| Windows background Agent | None found | New development: C#/.NET Worker Service, Windows service lifecycle, DPAPI/Credential Manager token store and secure local channel. Python bridge is not this agent. |
| Passwordless email/mobile OTP | None found | New development: OTP generation/delivery, expiry/replay/rate limits, session management and server-side role checks. |

