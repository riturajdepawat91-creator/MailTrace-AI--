# MailTrace AI — SIH Reuse Matrix

Classification is for the specified Outlook → Windows Agent → User Backend → shared analysis → risk/evidence → Central SOC demonstration. “Without changes” means usable as a service/library under its existing contract, not that production rollout is proven.

| Capability / module | Class | Recommendation and reason |
|---|---:|---|
| EML/MIME parsing: `services/email_parsing.py` | 1 | Reuse byte/part/depth/header limits and diagnostics. Keep raw message in memory on SAFE/LOW path. |
| Header/body/attachment extraction: `services/email_parser.py` helpers | 2 | Reuse extraction logic, but refactor `parse_email()` so analysis can be invoked without SOC persistence, implicit external lookups, or mixed gateway behavior. |
| URL extraction / link deception | 1 | Reuse deterministic analyzers with bounded inputs and explicit status; ensure external URL fetching is not introduced. |
| IOC normalization | 1 | Reuse pure normalization/extraction with no raw-content logging. |
| IP/domain intelligence | 2 | Reuse under explicit provider policy/time budgets; make unavailable/not-checked states visible and avoid sending SAFE message content externally. |
| Email forensics (received chain/timeline/authentication) | 2 | Reuse after defining trusted acquisition fields from Graph; uploaded headers remain untrusted and cannot establish sender origin. |
| Attachment static metadata | 2 | Reuse on in-memory bytes under the existing limits. External ClamAV is optional and requires policy/configuration; no detonation is present. |
| Threat rules and email classification | 2 | Reuse as evidence providers; review their output contract and scoring interactions through the shared core. |
| Email AI inference/model loader | 2 | Reuse inference only if model artifact exists and can be loaded; treat missing model as unavailable. Do not retrain until rights/label/privacy approvals clear. |
| Risk fusion and explanation | 2 | Reuse canonical score contract after extracting a stable, side-effect-free analysis result. Keep score separate from ML probability/confidence. |
| SOC API key/OIDC middleware | 3 | Keep for the existing SOC. User platform needs separate local OTP/session auth and mailbox OAuth; never conflate Graph OAuth with MailTrace login. |
| Cases, routing, analyst assignment, SLA | 1 | Reuse through existing SOC APIs for approved CRITICAL escalation. Preserve claims, roles, tenant scoping and idempotency. |
| Evidence custody / privacy governance | 2 | Reuse only for policy-authorized HIGH/CRITICAL evidence after ensuring encryption keys are configured; add explicit interfaces for encrypted local user quarantine and controlled export. |
| SOC webhook + action receipt | 3 | Potential integration bridge for signed server-to-server events; adapt central SOC intake to a minimal CRITICAL evidence package. Current endpoint persists investigation and is not a Graph connector. |
| Default mail gateway adapter | 3 | Its contract is reusable, but adapter is deliberately unconfigured. SIH objective can demonstrate detection/transfer; do not claim mailbox quarantine until a real adapter is implemented. |
| Existing SOC dashboard | 1 | Preserve and extend only if needed to show received central case/evidence; do not replace with the user UI. Resolve port discrepancy first. |
| Existing Python bridge | 5 | Not required for the target mail workflow unless separately shown to support local orchestration. It is not a Windows Service or Graph connector. |
| Existing SQLite SOC persistence | 5 for SAFE/LOW | Avoid invoking it for SAFE/LOW because investigation analysis data is persisted. Retain existing SOC schema/workflows for escalated cases. |
| Microsoft Graph / Windows Agent / local User API/UI / OTP | 4 | Build new components. No implementations were found. |
| Multi-tenant deployment, enterprise production certification | 5 for immediate demo | Out of SIH scope; maintain the current SOC single-tenant guard and local-demo boundaries. |

## Shared analysis boundary to introduce

Create a small service contract that accepts a normalized message (RFC822 bytes plus trusted acquisition metadata) and returns structured findings, risk score/tier, confidence, evidence references, and analysis status. It must not persist, alert, transfer, or mutate gateway state by itself. The existing SOC endpoint can call this contract and continue its current persistence behavior; the new User Backend can call it in memory and apply the separate user privacy policy. This avoids cloning parsers while preventing SAFE data from flowing through the SOC persistence path.

