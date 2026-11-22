# Customer App UI Completion Report

## Scope and isolation

UI work was performed only in `customer-app/`. The existing SOC backend, frontend, APIs, database, Gmail connector, and ports were not changed. No mailbox was connected and no email content was fetched.

## UI completed

- Replaced the previous approximated logo with an isolated local SVG containing the exact SOC shield, envelope and trace paths and the same CSS colors from `frontend/index.html` and `frontend/style.css`; added an SVG favicon and a shield fallback for failed image loads.
- Restored the five Overview Quick Actions and kept cards, charts, activity, health and mailbox counts empty until an authorized service reports real data.
- Added dedicated customer views for Mailbox Connections, Continuous Protection, Manual Scan, Scan Activity, Threat Center, Quarantine, Reports, and Settings; retained Performance, Privacy Center, Device & Agent Status and Mailbox Security.
- Added provider status cards for Gmail, Outlook/Microsoft 365 and Exchange. They do not begin OAuth or mailbox access.
- Added manual scan configuration for 1, 3, 7, 14 and 30 days, folder, scan mode, message count and data-size limits, configuration summary, progress/completion/failure states, and start/pause/resume/cancel/retry controls. These controls do not submit a scan; operation controls requiring a real job are disabled and Start reports that no scan began.
- Added empty-state and evidence/privacy indicators for SAFE, MODERATE, HIGH, CRITICAL and unavailable/incomplete findings. Quarantine actions remain disabled.
- Added report filters/export state and read-only settings for privacy, local processing/resource limits, reconciliation, notifications and Agent status.
- Improved sidebar and workspace scrolling, responsive card grids, spacing, typography, contrast, and focus-visible keyboard outlines.

## Files changed

- `src/index.html`
- `src/styles.css`
- `src/app.js`
- `src/ui-state.js` (new)
- `tests/customer-app.test.mjs`
- `README.md`
- `CUSTOMER_APP_UI_COMPLETION_REPORT.md` (new)

Existing bundled `assets/mailtrace-mark.svg`, icon registry and WinUI host source remain in place.

## Validation

- `npm test`: **12 passed, 0 failed, 0 skipped**.
- `node --check src/app.js`, `node --check src/ui-state.js`, `node --check server.mjs`: passed.
- Asset-path tests confirm local page references resolve within `customer-app` and the WebView2 asset layout includes the bundled logo.
- `git diff --check`: passed; Git printed line-ending normalization warnings for pre-existing project files, with no whitespace errors.
- Preview server started and bound to `127.0.0.1:4173`. A browser screenshot could not be verified: the in-app browser could not connect to loopback, and the Windows computer-use session stopped because it could not confidently determine Brave's current URL. No visual rendering success is claimed.
- .NET SDK availability: **not installed** (`dotnet` command unavailable). WinUI 3 build and native Windows rendering were not verified.

## Remaining limitations

- Mailbox authorization/synchronization, customer scan execution, scan history, threat/report feeds, quarantine/evidence APIs, Agent controls, and configurable processing/reconciliation settings are not exposed by the current customer API. Corresponding UI is honest placeholder/unavailable state.
- The native WinUI app cannot be built in this environment without .NET 8 and the Windows App SDK toolchain.
- Browser and native visual QA remain pending because local browser access was blocked in this session.

## Backend connection follow-up — 2026-11-22

- Added an automatic, read-only connection check when the customer app opens, on window focus, and every 20 seconds while visible. The UI requests only `/api/health` and `/api/ready` through the existing loopback-only WebView2 bridge or the preview server adapter.
- Backend default remains `http://127.0.0.1:8002`; Settings may select another loopback URL. No customer, mailbox, analysis, SOC, or evidence endpoint is called.
- Started the existing backend on `127.0.0.1:8002` with its background workers disabled for this session. Live verification returned API `ok`, readiness `ok`, and database `ok`.
- Rebuilt and installed the customer desktop app. The running Overview was visually verified to show `API CONNECTED` and `Ready`. Mailbox sync, scanning, evidence encryption, threat results, and SOC transfer correctly remain unavailable/unverified.
- Follow-up validation: **13 customer-app tests passed, 0 failed, 0 skipped**; JavaScript syntax checks and `git diff --check` passed. Native publish succeeded with 0 warnings and 0 errors.
- The preview port 4173 was already occupied; it was not changed or stopped. Desktop verification used the installed WinUI app.

## Backend auto-start follow-up — 2026-11-22

- The WinUI host now checks the default API first and starts the existing local backend hidden on `127.0.0.1:8002` only when it cannot reach it. A named semaphore prevents duplicate launches across app instances.
- The installer includes a local backend path hint only when the build machine has the repository backend and its virtual-environment Python. `MAILTRACE_BACKEND_DIR` can override that path. No backend files, database, `.env`, credentials, or dependencies are copied into the customer installer.
- The launched backend inherits its normal environment and background-worker settings; its output is drained and discarded. The backend remains running after the customer UI closes so the customer app cannot stop a backend used by other local workflows.
- For end-to-end auto-start verification, stopped the backend process started for this task, launched the updated desktop app, and confirmed it started a new backend process on 8002. Live `/api/health` and `/api/ready` returned `ok`, including database `ok`; the installed dashboard showed API connected / ready.
- Final validation: **14 customer-app tests passed, 0 failed, 0 skipped**; JavaScript syntax checks passed; Visual Studio MSBuild installer publish succeeded with 0 warnings and 0 errors. Mailbox and scan features remain unavailable.
- The final backend auto-start verification uses the backend's normal configured background-worker behavior, matching the existing startup launcher.
