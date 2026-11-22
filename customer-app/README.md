# MailTrace AI Customer App

An isolated customer-facing dashboard preview and WinUI 3 desktop host. All application source, icons, styles, configuration and dependencies are contained in this directory. It does not replace or modify the internal SOC dashboard.

The UI includes Overview, Mailbox Connections, Continuous Protection, Manual Scan, Scan Activity, Threat Center, Quarantine, Reports, Performance, Privacy Center, Device & Agent Status, Mailbox Security, and Settings. Views with no customer API remain empty or explicitly unavailable. Manual scan options are configuration-only and cannot launch, pause, resume, cancel, or retry a real job.

## Run the visual preview

Requirements: Node.js 20 or later. From this directory:

```powershell
npm test
node --check server.mjs
node --check src/app.js
./start-preview.ps1
```

Open the printed `http://127.0.0.1:4173` address in a browser. Set `MAILTRACE_CUSTOMER_PREVIEW_PORT` to another available port if 4173 is occupied. Stop the preview with `./stop-preview.ps1`.

The preview server serves only this application's static files, binds to loopback on port 4173, and proxies only `GET /api/health` and `GET /api/ready` to a loopback MailTrace API. It does not use customer mailbox, analysis, report, or SOC endpoints.

## Windows desktop host

`windows/MailTraceCustomer.csproj` is a separate WinUI 3 / WebView2 host for Windows 10 19041 or later, .NET 8, and Windows App SDK 1.6. Build on a Windows machine with the .NET 8 SDK and Windows App SDK workload/package restore available:

```powershell
dotnet build windows/MailTraceCustomer.csproj
```

The host uses native window controls and supplies local device telemetry. The web UI remains separately previewable in a browser. No .NET SDK was available on the authoring machine, so the native project has not been compiled or run here.

## Current service boundary

The customer app checks the local API health/readiness endpoints on launch and refreshes the status while the app is visible. If the default API on `http://127.0.0.1:8002` is unavailable, the WinUI host starts the configured existing backend in a hidden process. The installer records the repository's `backend` directory when its local Python virtual environment is present; alternatively set `MAILTRACE_BACKEND_DIR` for the user running the app. The backend must have `main.py` and `venv\Scripts\python.exe`. Auto-start is restricted to the default loopback API, uses the existing 8002 port and the backend's normal environment/background-worker settings, and leaves the backend running when the UI closes. The loopback API address defaults to `http://127.0.0.1:8002` and can be changed in Settings; the app restricts it to loopback hosts. This integration reports API/database readiness only. Mailbox connection, continuous scanning, customer result feeds, quarantine, evidence vault, and SOC synchronization are unavailable in the existing customer-facing API surface. Dashboard counts and results therefore remain empty/unavailable. The app does not call the internal synthetic-analysis route, fetch Gmail content, or access customer email.

The MailTrace shield-envelope mark in `assets/mailtrace-mark.svg` reproduces the exact vector path data already present in the project's MailTrace logo and is used for the browser favicon, titlebar, sidebar and hero. The UI falls back to a bundled shield glyph if the SVG fails to load. Icons are from the locally bundled `src/icons.js` registry; there are no external icon libraries, CDNs, remote fonts, or runtime downloads.
