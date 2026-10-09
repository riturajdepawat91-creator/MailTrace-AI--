# MailTrace AI

AI-assisted email threat detection and forensic investigation prototype. The frontend is served locally and the FastAPI backend provides analysis, case management, SOC routing, alerts, employee reporting, and evidence workflows.

## Local start

1. Install Python 3.11.
2. Run `START_MAILTRACE.ps1` from PowerShell, or install dependencies with `python -m pip install -r backend/requirements.txt` and start the backend from `backend` using `python -m uvicorn main:app --host 127.0.0.1 --port 8000`.
3. Serve `frontend` on port 5503 (the launcher does this automatically).

Local databases, environment secrets, training datasets, generated runtime artifacts, and trained model binaries are intentionally excluded. Configure integrations and credentials through environment variables; do not commit secrets. This repository snapshot is not a production deployment configuration.
