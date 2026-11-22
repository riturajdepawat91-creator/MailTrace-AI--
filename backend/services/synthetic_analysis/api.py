"""Authenticated synthetic EML analysis, sanitized persistence, and SOC delivery."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, File, Header, HTTPException, Request, UploadFile

from database.database import create_email_alert, get_investigation, save_investigation
from services.synthetic_analysis.engine import (
    MAX_SYNTHETIC_MESSAGE_BYTES,
    SyntheticInputError,
    analyze_synthetic_email,
)
from services.synthetic_analysis.store import (
    claim_delivery,
    create_or_get_report,
    fail_delivery,
    finish_delivery,
    get_report,
    make_idempotency_hash,
)
from services.synthetic_analysis.verification import verify_email_authentication

router = APIRouter(tags=["Synthetic Analysis"])
ANALYST_ROLES = {"analyst", "soc_lead", "tenant_admin", "platform_admin", "admin"}
_MAX_SOC_ATTEMPTS = 5


def _principal(request: Request):
    principal = getattr(request.state, "principal", None)
    roles = set(getattr(principal, "roles", ())) if principal else set()
    if principal is None or not roles.intersection(ANALYST_ROLES):
        raise HTTPException(status_code=403 if principal else 401, detail="Authenticated analyst access is required.")
    tenant_id = str(getattr(principal, "tenant_id", "") or "").strip()
    subject = str(getattr(principal, "subject_id", "") or "").strip()
    if not tenant_id or not subject:
        raise HTTPException(status_code=403, detail="A verified tenant and analyst identity are required.")
    return principal, roles, tenant_id, subject


def _soc_delivery(row: dict, tenant_id: str) -> dict:
    report = row["report"]
    analysis_id = row["analysis_id"]
    claim, state = claim_delivery(analysis_id, tenant_id, max_attempts=_MAX_SOC_ATTEMPTS)
    if state in {"DELIVERED", "IN_PROGRESS", "RETRY_LIMIT", "NOT_FOUND"}:
        return {"status": state, "attempts": (claim or row).get("delivery_attempts", 0), "investigation_id": (claim or row).get("investigation_id"), "alert_id": (claim or row).get("alert_id"), "case_id": (claim or row).get("case_id")}

    investigation_id = f"SYN-{analysis_id}"
    event_id = f"SYN-{analysis_id}"
    risk = report["risk"]
    score = max(0, min(100, int(risk["score"])))
    verdict = str(risk["verdict"])
    severity = verdict if verdict in {"HIGH", "CRITICAL"} else "MEDIUM"
    try:
        prior_investigation = get_investigation(investigation_id, tenant_id)
        if prior_investigation is None:
            save_investigation(
                investigation_id=investigation_id,
                filename="synthetic-analysis.eml",
                subject="Synthetic email analysis",
                sender="synthetic-fixture@invalid",
                recipient="synthetic-analysis@invalid",
                threat_score=score,
                threat_verdict=verdict,
                threat_confidence="DEMO_HEURISTIC_WITH_AUTH_EVIDENCE",
                analysis_json=json.dumps(report, separators=(",", ":")),
                tenant_id=tenant_id,
            )
        alert = create_email_alert(
            event_id=event_id,
            investigation_id=investigation_id,
            severity=severity,
            threat_score=score,
            confidence="DEMO_HEURISTIC_WITH_AUTH_EVIDENCE",
            recommended_action="SYNTHETIC_REVIEW_ONLY",
            policy_version=str(risk["policy_version"]),
            user_notice={
                "title": "Synthetic analysis report",
                "summary": "This SOC item was created from an explicitly synthetic test fixture.",
                "why_risky": ["Review the sanitized synthetic analysis evidence."],
                "next_steps": ["Review the attached sanitized analysis report."],
            },
            tenant_id=tenant_id,
        )
        if not alert:
            raise RuntimeError("SOC_ALERT_NOT_CREATED")
        finish_delivery(
            analysis_id, tenant_id,
            investigation_id=investigation_id,
            alert_id=str(alert["alert_id"]),
            case_id=str(alert.get("case_id") or "") or None,
        )
        delivered = get_report(analysis_id, tenant_id)
        return {"status": "DELIVERED", "attempts": delivered["delivery_attempts"], "investigation_id": investigation_id, "alert_id": str(alert["alert_id"]), "case_id": alert.get("case_id")}
    except Exception as exc:
        # Store only the exception class; never persist/log exception text that
        # may include request data. The sanitized report remains durable.
        fail_delivery(analysis_id, tenant_id, type(exc).__name__, max_attempts=_MAX_SOC_ATTEMPTS)
        pending = get_report(analysis_id, tenant_id)
        return {"status": pending["delivery_status"], "attempts": pending["delivery_attempts"], "error_code": pending["delivery_error_code"]}


@router.post("/api/synthetic-analysis", status_code=201)
async def analyze_synthetic_fixture(
    request: Request,
    file: UploadFile = File(...),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    try:
        _, _, tenant_id, subject = _principal(request)
        if not isinstance(idempotency_key, str):
            # Direct handler unit tests see FastAPI's HeaderInfo default object;
            # ASGI requests receive a validated string or None.
            idempotency_key = None
        if idempotency_key is not None and (not idempotency_key.strip() or len(idempotency_key) > 128):
            raise HTTPException(status_code=400, detail="Invalid idempotency key.")
        if not (file.filename or "").lower().endswith(".eml"):
            raise HTTPException(status_code=415, detail="Only synthetic .eml fixtures are accepted.")
        raw = await file.read(MAX_SYNTHETIC_MESSAGE_BYTES + 1)
        if len(raw) > MAX_SYNTHETIC_MESSAGE_BYTES:
            raise SyntheticInputError("Synthetic EML exceeds the 1 MiB prototype limit.")
        authentication = verify_email_authentication(raw)
        report = analyze_synthetic_email(raw, verification_results=authentication)
        key = idempotency_key.strip() if idempotency_key else str(uuid.uuid4())
        stored, created = create_or_get_report(
            tenant_id, subject, make_idempotency_hash(tenant_id, key), report
        )
        soc = _soc_delivery(stored, tenant_id)
        current = get_report(stored["analysis_id"], tenant_id, subject)
        return {
            "success": True,
            "duplicate": not created,
            "report": current["report"],
            "persistence": {"status": "STORED", "analysis_id": current["analysis_id"]},
            "soc_delivery": soc,
        }
    except HTTPException:
        raise
    except SyntheticInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Synthetic analysis failed safely.") from exc
    finally:
        await file.close()


def _readable_report(request: Request, analysis_id: str) -> dict:
    _, roles, tenant_id, subject = _principal(request)
    owner = None if roles.intersection({"soc_lead", "tenant_admin", "platform_admin", "admin"}) else subject
    row = get_report(analysis_id, tenant_id, owner)
    if row is None:
        raise HTTPException(status_code=404, detail="Synthetic report not found.")
    return row


@router.get("/api/synthetic-analysis/{analysis_id}")
def read_synthetic_report(analysis_id: str, request: Request):
    row = _readable_report(request, analysis_id)
    return {
        "success": True,
        "report": row["report"],
        "persistence": {"status": "STORED", "analysis_id": row["analysis_id"]},
        "soc_delivery": {
            "status": row["delivery_status"],
            "attempts": row["delivery_attempts"],
            "investigation_id": row["investigation_id"],
            "alert_id": row["alert_id"],
            "case_id": row["case_id"],
            "error_code": row["delivery_error_code"],
        },
    }


@router.post("/api/synthetic-analysis/{analysis_id}/soc-retry")
def retry_synthetic_soc_delivery(analysis_id: str, request: Request):
    row = _readable_report(request, analysis_id)
    return {"success": True, "soc_delivery": _soc_delivery(row, row["tenant_id"])}
