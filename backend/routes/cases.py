from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import uuid

from database.database import get_connection, claim_case_for_analyst, release_case_claim


router = APIRouter(
    prefix="/api/cases",
    tags=["Cases"]
)


# ==========================================
# REQUEST MODELS
# ==========================================

class CreateCaseRequest(BaseModel):

    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "LOW"


class UpdateCaseRequest(BaseModel):

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None


class AddNoteRequest(BaseModel):

    note: str
    author: Optional[str] = "Analyst"


def _require_analyst_identity(request: Request):
    principal = getattr(request.state, "principal", None)
    if (
        principal is None
        or not principal.roles.intersection(
            {"analyst", "soc_lead", "tenant_admin", "platform_admin", "admin"}
        )
        or not principal.subject_id
    ):
        raise HTTPException(
            status_code=403,
            detail="A SOC analyst identity is required for case claiming.",
        )
    return principal


def _enforce_case_claim_owner(connection, case_id: str, request: Request):
    principal = getattr(request.state, "principal", None)
    if principal is None:
        return
    active = connection.execute("""
        SELECT assigned_analyst, lease_expires_at
        FROM case_claims
        WHERE case_id=? AND tenant_id=? AND status='ACTIVE'
          AND datetime(lease_expires_at) > datetime('now')
    """, (case_id, principal.tenant_id)).fetchone()
    if active and principal.subject_id != active["assigned_analyst"]:
        raise HTTPException(
            status_code=423,
            detail="Another analyst currently owns this case claim.",
        )


@router.post("/{case_id}/claim")
def claim_case(case_id: str, request: Request):
    principal = _require_analyst_identity(request)
    assignment, claimed = claim_case_for_analyst(
        case_id=case_id,
        tenant_id=principal.tenant_id,
        analyst_subject=principal.subject_id,
        lease_minutes=20,
    )
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    if not claimed:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Case is currently claimed by another analyst.",
                "assignment": assignment,
            },
        )
    return {"success": True, "assignment": assignment}


@router.post("/{case_id}/release")
def release_case(case_id: str, request: Request):
    principal = _require_analyst_identity(request)
    assignment, released = release_case_claim(
        case_id=case_id,
        tenant_id=principal.tenant_id,
        analyst_subject=principal.subject_id,
    )
    if assignment is None:
        raise HTTPException(status_code=404, detail="Case has no claim.")
    if not released:
        raise HTTPException(
            status_code=409,
            detail="Only the analyst who currently owns the claim can release it.",
        )
    return {"success": True, "assignment": assignment}


# ==========================================
# LIST CASES
# ==========================================

@router.get("")
def list_cases(request: Request):

    connection = get_connection()

    try:

        rows = connection.execute("""
            SELECT
                cases.case_id,
                cases.title,
                cases.description,
                cases.severity,
                cases.status,
                cases.threat_score,
                cases.created_at,
                cases.updated_at,
                cc.assigned_analyst,
                cc.claimed_at,
                cc.lease_expires_at,
                cc.status AS assignment_status
            FROM cases
            LEFT JOIN case_claims cc
              ON cc.case_id=cases.case_id
             AND cc.tenant_id=?
             AND cc.status='ACTIVE'
             AND datetime(cc.lease_expires_at) > datetime('now')
            WHERE cases.tenant_id = ?
              AND (cases.title NOT LIKE 'Automated % email review %'
               OR EXISTS (
                    SELECT 1
                    FROM email_alerts a
                    WHERE a.case_id = cases.case_id
                      AND a.recommended_action = 'QUARANTINE'
                      AND a.confidence = 'HIGH'
                 )
            ORDER BY cases.created_at DESC
        """, (getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"), getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchall()

        return {
            "success": True,
            "count": len(rows),
            "cases": [dict(row) for row in rows]
        }

    finally:

        connection.close()


# ==========================================
# GET SINGLE CASE
# ==========================================

@router.get("/{case_id}")
def get_case(case_id: str, request: Request):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT
                cases.case_id,
                cases.title,
                cases.description,
                cases.severity,
                cases.status,
                cases.threat_score,
                cases.created_at,
                cases.updated_at,
                cc.assigned_analyst,
                cc.claimed_at,
                cc.lease_expires_at,
                cc.status AS assignment_status
            FROM cases
            LEFT JOIN case_claims cc
              ON cc.case_id=cases.case_id
             AND cc.tenant_id=?
             AND cc.status='ACTIVE'
             AND datetime(cc.lease_expires_at) > datetime('now')
            WHERE cases.case_id = ?
              AND cases.tenant_id = ?
              AND (
                    title NOT LIKE 'Automated % email review %'
                    OR EXISTS (
                        SELECT 1
                        FROM email_alerts a
                        WHERE a.case_id = cases.case_id
                          AND a.tenant_id = ?
                          AND a.recommended_action = 'QUARANTINE'
                          AND a.confidence = 'HIGH'
                    )
              )
        """, (
            getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"),
            case_id,
            getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"),
            getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"),
        )).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        investigations = connection.execute("""
            SELECT
                ci.investigation_id,
                i.filename,
                i.subject,
                i.sender,
                i.recipient,
                i.threat_score,
                i.threat_verdict,
                i.threat_confidence,
                i.created_at
            FROM case_investigations ci
            LEFT JOIN investigations i
                ON i.investigation_id = ci.investigation_id
            WHERE ci.case_id = ? AND ci.tenant_id = ?
            ORDER BY ci.created_at DESC
        """, (case_id, getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchall()

        notes = connection.execute("""
            SELECT
                id,
                note,
                author,
                created_at
            FROM case_notes
            WHERE case_id = ? AND tenant_id = ?
            ORDER BY created_at DESC
        """, (case_id, getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchall()

        evidence = connection.execute("""
            SELECT
                id,
                evidence_type,
                value,
                description,
                investigation_id,
                created_at
            FROM evidence
            WHERE case_id = ? AND tenant_id = ?
            ORDER BY created_at DESC
        """, (case_id, getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchall()

        case_payload = dict(case)
        principal = getattr(request.state, "principal", None)
        case_payload["assignment_mine"] = bool(
            principal
            and principal.subject_id
            and case_payload.get("assigned_analyst") == principal.subject_id
            and case_payload.get("assignment_status") == "ACTIVE"
        )

        return {
            "success": True,
            "case": case_payload,
            "investigations": [dict(row) for row in investigations],
            "notes": [dict(row) for row in notes],
            "evidence": [dict(row) for row in evidence]
        }

    finally:

        connection.close()


# ==========================================
# CREATE CASE
# ==========================================

@router.post("")
def create_case(request: CreateCaseRequest, http_request: Request):

    case_id = (
        "CASE-"
        + uuid.uuid4().hex[:10].upper()
    )

    severity = (
        request.severity or "LOW"
    ).upper()

    connection = get_connection()

    try:

        connection.execute("""
            INSERT INTO cases (
                case_id,
                tenant_id,
                title,
                description,
                severity,
                status,
                threat_score
            )
            VALUES (?, ?, ?, ?, ?, 'OPEN', 0)
        """, (
            case_id,
            getattr(getattr(http_request.state, "principal", None), "tenant_id", "__local__"),
            request.title,
            request.description or "",
            severity
        ))

        connection.commit()

        return {
            "success": True,
            "case": {
                "case_id": case_id,
                "title": request.title,
                "description": request.description or "",
                "severity": severity,
                "status": "OPEN",
                "threat_score": 0
            }
        }

    finally:

        connection.close()


# ==========================================
# UPDATE CASE
# ==========================================

@router.patch("/{case_id}")
def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    http_request: Request,
):

    connection = get_connection()

    try:

        existing = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, getattr(getattr(http_request.state, "principal", None), "tenant_id", "__local__"))).fetchone()

        if existing is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, http_request)

        fields = []
        values = []

        if request.title is not None:
            fields.append("title = ?")
            values.append(request.title)

        if request.description is not None:
            fields.append("description = ?")
            values.append(request.description)

        if request.severity is not None:
            fields.append("severity = ?")
            values.append(request.severity.upper())

        if request.status is not None:
            fields.append("status = ?")
            values.append(request.status.upper())

        if not fields:

            raise HTTPException(
                status_code=400,
                detail="No fields provided for update."
            )

        fields.append(
            "updated_at = CURRENT_TIMESTAMP"
        )

        values.append(case_id)

        connection.execute(
            f"""
            UPDATE cases
            SET {", ".join(fields)}
            WHERE case_id = ? AND tenant_id = ?
            """,
            values + [getattr(getattr(http_request.state, "principal", None), "tenant_id", "__local__")]
        )

        connection.commit()

        return {
            "success": True,
            "message": "Case updated successfully."
        }

    finally:

        connection.close()


# ==========================================
# ADD INVESTIGATION TO CASE
# ==========================================

@router.post("/{case_id}/investigations/{investigation_id}")
def attach_investigation(
    case_id: str,
    investigation_id: str,
    request: Request,
):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, request)

        investigation = connection.execute("""
            SELECT
                investigation_id,
                threat_score
            FROM investigations
            WHERE investigation_id = ? AND tenant_id = ?
        """, (investigation_id, getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"))).fetchone()

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        connection.execute("""
            INSERT OR IGNORE INTO case_investigations (
                case_id,
                tenant_id,
                investigation_id
            )
            VALUES (?, ?, ?)
        """, (
            case_id,
            getattr(getattr(request.state, "principal", None), "tenant_id", "__local__"),
            investigation_id
        ))

        connection.execute("""
            UPDATE cases
            SET
                threat_score = MAX(
                    threat_score,
                    ?
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE case_id = ? AND tenant_id = ?
        """, (
            int(investigation["threat_score"] or 0),
            case_id,
            getattr(getattr(request.state, "principal", None), "tenant_id", "__local__")
        ))

        connection.commit()

        return {
            "success": True,
            "message": "Investigation attached to case."
        }

    finally:

        connection.close()


# ==========================================
# ADD NOTE
# ==========================================

@router.post("/{case_id}/notes")
def add_case_note(
    case_id: str,
    request: AddNoteRequest,
    http_request: Request,
):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ? AND tenant_id = ?
        """, (case_id, getattr(getattr(http_request.state, "principal", None), "tenant_id", "__local__"))).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        _enforce_case_claim_owner(connection, case_id, http_request)

        cursor = connection.execute("""
            INSERT INTO case_notes (
                case_id,
                tenant_id,
                note,
                author
            )
            VALUES (?, ?, ?, ?)
        """, (
            case_id,
            getattr(getattr(http_request.state, "principal", None), "tenant_id", "__local__"),
            request.note,
            request.author or "Analyst"
        ))

        connection.commit()

        return {
            "success": True,
            "note_id": cursor.lastrowid
        }

    finally:

        connection.close()
