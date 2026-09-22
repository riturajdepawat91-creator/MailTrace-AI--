from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import uuid

from database.database import get_connection


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


# ==========================================
# LIST CASES
# ==========================================

@router.get("")
def list_cases():

    connection = get_connection()

    try:

        rows = connection.execute("""
            SELECT
                case_id,
                title,
                description,
                severity,
                status,
                threat_score,
                created_at,
                updated_at
            FROM cases
            ORDER BY created_at DESC
        """).fetchall()

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
def get_case(case_id: str):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT
                case_id,
                title,
                description,
                severity,
                status,
                threat_score,
                created_at,
                updated_at
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

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
            WHERE ci.case_id = ?
            ORDER BY ci.created_at DESC
        """, (case_id,)).fetchall()

        notes = connection.execute("""
            SELECT
                id,
                note,
                author,
                created_at
            FROM case_notes
            WHERE case_id = ?
            ORDER BY created_at DESC
        """, (case_id,)).fetchall()

        evidence = connection.execute("""
            SELECT
                id,
                evidence_type,
                value,
                description,
                investigation_id,
                created_at
            FROM evidence
            WHERE case_id = ?
            ORDER BY created_at DESC
        """, (case_id,)).fetchall()

        return {
            "success": True,
            "case": dict(case),
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
def create_case(request: CreateCaseRequest):

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
                title,
                description,
                severity,
                status,
                threat_score
            )
            VALUES (?, ?, ?, ?, 'OPEN', 0)
        """, (
            case_id,
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
    request: UpdateCaseRequest
):

    connection = get_connection()

    try:

        existing = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

        if existing is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

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
            WHERE case_id = ?
            """,
            values
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
    investigation_id: str
):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        investigation = connection.execute("""
            SELECT
                investigation_id,
                threat_score
            FROM investigations
            WHERE investigation_id = ?
        """, (investigation_id,)).fetchone()

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        connection.execute("""
            INSERT OR IGNORE INTO case_investigations (
                case_id,
                investigation_id
            )
            VALUES (?, ?)
        """, (
            case_id,
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
            WHERE case_id = ?
        """, (
            int(investigation["threat_score"] or 0),
            case_id
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
    request: AddNoteRequest
):

    connection = get_connection()

    try:

        case = connection.execute("""
            SELECT case_id
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

        if case is None:

            raise HTTPException(
                status_code=404,
                detail="Case not found."
            )

        cursor = connection.execute("""
            INSERT INTO case_notes (
                case_id,
                note,
                author
            )
            VALUES (?, ?, ?)
        """, (
            case_id,
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
