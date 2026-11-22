from fastapi import APIRouter, HTTPException, Request

from database.database import (
    get_all_investigation_summaries,
    get_investigation
)

import json


router = APIRouter(
    prefix="/api/investigations",
    tags=["Investigations"]
)


@router.get("")
def list_investigations(request: Request):

    try:

        principal = getattr(request.state, "principal", None)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        investigations = get_all_investigation_summaries(
            principal.tenant_id if principal else None
        )

        return {
            "success": True,
            "count": len(investigations),
            "investigations": investigations
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error.")


@router.get("/{investigation_id}")
def get_single_investigation(
    investigation_id: str,
    request: Request,
):

    try:

        principal = getattr(request.state, "principal", None)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        investigation = get_investigation(
            investigation_id,
            principal.tenant_id if principal else None,
        )

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        try:
            decoded = json.loads(investigation.get("analysis_json", "{}"))
            if not isinstance(decoded, dict):
                raise ValueError("stored analysis is not an object")
            investigation["analysis"] = decoded
            investigation["analysis_document_status"] = "PASS"
        except Exception:
            # Keep the existing response shape but do not disguise corrupt
            # persisted analysis as an empty successful report.
            investigation["analysis"] = {
                "analysis_status": "ERROR",
                "threat_analysis": {
                    "score": None,
                    "verdict": "REPORT DATA UNAVAILABLE",
                    "confidence": "UNKNOWN",
                },
                "result_statuses": {
                    "report_document": {
                        "status": "ERROR",
                        "message": "Stored analysis document could not be read.",
                    }
                },
            }
            investigation["analysis_document_status"] = "ERROR"

        investigation.pop(
            "analysis_json",
            None
        )

        return {
            "success": True,
            "investigation": investigation
        }

    except HTTPException:

        raise

    except Exception:

        raise HTTPException(status_code=500, detail="Internal server error.")
