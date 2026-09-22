from fastapi import APIRouter, HTTPException

from database.database import (
    get_all_investigations,
    get_investigation
)

import json


router = APIRouter(
    prefix="/api/investigations",
    tags=["Investigations"]
)


# ==========================================
# LIST ALL INVESTIGATIONS
# ==========================================

@router.get("")
def list_investigations():

    try:

        investigations = get_all_investigations()

        return {
            "success": True,
            "count": len(investigations),
            "investigations": investigations
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch investigations: {str(error)}"
        )


# ==========================================
# GET SINGLE INVESTIGATION
# ==========================================

@router.get("/{investigation_id}")
def get_single_investigation(
    investigation_id: str
):

    try:

        investigation = get_investigation(
            investigation_id
        )

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        try:

            investigation["analysis"] = json.loads(
                investigation.get(
                    "analysis_json",
                    "{}"
                )
            )

        except Exception:

            investigation["analysis"] = {}

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

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch investigation: {str(error)}"
        )