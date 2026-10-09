"""
MailTrace AI — Threat Intelligence API
"""

from fastapi import APIRouter, HTTPException, Request

from services.threat_intelligence import (
    ThreatIntelligenceEngine,
)

from database.database import (
    initialize_threat_intelligence_table,
    save_threat_intelligence,
    get_threat_intelligence,
)


router = APIRouter(
    prefix="/api/threat-intelligence",
    tags=["Threat Intelligence"],
)


try:
    initialize_threat_intelligence_table()
except Exception:
    pass


@router.get("/status")
def threat_intelligence_status():

    return {
        "success": True,
        "service": "threat-intelligence",
        "providers":
            ThreatIntelligenceEngine.provider_status(),
    }


@router.post("/sync")
def threat_intelligence_sync(
    days: int = 1,
    request: Request = None,
):

    if days < 1:
        days = 1

    if days > 7:
        days = 7

    result = ThreatIntelligenceEngine.sync(
        days=days,
    )

    saved = save_threat_intelligence(
        result.get(
            "indicators",
            [],
        ),
        tenant_id=getattr(getattr(request, "state", None), "principal", None).tenant_id if getattr(getattr(request, "state", None), "principal", None) else None,
    )

    return {
        "success": result.get(
            "success",
            False,
        ),
        "providers": result.get(
            "providers",
            {},
        ),
        "fetched": result.get(
            "count",
            0,
        ),
        "saved": saved,
    }


@router.get("/indicators")
def threat_intelligence_indicators(
    limit: int = 100,
    request: Request = None,
):

    limit = max(
        1,
        min(int(limit), 500),
    )

    principal = getattr(getattr(request, "state", None), "principal", None)
    indicators = get_threat_intelligence(
        limit=limit,
        tenant_id=getattr(principal, "tenant_id", None),
    )

    return {
        "success": True,
        "count": len(indicators),
        "indicators": indicators,
    }
