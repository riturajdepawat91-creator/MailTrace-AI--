from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.ip_intelligence_v2.engine import analyze_ip_v2


router = APIRouter(
    prefix="/api/ip-intelligence",
    tags=["IP Intelligence"]
)


# ==========================================
# REQUEST MODELS
# ==========================================

class IPAnalysisRequest(BaseModel):

    ip: str = Field(
        ...,
        min_length=1,
        description="IPv4 or IPv6 address"
    )


class MultipleIPAnalysisRequest(BaseModel):

    ips: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of IPv4 or IPv6 addresses"
    )


# ==========================================
# SINGLE IP ANALYSIS — V2
# ==========================================

@router.post("")
def analyze_single_ip(
    request: IPAnalysisRequest
):

    ip = request.ip.strip()

    if not ip:

        raise HTTPException(
            status_code=400,
            detail="IP address is required."
        )

    result = analyze_ip_v2(ip)

    return {
        "success": True,
        "engine": "ip-intelligence-v2",
        "result": result
    }


# ==========================================
# MULTIPLE IP ANALYSIS — V2
# ==========================================

@router.post("/batch")
def analyze_multiple_ips(
    request: MultipleIPAnalysisRequest
):

    cleaned_ips = [
        ip.strip()
        for ip in request.ips
        if ip and ip.strip()
    ]

    if not cleaned_ips:

        raise HTTPException(
            status_code=400,
            detail="At least one valid IP value is required."
        )

    results = [
        analyze_ip_v2(ip)
        for ip in cleaned_ips
    ]

    return {
        "success": True,
        "engine": "ip-intelligence-v2",
        "count": len(results),
        "results": results
    }
