from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List

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
        max_length=100,
        description="IPv4 or IPv6 address"
    )


class MultipleIPAnalysisRequest(BaseModel):
    ips: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of IPv4 or IPv6 addresses"
    )


# ==========================================
# SINGLE IP ANALYSIS
# ==========================================

@router.post("")
def analyze_single_ip(request: IPAnalysisRequest):

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
        "version": result.get("risk_engine", "v5"),
        "result": result
    }


# ==========================================
# ADVANCED BATCH IP ANALYSIS
# ==========================================

@router.post("/batch")
def analyze_multiple_ips(
    request: MultipleIPAnalysisRequest
):

    seen = set()
    cleaned_ips = []

    for raw_ip in request.ips:

        if not raw_ip:
            continue

        ip = raw_ip.strip()

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)
        cleaned_ips.append(ip)

    if not cleaned_ips:

        raise HTTPException(
            status_code=400,
            detail="At least one IP address is required."
        )

    results = [
        analyze_ip_v2(ip)
        for ip in cleaned_ips
    ]

    # --------------------------------------
    # INTELLIGENCE SUMMARY
    # --------------------------------------

    valid_results = [
        item for item in results
        if item.get("valid")
    ]

    risk_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
        "OTHER": 0
    }

    total_risk_score = 0
    highest_risk_score = 0

    countries = set()
    asns = set()

    suspicious_ips = []

    for item in valid_results:

        risk = str(
            item.get("risk", "UNKNOWN")
        ).upper()

        if risk in risk_distribution:
            risk_distribution[risk] += 1
        else:
            risk_distribution["OTHER"] += 1

        score = item.get("risk_score", 0)

        if isinstance(score, (int, float)):

            total_risk_score += score

            if score > highest_risk_score:
                highest_risk_score = score

        country = item.get("country_code")

        if country:
            countries.add(country)

        asn = item.get("asn")

        if asn:
            asns.add(str(asn))

        if risk in ("CRITICAL", "HIGH"):

            suspicious_ips.append({
                "ip": item.get("ip"),
                "risk": risk,
                "risk_score": score,
                "confidence": item.get("confidence", 0),
                "country": item.get("country"),
                "organization": item.get("organization")
            })

    average_risk_score = 0

    if valid_results:

        average_risk_score = round(
            total_risk_score / len(valid_results),
            2
        )

    suspicious_ips.sort(
        key=lambda x: x.get(
            "risk_score",
            0
        ),
        reverse=True
    )

    summary = {
        "requested_count": len(request.ips),
        "unique_count": len(cleaned_ips),
        "valid_count": len(valid_results),
        "invalid_count": (
            len(results) -
            len(valid_results)
        ),
        "highest_risk_score": highest_risk_score,
        "average_risk_score": average_risk_score,
        "risk_distribution": risk_distribution,
        "unique_countries": len(countries),
        "unique_asns": len(asns),
        "suspicious_count": len(suspicious_ips)
    }

    return {
        "success": True,
        "engine": "ip-intelligence-v2",
        "version": "advanced-v5",
        "count": len(results),
        "summary": summary,
        "suspicious_ips": suspicious_ips,
        "results": results
    }


# ==========================================
# IP HEALTH CHECK
# ==========================================

@router.get("/health")
def ip_intelligence_health():

    return {
        "success": True,
        "service": "IP Intelligence",
        "engine": "ip-intelligence-v2",
        "version": "advanced-v5",
        "status": "operational",
        "capabilities": [
            "IPv4 validation",
            "IPv6 validation",
            "reverse DNS",
            "geolocation enrichment",
            "ASN intelligence",
            "organization detection",
            "network classification",
            "hosting detection",
            "reputation analysis",
            "evidence collection",
            "confidence scoring",
            "explainable risk scoring",
            "batch analysis"
        ]
    }
