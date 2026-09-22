from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from services.email_parser import parse_email
from services.ip_intelligence import analyze_ip, analyze_ips

from database.database import (
    initialize_database,
    save_investigation,
    get_all_investigations,
)

from routes.investigations import router as investigations_router
from routes.cases import router as cases_router

from routes.ip_intelligence_routes import router as ip_intelligence_router

from services.email_forensics.orchestrator import analyze_email_forensics

import json
import uuid


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="MailTrace AI API",
    description="AI-powered email threat detection and forensic intelligence backend",
    version="0.1.0",
)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

initialize_database()


# =========================================================
# CORS CONFIGURATION
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# ROUTERS
# =========================================================

app.include_router(
    investigations_router
)

app.include_router(
    ip_intelligence_router
)

app.include_router(
    cases_router
)

# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "name": "MailTrace AI",
        "status": "operational",
        "version": "0.1.0",
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health_check():

    return {
        "status": "ok",
        "service": "MailTrace AI Backend",
    }


# =========================================================
# CASES
# =========================================================

@app.get("/api/cases")
def get_cases():

    try:

        investigations = get_all_investigations()

        cases = []

        for investigation in investigations:

            score = int(
                investigation.get(
                    "threat_score",
                    0,
                )
                or 0
            )

            verdict = str(
                investigation.get(
                    "threat_verdict",
                    "",
                )
                or ""
            ).upper()

            # -----------------------------------------
            # HIGH-RISK INVESTIGATIONS BECOME CASES
            # -----------------------------------------

            if score >= 70 or verdict in (
                "CRITICAL",
                "HIGH",
                "HIGH RISK",
            ):

                case = {

                    "case_id":
                        "CASE-"
                        + investigation[
                            "investigation_id"
                        ].replace(
                            "INV-",
                            "",
                        ),

                    "investigation_id":
                        investigation[
                            "investigation_id"
                        ],

                    "subject":
                        investigation.get(
                            "subject",
                            "No Subject",
                        ),

                    "sender":
                        investigation.get(
                            "sender",
                            "Unknown",
                        ),

                    "recipient":
                        investigation.get(
                            "recipient",
                            "Unknown",
                        ),

                    "threat_score":
                        score,

                    "threat_verdict":
                        verdict,

                    "threat_confidence":
                        investigation.get(
                            "threat_confidence",
                            "UNKNOWN",
                        ),

                    "created_at":
                        investigation.get(
                            "created_at",
                            "",
                        ),

                    "status":
                        "OPEN",
                }

                cases.append(case)

        return {

            "success": True,

            "count":
                len(cases),

            "cases":
                cases,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to load cases: {str(error)}",
        )


# =========================================================
# CAMPAIGNS
# =========================================================

@app.get("/api/campaigns")
def get_campaigns():

    try:

        investigations = get_all_investigations()

        campaigns = []

        for index, investigation in enumerate(
            investigations[:10],
            start=1,
        ):

            score = int(
                investigation.get(
                    "threat_score",
                    0,
                )
                or 0
            )

            verdict = str(
                investigation.get(
                    "threat_verdict",
                    "UNKNOWN",
                )
                or "UNKNOWN"
            ).upper()

            # -----------------------------------------
            # SEVERITY
            # -----------------------------------------

            if score >= 90 or verdict == "CRITICAL":

                severity = "CRITICAL"

            elif score >= 70 or verdict in (
                "HIGH",
                "HIGH RISK",
            ):

                severity = "HIGH"

            elif score >= 40:

                severity = "MEDIUM"

            else:

                severity = "LOW"

            campaign = {

                "campaign_id":
                    f"CAMPAIGN-{index:03d}",

                "name":
                    investigation.get(
                        "subject",
                        "Unknown Campaign",
                    ),

                "severity":
                    severity,

                "description":
                    "Correlated email threat activity.",

                "email_count":
                    1,

                "indicator_count":
                    0,

                "status":
                    "ACTIVE",

                "threat_score":
                    score,

                "created_at":
                    investigation.get(
                        "created_at",
                        "",
                    ),

                "investigation_ids": [

                    investigation.get(
                        "investigation_id",
                        "",
                    )

                ],
            }

            campaigns.append(campaign)

        return {

            "success": True,

            "count":
                len(campaigns),

            "campaigns":
                campaigns,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to load campaigns: {str(error)}",
        )


# =========================================================
# CAMPAIGN DETAIL
# =========================================================

@app.get("/api/campaigns/{campaign_id}")
def get_campaign_detail(
    campaign_id: str,
):

    try:

        investigations = get_all_investigations()

        matched_investigations = []

        for index, investigation in enumerate(
            investigations[:10],
            start=1,
        ):

            current_campaign_id = (
                f"CAMPAIGN-{index:03d}"
            )

            if current_campaign_id != campaign_id:
                continue

            score = int(
                investigation.get(
                    "threat_score",
                    0,
                )
                or 0
            )

            verdict = str(
                investigation.get(
                    "threat_verdict",
                    "UNKNOWN",
                )
                or "UNKNOWN"
            ).upper()

            if score >= 90 or verdict == "CRITICAL":

                severity = "CRITICAL"

            elif score >= 70 or verdict in (
                "HIGH",
                "HIGH RISK",
            ):

                severity = "HIGH"

            elif score >= 40:

                severity = "MEDIUM"

            else:

                severity = "LOW"

            matched_investigations.append({

                "investigation_id":
                    investigation.get(
                        "investigation_id",
                        "",
                    ),

                "subject":
                    investigation.get(
                        "subject",
                        "No Subject",
                    ),

                "sender":
                    investigation.get(
                        "sender",
                        "Unknown",
                    ),

                "recipient":
                    investigation.get(
                        "recipient",
                        "Unknown",
                    ),

                "threat_score":
                    score,

                "threat_verdict":
                    verdict,

                "threat_confidence":
                    investigation.get(
                        "threat_confidence",
                        "UNKNOWN",
                    ),

                "created_at":
                    investigation.get(
                        "created_at",
                        "",
                    ),

                "status":
                    "OPEN",
            })

        if not matched_investigations:

            raise HTTPException(
                status_code=404,
                detail="Campaign not found.",
            )

        campaign = {

            "campaign_id":
                campaign_id,

            "name":
                matched_investigations[0][
                    "subject"
                ],

            "severity":
                severity,

            "status":
                "ACTIVE",

            "email_count":
                len(
                    matched_investigations
                ),

            "threat_score":
                max(
                    item["threat_score"]
                    for item in matched_investigations
                ),

            "investigations":
                matched_investigations,
        }

        return {

            "success": True,

            "campaign":
                campaign,
        }

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to load campaign: {str(error)}",
        )


# =========================================================
# EMAIL ANALYSIS
# =========================================================

@app.post("/api/analyze-email")
async def analyze_email(
    file: UploadFile = File(...),
):

    # -----------------------------------------
    # FILE CHECK
    # -----------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file provided.",
        )

    # -----------------------------------------
    # FILE EXTENSION CHECK
    # -----------------------------------------

    allowed_extensions = (
        ".eml",
        ".msg",
    )

    if not file.filename.lower().endswith(
        allowed_extensions
    ):

        raise HTTPException(
            status_code=400,
            detail="Only .eml and .msg files are supported.",
        )

    try:

        # -------------------------------------
        # READ FILE
        # -------------------------------------

        file_content = await file.read()

        # -------------------------------------
        # PARSE EMAIL
        # -------------------------------------

        result = parse_email(
            file_content,
            file.filename,
        )

        # -------------------------------------
        # EMAIL FORENSICS
        # -------------------------------------

        forensic_analysis = analyze_email_forensics(
            file_content
        )

        # Enrich forensic IP candidates using the
        # existing IP intelligence engine.
        forensic_ips = [
            item.get("ip")
            for item in forensic_analysis.get(
                "ip_intelligence", {}
            ).get("candidates", [])
            if item.get("ip")
        ]

        forensic_ip_intelligence = {}

        if forensic_ips:
            try:
                ip_results = analyze_ips(forensic_ips)

                if isinstance(ip_results, list):
                    forensic_ip_intelligence = {
                        item.get("ip"): item
                        for item in ip_results
                        if item.get("ip")
                    }

            except Exception:
                forensic_ip_intelligence = {}

        if forensic_ip_intelligence:
            forensic_analysis = analyze_email_forensics(
                file_content,
                forensic_ip_intelligence
            )

        result["email_forensics"] = forensic_analysis

        # -------------------------------------
        # BASIC INFORMATION
        # -------------------------------------

        basic_information = result.get(
            "basic_information",
            {},
        )

        # -------------------------------------
        # THREAT ANALYSIS
        # -------------------------------------

        threat_analysis = result.get(
            "threat_analysis",
            {},
        )

        # -------------------------------------
        # CREATE INVESTIGATION ID
        # -------------------------------------

        investigation_id = (
            "INV-"
            + uuid.uuid4().hex[:10].upper()
        )

        # -------------------------------------
        # SAVE INVESTIGATION
        # -------------------------------------

        save_investigation(

            investigation_id=investigation_id,

            filename=file.filename,

            subject=basic_information.get(
                "subject"
            ),

            sender=basic_information.get(
                "from"
            ),

            recipient=basic_information.get(
                "to"
            ),

            threat_score=threat_analysis.get(
                "score",
                0,
            ),

            threat_verdict=threat_analysis.get(
                "verdict",
                "UNKNOWN",
            ),

            threat_confidence=threat_analysis.get(
                "confidence",
                "UNKNOWN",
            ),

            analysis_json=json.dumps(
                result
            ),
        )

        # -------------------------------------
        # RESPONSE
        # -------------------------------------

        return {

            "success": True,

            "investigation_id":
                investigation_id,

            "filename":
                file.filename,

            "analysis":
                result,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Email analysis failed: "
                + str(error)
            ),
        )



