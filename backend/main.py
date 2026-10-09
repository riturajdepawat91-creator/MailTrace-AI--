from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal
from services.access_control import (
    ApiPrincipal,
    authenticate_api_key,
    configured_api_keys,
    is_production,
)

from services.email_parser import parse_email
from services.ip_intelligence import analyze_ip, analyze_ips

from database.database import (
    initialize_database,
    initialize_email_webhook_events,
    initialize_email_alerts,
    initialize_employee_email_reports,
    initialize_case_claims,
    initialize_soc_routing,
    begin_email_webhook_event,
    complete_email_webhook_event,
    fail_email_webhook_event,
    create_email_alert,
    get_email_alerts,
    get_email_alert_by_event,
    get_email_alert_history,
    acknowledge_email_alert,
    resolve_email_alert,
    submit_employee_email_report,
    get_employee_email_reports,
    get_employee_email_report,
    initialize_threat_intelligence_table,
    upgrade_threat_intelligence_schema,
    save_investigation,
    get_all_investigations,
    get_investigation_snapshot_marker,
    get_investigation,
)

from routes.investigations import router as investigations_router
from routes.cases import router as cases_router
from routes.soc_routing import router as soc_routing_router

from routes.ip_intelligence_routes import router as ip_intelligence_router

from services.email_forensics.orchestrator import analyze_email_forensics
from services.email_thread_intelligence import analyze_thread_to_dict

from services.threat_intelligence.ioc_normalizer import (
    extract_iocs,
    summarize_iocs,
)

from database.database import (
    lookup_threat_intelligence_batch,
)

from database.database import get_connection, renew_email_webhook_event_lease

from services.threat_intelligence_v2.engine import analyze_threat_intelligence_v2
from services.campaign_correlation import correlate_campaigns
from services.email_ai.engine import analyze_email_ai
from services.email_ai.intelligence_fusion import analyze_email_intelligence
from services.response_management import manage_response
from copy import deepcopy
from services.ioc_timeline import build_ioc_timeline
from services.recommendation_engine import recommend_actions
from services.response_execution import transition_response
from services.response_verification import verify_response
from services.email_alerting import build_mail_flow_decision, should_create_alert
from services.threat_hunting import hunt_threats

import json
import uuid
import hashlib
import hmac
import os
import logging
import ipaddress
import asyncio
import time
from threading import Event, Thread
from contextlib import asynccontextmanager
from io import BytesIO

from pathlib import Path
from datetime import datetime, timezone

from services.evidence_custody import (
    EvidenceCustodyLedger,
)
from services.integrity_anchoring import (
    IntegrityAnchorEngine,
    LocalAnchorProvider,
)
from services.privacy_governance import (
    PrivacyGovernanceEngine,
    RetentionPolicy,
)



# =========================================================
# APPLICATION
# =========================================================

logging.basicConfig(
    level=os.getenv("MAILTRACE_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
api_logger = logging.getLogger("mailtrace.api")

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail at startup on a broken hosted deployment instead of serving an app
    # that looks healthy while every protected API request is unusable.
    if is_production():
        configured_api_keys()
    yield


app = FastAPI(
    title="MailTrace AI API",
    description="AI-powered email threat detection and forensic intelligence backend",
    version="0.1.0",
    lifespan=lifespan,
)

MAX_EMAIL_UPLOAD_BYTES = 25 * 1024 * 1024


def _request_tenant_id(request: Request):
    principal = getattr(getattr(request, "state", None), "principal", None)
    return principal.tenant_id if isinstance(principal, ApiPrincipal) else None
WEBHOOK_LEASE_HEARTBEAT_SECONDS = 60
SOC_API_PREFIXES = (
    "/api/alerts",
    "/api/campaigns",
    "/api/cases",
    "/api/evidence",
    "/api/investigations",
    "/api/ip-intelligence",
    "/api/reports",
    "/api/response-management",
    "/api/threat-hunting",
    "/api/threat-intelligence",
    "/api/ioc-timeline",
    "/api/soc/routing",
)
SOC_API_PATHS = {
    "/api/analyze-email",
    "/api/analyze-thread",
    "/api/recommendations/build",
}
SOC_ACCESS_ROLES = {
    "analyst", "soc_lead", "tenant_admin", "platform_admin", "admin"
}
EMPLOYEE_API_PREFIX = "/api/employee/reports"


def _start_webhook_lease_heartbeat(event_id: str, lease_token: str, tenant_id: str | None = None):
    stop_event = Event()

    def renew_until_stopped():
        while not stop_event.wait(WEBHOOK_LEASE_HEARTBEAT_SECONDS):
            try:
                if not renew_email_webhook_event_lease(event_id, lease_token, tenant_id):
                    return
            except Exception:
                api_logger.exception("webhook_lease_renewal_failed")

    worker = Thread(
        target=renew_until_stopped,
        name="mailtrace-webhook-lease-heartbeat",
        daemon=True,
    )
    worker.start()
    return stop_event, worker


@app.middleware("http")
async def authenticate_api_requests(request: Request, call_next):
    """Require a configured bearer key on hosted API routes.

    The signed email webhook retains its independent HMAC authentication.
    During local development only loopback clients may use the no-key path.
    """
    if not request.url.path.startswith("/api/") or request.method == "OPTIONS":
        return await call_next(request)

    # Health probes expose only service/dependency status, never tenant data.
    if request.url.path in {"/api/health", "/api/ready", "/api/live"}:
        return await call_next(request)

    # This endpoint validates its own timestamped HMAC signature.
    if request.url.path == "/api/webhooks/email":
        return await call_next(request)

    production = is_production()
    if not production:
        client_host = request.client.host if request.client else ""
        try:
            import ipaddress
            loopback = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            loopback = False
        if loopback and not request.url.path.startswith(EMPLOYEE_API_PREFIX):
            request.state.principal = ApiPrincipal(
                tenant_id="local",
                roles=frozenset({"read", "write", "analyst"}),
                subject_id="local-dev-analyst",
            )
            return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return JSONResponse(
            status_code=401,
            content={"detail": "A valid Bearer API key is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        principal = authenticate_api_key(token.strip(), configured_api_keys())
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is not configured safely."},
        )
    if principal is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid API key."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    is_employee_report_api = request.url.path == EMPLOYEE_API_PREFIX or request.url.path.startswith(
        EMPLOYEE_API_PREFIX + "/"
    )
    if "employee" in principal.roles and not is_employee_report_api:
        return JSONResponse(
            status_code=403,
            content={"detail": "Employee credentials are limited to employee self-service APIs."},
        )

    is_soc_api = request.url.path in SOC_API_PATHS or any(
        request.url.path == prefix or request.url.path.startswith(prefix + "/")
        for prefix in SOC_API_PREFIXES
    )
    if is_soc_api and not (principal.roles & SOC_ACCESS_ROLES):
        return JSONResponse(
            status_code=403,
            content={"detail": "A SOC analyst role is required for this resource."},
        )

    required_role = "read" if request.method in {"GET", "HEAD"} else "write"
    if "admin" not in principal.roles and required_role not in principal.roles:
        return JSONResponse(status_code=403, content={"detail": "Insufficient API key role."})

    request.state.principal = principal
    return await call_next(request)


# =========================================================
# API REQUEST OBSERVABILITY
# =========================================================

@app.middleware("http")
async def observe_api_requests(request: Request, call_next):
    """Attach a correlation ID and log API latency without logging user data."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)

    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    started_at = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        api_logger.exception(
            "request_failed request_id=%s method=%s route=%s elapsed_ms=%s",
            request_id,
            request.method,
            route,
            elapsed_ms,
        )
        raise

    elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
    route = getattr(request.scope.get("route"), "path", "unmatched")
    response.headers["X-Request-ID"] = request_id
    response.headers["Access-Control-Expose-Headers"] = "X-Request-ID"
    api_logger.info(
        "request_complete request_id=%s method=%s route=%s status=%s elapsed_ms=%s",
        request_id,
        request.method,
        route,
        response.status_code,
        elapsed_ms,
    )
    return response


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

initialize_database()
initialize_email_webhook_events()
initialize_email_alerts()
initialize_employee_email_reports()
initialize_case_claims()
initialize_soc_routing()

# =========================================================
# THREAT INTELLIGENCE DATABASE INITIALIZATION
# =========================================================

initialize_threat_intelligence_table()
upgrade_threat_intelligence_schema()


# =========================================================
# CORS CONFIGURATION
# =========================================================

_configured_cors_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("MAILTRACE_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
_default_cors_origins = [
    "http://127.0.0.1:5503",
    "http://localhost:5503",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_configured_cors_origins or _default_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    expose_headers=["X-Request-ID"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Webhook-Signature",
        "X-Webhook-Event-ID",
        "X-MailTrace-Filename",
        "X-MailTrace-Event-Id",
        "X-MailTrace-SMTP-Client-IP",
        "X-MailTrace-SMTP-Mail-From",
        "X-MailTrace-SMTP-HELO",
        "X-MailTrace-SMTP-RCPT-TO",
        "X-MailTrace-Timestamp",
        "X-MailTrace-Signature",
    ],
)



# =========================================================
# EVIDENCE / PRIVACY / INTEGRITY RUNTIME
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

RUNTIME_DATA_DIR = (
    BASE_DIR / "runtime_data"
)

EVIDENCE_VAULT_DIR = (
    RUNTIME_DATA_DIR / "evidence_vault"
)

EVIDENCE_STATE_PATH = (
    RUNTIME_DATA_DIR / "evidence_ledger.jsonl"
)

EVIDENCE_VAULT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

RUNTIME_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

# Original evidence authority.
evidence_custody = EvidenceCustodyLedger(
    ledger_path=EVIDENCE_STATE_PATH,
)

# Independent integrity boundary.
integrity_anchoring = IntegrityAnchorEngine(
    providers={
        "local": LocalAnchorProvider(),
    },
)

# Governance applies to derived/control-plane data.
privacy_governance = PrivacyGovernanceEngine(
    policies=[
        RetentionPolicy(
            policy_id="mailtrace-default",
            name="MailTrace Default Evidence Policy",
            classification="INTERNAL",
            retention_days=365,
            legal_hold_allowed=True,
            forensic_hold_allowed=True,
            purge_derived_views=True,
            purge_raw_evidence=False,
        ),
        RetentionPolicy(
            policy_id="mailtrace-sensitive",
            name="MailTrace Sensitive Evidence Policy",
            classification="SENSITIVE",
            retention_days=730,
            legal_hold_allowed=True,
            forensic_hold_allowed=True,
            purge_derived_views=True,
            purge_raw_evidence=False,
        ),
        RetentionPolicy(
            policy_id="mailtrace-restricted",
            name="MailTrace Restricted Evidence Policy",
            classification="RESTRICTED",
            retention_days=1095,
            legal_hold_allowed=True,
            forensic_hold_allowed=True,
            purge_derived_views=True,
            purge_raw_evidence=False,
        ),
    ],
)


def _mailtrace_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _classification_policy(
    classification: str,
) -> str:
    if classification == "RESTRICTED":
        return "mailtrace-restricted"

    if classification == "SENSITIVE":
        return "mailtrace-sensitive"

    return "mailtrace-default"


def _model_to_dict(value):
    """Recursively convert application objects into JSON-safe values.

    This serializer intentionally avoids dataclasses.asdict() because
    asdict() performs deepcopy() and can fail on non-pickleable values
    such as memoryview.

    Rules:
      bytes / bytearray / memoryview -> lowercase hexadecimal text
      mappings -> recursively converted dictionaries
      list / tuple / set / frozenset -> recursively converted lists
      dataclasses -> fields traversed recursively without deepcopy
      to_dict() objects -> recursively converted
      Enum -> underlying value
      datetime / date -> ISO-8601 text
      pathlib.Path -> string
      primitive JSON values -> unchanged
    """
    from collections.abc import Mapping as _Mapping
    from dataclasses import fields, is_dataclass
    from datetime import date, datetime
    from enum import Enum
    from pathlib import Path as _Path

    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()

    if isinstance(value, Enum):
        return _model_to_dict(value.value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, _Path):
        return str(value)

    if isinstance(value, _Mapping):
        return {
            str(key): _model_to_dict(child)
            for key, child in value.items()
        }

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _model_to_dict(child)
            for child in value
        ]

    if is_dataclass(value) and not isinstance(value, type):
        return {
            field_info.name: _model_to_dict(
                getattr(value, field_info.name)
            )
            for field_info in fields(value)
        }

    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _model_to_dict(value.to_dict())

    if hasattr(value, "__dict__"):
        return {
            str(key): _model_to_dict(child)
            for key, child in vars(value).items()
            if not key.startswith("__")
        }

    if isinstance(value, (str, int, float, bool)):
        return value

    raise TypeError(
        f"Object of type {type(value).__name__} "
        "is not JSON serializable"
    )



def _build_evidence_governance(
    *,
    file_content: bytes,
    filename: str,
    investigation_id: str,
    analysis_result: dict,
    tenant_id: str | None = None,
):
    evidence_id = (
        "EV-"
        + investigation_id.replace("INV-", "")
    )

    acquired_at = _mailtrace_utc_now()

    classification = privacy_governance.classify(
        analysis_result
    )

    if classification not in {
        "PUBLIC",
        "INTERNAL",
        "SENSITIVE",
        "RESTRICTED",
    }:
        classification = "INTERNAL"

    policy_id = _classification_policy(
        classification
    )

    result = {
        "enabled": True,
        "evidence_id": evidence_id,
        "classification": classification,
        "policy_id": policy_id,
        "acquired_at_utc": acquired_at,
        "preservation": {
            "attempted": False,
            "verified": False,
        },
        "custody": {
            "registered": False,
            "sealed": False,
            "verified": False,
            "verification": None,
        },
        "integrity_anchor": {
            "created": False,
            "verified": False,
            "receipt": None,
            "verification": None,
        },
        "retention": None,
        "governance": {
            "raw_evidence_mutated": False,
            "derived_views_only": True,
            "static_only": True,
        },
        "error": None,
    }

    # --------------------------------------------------------
    # 1. Register + preserve original bytes
    # --------------------------------------------------------

    record = evidence_custody.register(
        data=file_content,
        artifact_type="EMAIL_MESSAGE",
        source="api:/api/analyze-email",
        collector="MailTrace-AI",
        acquisition_method="API_UPLOAD",
        original_filename=filename,
        media_type="message/rfc822",
        case_id=None,
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        preservation_dir=EVIDENCE_VAULT_DIR,
        metadata={
            "classification": classification,
            "policy_id": policy_id,
            "content_length": len(file_content),
            "tenant_id": tenant_id,
            "analysis_binding": {
                "investigation_id": investigation_id,
                "analysis_version": "0.1.0",
            },
        },
    )

    result["custody"]["registered"] = True
    result["preservation"]["attempted"] = True

    # --------------------------------------------------------
    # 2. Verify preservation against uploaded bytes
    # --------------------------------------------------------

    preservation_check = evidence_custody.verify(
        evidence_id,
        data=file_content,
        actor="MailTrace-AI",
        purpose="initial acquisition verification",
    )

    result["preservation"]["verified"] = bool(
        preservation_check.preservation_copy_match
        and preservation_check.evidence_hash_match
    )

    result["custody"]["verification"] = (
        _model_to_dict(preservation_check)
    )

    # Do NOT advance to anchoring if the original bytes
    # cannot be verified.
    if not result["preservation"]["verified"]:
        result["error"] = (
            "Evidence preservation/hash verification failed."
        )

    else:
        # ----------------------------------------------------
        # 3. Seal custody record
        # ----------------------------------------------------

        evidence_custody.seal(
            evidence_id,
            actor="MailTrace-AI",
            purpose="initial evidence preservation seal",
        )

        result["custody"]["sealed"] = True

        # ----------------------------------------------------
        # 4. Verify sealed custody
        # ----------------------------------------------------

        custody_verification = evidence_custody.verify(
            evidence_id,
            data=file_content,
            actor="MailTrace-AI",
            purpose="post-seal custody verification",
        )

        result["custody"]["verified"] = bool(
            custody_verification.verified
        )

        result["custody"]["verification"] = (
            _model_to_dict(custody_verification)
        )

        if not result["custody"]["verified"]:
            result["error"] = (
                "Post-seal custody verification failed."
            )

        else:
            # ------------------------------------------------
            # 5. Independent integrity anchor
            # ------------------------------------------------

            anchor = evidence_custody.chain_anchor(
                evidence_id
            )

            custody_events = (
                evidence_custody.events(
                    evidence_id
                )
            )

            if not custody_events:
                raise RuntimeError(
                    "Cannot anchor evidence without custody events."
                )

            terminal_event_hash = (
                custody_events[-1].event_hash
            )

            record = evidence_custody.get(
                evidence_id
            )

            evidence_sha256 = (
                record.hashes.sha256
            )

            chain_anchor_digest = str(
                anchor.get(
                    "digest"
                )
                or anchor.get(
                    "sha256"
                )
                or anchor.get(
                    "anchor_digest"
                )
                or ""
            )

            if not chain_anchor_digest:
                raise RuntimeError(
                    "Custody chain anchor digest is empty."
                )

            integrity_receipt = (
                integrity_anchoring.create_anchor(
                    evidence_id=evidence_id,
                    evidence_sha256=evidence_sha256,
                    terminal_event_hash=terminal_event_hash,
                    chain_anchor_digest=chain_anchor_digest,
                    provider="local",
                    metadata={
                        "investigation_id":
                            investigation_id,
                        "classification":
                            classification,
                        "purpose":
                            "independent evidence integrity commitment",
                    },
                )
            )

            result["integrity_anchor"]["created"] = True
            result["integrity_anchor"]["receipt"] = (
                _model_to_dict(
                    integrity_receipt
                )
            )

            integrity_verification = (
                integrity_anchoring.verify_anchor(
                    integrity_receipt.anchor_id
                )
            )

            result["integrity_anchor"]["verified"] = bool(
                integrity_verification.valid
            )

            result["integrity_anchor"]["verification"] = (
                _model_to_dict(
                    integrity_verification
                )
            )

            if not result["integrity_anchor"]["verified"]:
                result["error"] = (
                    "Independent integrity anchor verification failed."
                )

    # --------------------------------------------------------
    # 6. Retention policy evaluation
    # --------------------------------------------------------

    retention = (
        privacy_governance.evaluate_retention(
            evidence_id=evidence_id,
            classification=classification,
            acquired_at_utc=acquired_at,
            policy_id=policy_id,
            legal_hold=False,
            forensic_hold=False,
        )
    )

    result["retention"] = (
        _model_to_dict(retention)
    )

    return result


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

app.include_router(
    soc_routing_router
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


@app.get("/api/live")
def liveness_check():
    """Return process liveness without checking external dependencies."""
    return {
        "status": "ok",
        "service": "MailTrace AI Backend",
    }


@app.get("/api/ready")
def readiness_check():
    """Report readiness only when the persistent database can answer queries."""
    connection = None
    try:
        connection = get_connection()
        connection.execute("SELECT 1").fetchone()
    except Exception:
        api_logger.exception("readiness_check_failed dependency=database")
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "service": "MailTrace AI Backend",
                "dependencies": {"database": "unavailable"},
            },
        )
    finally:
        if connection is not None:
            connection.close()

    return {
        "status": "ok",
        "service": "MailTrace AI Backend",
        "dependencies": {"database": "ok"},
    }




# =========================================================
# REPORT MAP VIEW / GEOLOCATION INTELLIGENCE
# =========================================================

@app.get("/api/reports/map-view/{investigation_id}")
def get_report_map_view(investigation_id: str, request: Request):
    """Return only geolocation evidence already present in an investigation.

    No synthetic threat locations are generated. Nodes are returned only when
    stored analysis contains reliable latitude/longitude values.
    """
    try:
        investigation = get_investigation(investigation_id)
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        analysis = investigation.get("analysis", {})
        if not analysis:
            raw = investigation.get("analysis_json", "{}")
            try:
                analysis = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except Exception:
                analysis = {}

        nodes = []
        seen = set()

        def walk(value, path="root"):
            if isinstance(value, dict):
                lat = value.get("latitude", value.get("lat"))
                lon = value.get("longitude", value.get("lon", value.get("lng")))
                try:
                    if lat is not None and lon is not None:
                        latitude = float(lat)
                        longitude = float(lon)
                        if -90 <= latitude <= 90 and -180 <= longitude <= 180:
                            node = {
                                "label": value.get("label") or value.get("hostname") or value.get("domain") or value.get("ip") or value.get("ip_address") or path,
                                "ip": value.get("ip") or value.get("ip_address") or value.get("origin_ip"),
                                "latitude": latitude,
                                "longitude": longitude,
                                "country": value.get("country") or value.get("country_name"),
                                "region": value.get("region") or value.get("region_name"),
                                "city": value.get("city"),
                                "isp": value.get("isp") or value.get("org") or value.get("organization"),
                            }
                            key = (node["ip"], latitude, longitude, node["label"])
                            if key not in seen:
                                seen.add(key)
                                nodes.append(node)
                except (TypeError, ValueError):
                    pass
                for key, item in value.items():
                    walk(item, f"{path}.{key}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, f"{path}[{index}]")

        walk(analysis)

        return {
            "success": True,
            "investigation_id": investigation_id,
            "node_count": len(nodes),
            "nodes": nodes,
            "data_source": "stored_investigation_analysis",
            "synthetic_data": False,
        }
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Failed to build report map view: {str(error)}")


# =========================================================
# CASES
# =========================================================

@app.get("/api/cases")
def get_cases(request: Request):

    try:

        investigations = get_all_investigations(_request_tenant_id(request))

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

            confidence = str(
                investigation.get("threat_confidence", "UNKNOWN") or "UNKNOWN"
            ).strip().upper()
            if confidence == "HIGH" and (score >= 85 or verdict == "CRITICAL"):

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
def get_campaigns(request: Request):
    try:
        campaigns = correlate_campaigns(get_all_investigations(_request_tenant_id(request)))
        return {"success": True, "count": len(campaigns), "campaigns": campaigns}
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Failed to load campaigns: {str(error)}")


# =========================================================
# CAMPAIGN DETAIL
# =========================================================

@app.get("/api/campaigns/{campaign_id}")
def get_campaign_detail(campaign_id: str, request: Request):
    try:
        campaign = next(
            (item for item in correlate_campaigns(get_all_investigations(_request_tenant_id(request)))
             if item["campaign_id"] == campaign_id),
            None,
        )
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found.")
        return {"success": True, "campaign": campaign}
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Failed to load campaign: {str(error)}")


# =========================================================# IOC THREAT SCORE ENRICHMENT
# =========================================================

def calculate_ioc_threat_score(threat_intelligence):

    if not threat_intelligence:
        return {
            "score": 0,
            "matched_iocs": 0,
            "evidence": []
        }

    matches = (
        threat_intelligence.get(
            "matches",
            {}
        )
        or {}
    )

    if not matches:
        return {
            "score": 0,
            "matched_iocs": 0,
            "evidence": []
        }

    ioc_score = 0
    evidence = []

    for ioc, records in matches.items():

        if not records:
            continue

        strongest = max(
            records,
            key=lambda item: int(
                item.get(
                    "confidence",
                    0
                )
                or 0
            )
        )

        confidence = int(
            strongest.get(
                "confidence",
                0
            )
            or 0
        )

        threat_type = (
            strongest.get(
                "threat_type"
            )
            or "Threat intelligence match"
        )

        malware = (
            strongest.get(
                "malware"
            )
            or ""
        )

        ioc_type = (
            strongest.get(
                "ioc_type"
            )
            or "unknown"
        )

        if confidence >= 90:
            points = 30

        elif confidence >= 70:
            points = 25

        elif confidence >= 50:
            points = 20

        else:
            points = 15

        ioc_score += points

        evidence.append({
            "ioc": ioc,
            "ioc_type": ioc_type,
            "confidence": confidence,
            "threat_type": threat_type,
            "malware": malware,
            "points": points,
            "source": strongest.get(
                "source"
            ),
            "reference": strongest.get(
                "reference"
            )
        })

    ioc_score = min(
        ioc_score,
        60
    )

    return {
        "score": ioc_score,
        "matched_iocs": len(evidence),
        "evidence": evidence
    }


# =========================================================
# EMAIL ANALYSIS
# =========================================================

@app.post("/api/response-management/plan")
async def create_response_plan(
    payload: dict,
):
    """
    Create a read-only response plan from existing SOC context.

    Expected payload:
        {
            "case_management": {...},
            "incident_management": {...},
            "investigation_management": {...},
            "existing_status": {...}   # optional
        }

    No containment, remediation, blocking, isolation, deletion,
    credential reset, account disablement, or other real-world
    response action is executed by this endpoint.
    """

    if not isinstance(
        payload,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail="Request body must be a JSON object.",
        )

    case_management = payload.get(
        "case_management",
        {},
    )

    incident_management = payload.get(
        "incident_management",
        {},
    )

    investigation_management = payload.get(
        "investigation_management",
        {},
    )

    existing_status = payload.get(
        "existing_status",
        None,
    )

    if not isinstance(
        case_management,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail="case_management must be an object.",
        )

    if not isinstance(
        incident_management,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail="incident_management must be an object.",
        )

    if not isinstance(
        investigation_management,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail="investigation_management must be an object.",
        )

    if (
        existing_status is not None
        and not isinstance(
            existing_status,
            dict,
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="existing_status must be an object when provided.",
        )

    try:

        response_management = manage_response(
            case_management=case_management,
            incident_management=incident_management,
            investigation_management=investigation_management,
            existing_status=existing_status,
        )

        return {
            "success": True,
            "response_management": response_management,
            "execution": {
                "performed": False,
                "side_effect": False,
            },
            "persistence": False,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Response planning failed: "
                + str(error)
            ),
        )


@app.post("/api/response-management/transition")

@app.post("/api/response-management/verification")



@app.post("/api/recommendations/build")
async def build_recommendations_api(payload: dict):
    if not isinstance(payload, dict):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="payload must be an object",
        )

    context = payload.get("context", {})

    if not isinstance(context, dict):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="context must be an object",
        )

    recommendations = recommend_actions(context)

    return {
        "success": True,
        "recommendations": recommendations,
        "execution": {
            "performed": False,
            "side_effect": False,
        },
        "persistence": False,
    }

@app.post("/api/ioc-timeline/build")
async def build_ioc_timeline_api(payload: dict):
    if not isinstance(payload, dict):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="payload must be an object")

    context = payload.get("context", {})

    if not isinstance(context, (dict, list)):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="context must be an object or list")

    source_snapshot = deepcopy(context)

    timeline = build_ioc_timeline(context)

    return {
        "success": True,
        "ioc_timeline": timeline,
        "execution": {
            "performed": False,
            "side_effect": False,
        },
        "persistence": False,
        "input_immutable": source_snapshot == context,
    }

@app.post("/api/threat-hunting/hunt")
async def threat_hunting_hunt(
    payload: dict,
):
    """
    Read-only SOC threat hunting endpoint.
    """

    if not isinstance(
        payload,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="Request body must be a JSON object.",
        )

    context = payload.get(
        "context",
        {},
    )

    query = payload.get(
        "query",
        {},
    )

    if not isinstance(
        context,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="context must be an object.",
        )

    if not isinstance(
        query,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="query must be an object.",
        )

    try:

        result = hunt_threats(
            context=context,
            query=query,
        )

        return {
            "success": bool(
                result.get(
                    "success",
                    False,
                )
            ),
            "threat_hunting": result,
            "execution": {
                "performed": False,
                "side_effect": False,
            },
            "persistence": False,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Threat hunting failed: "
                + str(error)
            ),
        )

async def verify_response_plan(
    payload: dict,
):
    """
    Read-only post-response verification endpoint.
    """

    if not isinstance(
        payload,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="Request body must be a JSON object.",
        )

    response = payload.get(
        "response",
        {},
    )

    verification_context = payload.get(
        "verification_context",
        {},
    )

    if not isinstance(
        response,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="response must be an object.",
        )

    if not isinstance(
        verification_context,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="verification_context must be an object.",
        )

    try:

        result = verify_response(
            response=response,
            verification_context=verification_context,
        )

        return {
            "success": bool(
                result.get(
                    "success",
                    False,
                )
            ),
            "response_verification": result,
            "execution": {
                "performed": False,
                "side_effect": False,
            },
            "persistence": False,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Response verification failed: "
                + str(error)
            ),
        )

async def transition_response_plan(
    payload: dict,
):
    """
    Apply an analyst-controlled response state transition.

    Simulation/tracking endpoint only.
    No real containment, blocking, isolation, deletion,
    credential reset, account modification, or remediation
    action is executed.
    """

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="Request body must be a JSON object.",
        )

    response = payload.get(
        "response",
        {},
    )

    operation = payload.get(
        "operation",
        "",
    )

    actor = payload.get(
        "actor",
        "ANALYST",
    )

    reason = payload.get(
        "reason",
        "",
    )

    action_ids = payload.get(
        "action_ids",
        [],
    )

    if not isinstance(response, dict):
        raise HTTPException(
            status_code=400,
            detail="response must be an object.",
        )

    if not isinstance(operation, str) or not operation.strip():
        raise HTTPException(
            status_code=400,
            detail="operation is required.",
        )

    if not isinstance(action_ids, list):
        raise HTTPException(
            status_code=400,
            detail="action_ids must be a list.",
        )

    try:

        result = transition_response(
            response=response,
            operation=operation,
            actor=str(actor),
            reason=str(reason),
            action_ids=action_ids,
        )

        return {
            "success": bool(
                result.get("success", False)
            ),
            "response_execution": result,
            "execution": {
                "performed": False,
                "side_effect": False,
            },
            "persistence": False,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Response transition failed: "
                + str(error)
            ),
        )

# ============================================================
# MULTI-MESSAGE THREAD ANALYSIS
# ============================================================

@app.post("/api/analyze-thread")
async def analyze_thread_endpoint(
    files: list[UploadFile] = File(...),
):
    """
    Analyze a supplied multi-message email conversation.

    This endpoint intentionally:
    - accepts explicit email messages supplied by the caller
    - preserves Message-ID / In-Reply-To / References
    - performs static-only thread reconstruction
    - does not invent historical messages
    - does not replace /api/analyze-email
    """

    MAX_THREAD_MESSAGES = 100

    if not files:
        raise HTTPException(
            status_code=400,
            detail="At least one email message is required.",
        )

    if len(files) > MAX_THREAD_MESSAGES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Maximum thread size is "
                f"{MAX_THREAD_MESSAGES} messages."
            ),
        )

    parsed_messages = []

    for index, file in enumerate(files):

        filename = (
            str(file.filename or "").strip()
        )

        if not filename:
            raise HTTPException(
                status_code=400,
                detail=f"Thread message {index + 1} has no filename.",
            )

        if not filename.lower().endswith(".eml"):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unsupported thread message '{filename}'. "
                    "Only .eml files are accepted."
                ),
            )

        try:
            raw_bytes = await file.read()

            if not raw_bytes:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Thread message '{filename}' is empty."
                    ),
                )

            message = BytesParser(
                policy=policy.default
            ).parsebytes(raw_bytes)

            parsed = parse_email(
                raw_bytes,
                filename,
            )

            basic = (
                parsed.get("basic_information", {})
                if isinstance(
                    parsed.get(
                        "basic_information",
                        {},
                    ),
                    dict,
                )
                else {}
            )

            body = (
                parsed.get("body", {})
                if isinstance(
                    parsed.get(
                        "body",
                        {},
                    ),
                    dict,
                )
                else {}
            )

            headers = (
                parsed.get("headers", {})
                if isinstance(
                    parsed.get(
                        "headers",
                        {},
                    ),
                    dict,
                )
                else {}
            )

            thread_message = {
                "message_id": message.get(
                    "Message-ID"
                ),
                "in_reply_to": message.get(
                    "In-Reply-To"
                ),
                "references": message.get(
                    "References"
                ),
                "subject": basic.get(
                    "subject"
                ),
                "from": basic.get(
                    "from"
                ),
                "sender": basic.get(
                    "from"
                ),
                "to": basic.get(
                    "to"
                ),
                "cc": basic.get(
                    "cc"
                ),
                "reply_to": basic.get(
                    "reply_to"
                ),
                "return_path": basic.get(
                    "return_path"
                ),
                "date": basic.get(
                    "date"
                ),
                "body": body.get(
                    "text",
                    "",
                ),
                "headers": headers,
                "source_filename": filename,
            }

            parsed_messages.append(
                thread_message
            )

        except HTTPException:
            raise

        except Exception as parse_error:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Failed to parse thread message "
                    f"'{filename}': "
                    f"{parse_error}"
                ),
            )

    # --------------------------------------------------------
    # Deterministic ordering
    #
    # Parse dates only for ordering; the original filename and
    # input index remain available as tie-breakers.
    # --------------------------------------------------------

    def _sort_key(item):
        return (
            str(item.get("date") or ""),
            str(item.get("source_filename") or ""),
        )

    parsed_messages.sort(
        key=_sort_key
    )

    try:
        thread_result = analyze_thread_to_dict(
            parsed_messages
        )

    except Exception as thread_error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Email Thread Intelligence analysis failed: "
                + str(thread_error)
            ),
        )

    return {
        "success": True,
        "analysis": {
            "email_thread_intelligence": thread_result,
        },
        "thread_message_count": len(
            parsed_messages
        ),
        "message_filenames": [
            item.get(
                "source_filename",
                "",
            )
            for item in parsed_messages
        ],
        "static_only": True,
    }


@app.post("/api/webhooks/email")
async def ingest_email_webhook(request: Request):
    """Receive a provider-neutral RFC822 email using an HMAC-authenticated webhook.

    The route stays disabled until MAILTRACE_WEBHOOK_SECRET is configured.
    The HMAC covers the timestamp, event ID, filename, trusted SMTP context, and raw body.
    """
    secret = os.environ.get("MAILTRACE_WEBHOOK_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(
            status_code=503,
            detail="Email webhook is disabled; configure a 32-character secret.",
        )
    try:
        # Validate policy configuration before claiming or analyzing a delivery.
        build_mail_flow_decision({})
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

    filename = request.headers.get("X-MailTrace-Filename", "webhook.eml")
    if Path(filename).name != filename or not filename.lower().endswith((".eml", ".msg")):
        raise HTTPException(
            status_code=400,
            detail="X-MailTrace-Filename must be a simple .eml or .msg filename.",
        )

    event_id = request.headers.get("X-MailTrace-Event-Id", "")
    if (
        not event_id
        or len(event_id) > 128
        or any(
            not (char.isascii() and (char.isalnum() or char in "._:-"))
            for char in event_id
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="X-MailTrace-Event-Id is required and must be a safe 1-128 character ID.",
        )

    smtp_headers = {
        "client_ip": request.headers.get("X-MailTrace-SMTP-Client-IP", "").strip(),
        "mail_from": request.headers.get("X-MailTrace-SMTP-Mail-From", "").strip(),
        "helo": request.headers.get("X-MailTrace-SMTP-HELO", "").strip().lower(),
    }
    smtp_recipient = request.headers.get("X-MailTrace-SMTP-RCPT-TO", "").strip()
    if smtp_recipient:
        if len(smtp_recipient) > 2000 or "\r" in smtp_recipient or "\n" in smtp_recipient:
            raise HTTPException(status_code=400, detail="SMTP recipient metadata is malformed.")
        parsed_recipients = [
            address.strip().lower()
            for _, address in getaddresses([smtp_recipient])
            if address and "@" in address
        ]
        if not parsed_recipients:
            raise HTTPException(status_code=400, detail="SMTP recipient metadata is malformed.")
        smtp_headers["recipient"] = ", ".join(parsed_recipients)
    base_smtp_fields = [bool(smtp_headers[key]) for key in ("client_ip", "mail_from", "helo")]
    if any(base_smtp_fields) and not all(base_smtp_fields):
        raise HTTPException(
            status_code=400,
            detail="Supply all three trusted SMTP context headers together, or omit them all.",
        )
    smtp_context = None
    if all(base_smtp_fields):
        try:
            smtp_headers["client_ip"] = str(ipaddress.ip_address(smtp_headers["client_ip"]))
        except ValueError:
            raise HTTPException(status_code=400, detail="SMTP client IP is invalid.")
        if (
            len(smtp_headers["mail_from"]) > 320
            or len(smtp_headers["helo"]) > 255
            or "\r" in smtp_headers["mail_from"]
            or "\n" in smtp_headers["mail_from"]
            or "\r" in smtp_headers["helo"]
            or "\n" in smtp_headers["helo"]
            or (smtp_headers["mail_from"] != "<>" and "@" not in smtp_headers["mail_from"])
            or not smtp_headers["helo"]
            or any(
                not (char.isascii() and (char.isalnum() or char in ".-"))
                for char in smtp_headers["helo"]
            )
            or any(
                not label
                or label.startswith("-")
                or label.endswith("-")
                or len(label) > 63
                for label in smtp_headers["helo"].rstrip(".").split(".")
            )
        ):
            raise HTTPException(status_code=400, detail="SMTP envelope metadata is malformed.")
        smtp_context = smtp_headers
    elif smtp_recipient:
        smtp_context = {"recipient": smtp_headers["recipient"]}

    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > MAX_EMAIL_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Email file exceeds the 25 MiB upload limit.",
            )

    timestamp = request.headers.get("X-MailTrace-Timestamp", "")
    if not timestamp.isascii() or not timestamp.isdecimal():
        raise HTTPException(status_code=401, detail="Missing or invalid webhook timestamp.")
    try:
        signed_at = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Missing or invalid webhook timestamp.")
    if abs(int(datetime.now(timezone.utc).timestamp()) - signed_at) > 300:
        raise HTTPException(status_code=401, detail="Webhook timestamp is outside the 5-minute validity window.")

    supplied_signature = request.headers.get("X-MailTrace-Signature", "")
    if supplied_signature.startswith("sha256="):
        supplied_signature = supplied_signature[7:]
    signed_metadata = {
        "timestamp": timestamp,
        "event_id": event_id,
        "filename": filename,
        "smtp_context": smtp_context,
    }
    signed_metadata_bytes = json.dumps(
        signed_metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signed_metadata_bytes + b"\n" + bytes(content),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied_signature.lower(), expected_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    fingerprint_metadata = {
        "event_id": event_id,
        "filename": filename,
        "smtp_context": smtp_context,
    }
    fingerprint_bytes = json.dumps(
        fingerprint_metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n" + bytes(content)
    fingerprint = hashlib.sha256(fingerprint_bytes).hexdigest()
    delivery = begin_email_webhook_event(event_id, fingerprint, _request_tenant_id(request))

    if delivery["status"] == "conflict":
        raise HTTPException(
            status_code=409,
            detail="This event ID was already used for a different message or SMTP context.",
        )
    if delivery["status"] == "completed":
        try:
            prior_decision = json.loads(delivery.get("policy_decision_json") or "null")
        except (TypeError, json.JSONDecodeError):
            prior_decision = None
        prior_alert = get_email_alert_by_event(event_id, _request_tenant_id(request))
        try:
            prior_notice = json.loads(prior_alert.get("user_notice_json") or "null") if prior_alert else None
        except (TypeError, json.JSONDecodeError):
            prior_notice = None
        return {
            "success": True,
            "event_id": event_id,
            "status": "completed",
            "duplicate": True,
            "attempts": delivery["attempts"],
            "investigation_id": delivery["investigation_id"],
            "mail_flow_decision": prior_decision,
            "alert": ({
                "alert_id": prior_alert["alert_id"],
                "case_id": prior_alert.get("case_id"),
                "severity": prior_alert["severity"],
                "status": prior_alert["status"],
                "user_notification": prior_notice,
            } if prior_alert else None),
        }
    if (
        delivery["status"] == "processing"
        and delivery["duplicate"]
        and not delivery.get("retry", False)
    ):
        return JSONResponse(
            status_code=202,
            content={
                "success": True,
                "event_id": event_id,
                "status": "processing",
                "duplicate": True,
                "attempts": delivery["attempts"],
            },
        )

    uploaded_email = UploadFile(
        file=BytesIO(bytes(content)),
        filename=filename,
    )
    heartbeat_stop, heartbeat_worker = _start_webhook_lease_heartbeat(
        event_id,
        delivery["lease_token"],
    )
    try:
        analysis_response = await _analyze_email(uploaded_email, smtp_context)
        investigation_id = analysis_response.get("investigation_id")
        if not investigation_id:
            raise RuntimeError("Analysis completed without an investigation ID.")
        decision = build_mail_flow_decision(analysis_response.get("analysis", {}))
        alert = None
        if should_create_alert(decision):
            alert = create_email_alert(
                event_id=event_id,
                investigation_id=investigation_id,
                severity=decision["severity"],
                threat_score=decision["threat_score"],
                confidence=decision["confidence"],
                recommended_action=decision["recommended_action"],
                policy_version=decision["policy_version"],
                user_notice=decision.get("user_notification"),
                tenant_id=_request_tenant_id(request),
            )
        finalized = complete_email_webhook_event(
            event_id,
            investigation_id,
            delivery["lease_token"],
            decision,
            _request_tenant_id(request),
        )
        if not finalized:
            # This worker lost its lease while analyzing. Do not report its
            # result as the canonical delivery; the current owner will finish it.
            return JSONResponse(
                status_code=202,
                content={
                    "success": True,
                    "event_id": event_id,
                    "status": "processing",
                    "duplicate": True,
                    "attempts": delivery["attempts"],
                },
            )
        analysis_response["webhook"] = {
            "event_id": event_id,
            "status": "completed",
            "duplicate": False,
            "attempts": delivery["attempts"],
        }
        analysis_response["mail_flow_decision"] = decision
        analysis_response["alert"] = ({
            "alert_id": alert["alert_id"],
            "case_id": alert.get("case_id"),
            "severity": alert["severity"],
            "status": alert["status"],
            "user_notification": decision.get("user_notification"),
        } if alert else None)
        return analysis_response
    except HTTPException as error:
        fail_email_webhook_event(
            event_id,
            f"HTTP_{error.status_code}:{type(error).__name__}",
            delivery["lease_token"],
            _request_tenant_id(request),
        )
        raise HTTPException(
            status_code=error.status_code,
            detail={
                "event_id": event_id,
                "status": "failed",
                "attempts": delivery["attempts"],
                "retryable": error.status_code >= 500,
                "message": str(error.detail),
            },
        )
    except Exception as error:
        fail_email_webhook_event(
            event_id,
            type(error).__name__,
            delivery["lease_token"],
            _request_tenant_id(request),
        )
        raise HTTPException(
            status_code=500,
            detail={
                "event_id": event_id,
                "status": "failed",
                "attempts": delivery["attempts"],
                "retryable": True,
                "message": "Webhook email analysis failed.",
            },
        )
    finally:
        heartbeat_stop.set()
        heartbeat_worker.join(timeout=2)


class EmployeeEmailReportSubmission(BaseModel):
    investigation_id: str = Field(min_length=1, max_length=128)
    incident_type: Literal[
        "suspicious",
        "clicked_link",
        "opened_attachment",
        "shared_credentials",
        "made_payment",
    ]
    employee_note: str = Field(default="", max_length=1000)


def _require_employee_principal(request: Request):
    principal = getattr(request.state, "principal", None)
    if (
        principal is None
        or "employee" not in principal.roles
        or not principal.subject_id
        or not principal.email
    ):
        raise HTTPException(status_code=403, detail="Authenticated employee identity is required.")
    return principal


@app.post("/api/employee/reports")
def submit_employee_report(payload: EmployeeEmailReportSubmission, request: Request):
    """Report only a message addressed to the authenticated employee mailbox."""
    principal = _require_employee_principal(request)
    investigation = get_investigation(payload.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Message not found for this employee account.")
    recipients = {
        address.strip().lower()
        for _, address in getaddresses([str(investigation.get("smtp_recipient") or "")])
        if address and "@" in address
    }
    if principal.email.lower() not in recipients:
        raise HTTPException(status_code=404, detail="Message not found for this employee account.")

    result = submit_employee_email_report(
        tenant_id=principal.tenant_id,
        reporter_subject=principal.subject_id,
        reporter_email=principal.email,
        investigation_id=payload.investigation_id,
        incident_type=payload.incident_type,
        employee_note="".join(
            char for char in payload.employee_note
            if char in "\n\t" or ord(char) >= 32
        ).strip(),
        hourly_limit=10,
    )
    if result is None:
        raise HTTPException(
            status_code=429,
            detail="Report limit reached. Existing reports can still be viewed; contact the security team for an urgent incident.",
            headers={"Retry-After": "3600"},
        )
    report, created = result
    routing = None
    routing_error = None
    case_id = report.get("case_id") if isinstance(report, dict) else None
    if case_id:
        try:
            from services.case_routing import route_employee_case
            routing = route_employee_case(
                case_id=case_id,
                tenant_id=principal.tenant_id,
                reporter_subject=principal.subject_id,
            )
        except Exception as error:
            # Reporting must not fail just because SOC routing is temporarily unavailable.
            # The case remains visible for SOC recovery/reconciliation.
            routing_error = str(error)[:300]
    response_payload = {"success": True, "duplicate": not created, "report": report}
    if routing is not None:
        response_payload["routing"] = routing
    if routing_error is not None:
        response_payload["routing_status"] = "UNROUTED"
        response_payload["routing_error"] = routing_error
    return JSONResponse(
        status_code=201 if created else 200,
        content=response_payload,
    )


@app.get("/api/employee/reports")
def list_my_employee_reports(request: Request, limit: int = 50):
    principal = _require_employee_principal(request)
    reports = get_employee_email_reports(
        principal.tenant_id, principal.subject_id, limit
    )
    return {"success": True, "count": len(reports), "reports": reports}


@app.get("/api/employee/reports/{report_id}")
def get_my_employee_report(report_id: str, request: Request):
    principal = _require_employee_principal(request)
    report = get_employee_email_report(
        principal.tenant_id, principal.subject_id, report_id
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"success": True, "report": report}


@app.get("/api/alerts")
def list_security_alerts(limit: int = 100, status: str | None = None):
    """Return durable high-risk mail alerts for the analyst notification UI."""
    normalized_status = status.strip().upper() if status else None
    if normalized_status and normalized_status not in {"NEW", "ACKNOWLEDGED", "RESOLVED"}:
        raise HTTPException(status_code=400, detail="Unsupported alert status filter.")
    alerts = get_email_alerts(limit=limit, status=normalized_status, tenant_id=principal.tenant_id if principal else None)
    for alert in alerts:
        try:
            alert["user_notification"] = json.loads(alert.pop("user_notice_json") or "null")
        except (TypeError, json.JSONDecodeError):
            alert["user_notification"] = None
    return {"success": True, "count": len(alerts), "alerts": alerts}


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_security_alert(alert_id: str, request: Request):
    """Persist analyst acknowledgement on the server instead of browser storage."""
    principal = getattr(request.state, "principal", None)
    actor = f"tenant:{principal.tenant_id}" if principal else "local-loopback-analyst"
    alert = acknowledge_email_alert(alert_id, actor, principal.tenant_id if principal else None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Security alert not found.")
    return {"success": True, "alert": alert}


@app.get("/api/alerts/{alert_id}/history")
def get_security_alert_history(alert_id: str):
    events = get_email_alert_history(alert_id)
    if not events:
        raise HTTPException(status_code=404, detail="Security alert history not found.")
    return {"success": True, "alert_id": alert_id, "events": events}


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_security_alert(alert_id: str, request: Request):
    principal = getattr(request.state, "principal", None)
    actor = f"tenant:{principal.tenant_id}" if principal else "local-loopback-analyst"
    alert = resolve_email_alert(alert_id, actor, principal.tenant_id if principal else None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Security alert not found.")
    return {"success": True, "alert": alert}


@app.post("/api/analyze-email")
async def analyze_email(
    file: UploadFile = File(...),
):
    return await _analyze_email(file)


async def _analyze_email(
    file: UploadFile,
    trusted_smtp_context: dict[str, str] | None = None,
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

        file_content = await file.read(MAX_EMAIL_UPLOAD_BYTES + 1)
        if len(file_content) > MAX_EMAIL_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Email file exceeds the 25 MiB upload limit."
                ),
            )

        # -------------------------------------
        # PARSE EMAIL
        # -------------------------------------

        result = parse_email(
            file_content,
            file.filename,
        )
        forensic_input = result.pop("_forensics_input", None) or file_content


        # -------------------------------------
        # EMAIL THREAD INTELLIGENCE
        # -------------------------------------
        try:
            thread_basic = (
                result.get("basic_information", {})
                if isinstance(
                    result.get("basic_information", {}),
                    dict,
                )
                else {}
            )

            thread_body = (
                result.get("body", {})
                if isinstance(
                    result.get("body", {}),
                    dict,
                )
                else {}
            )

            thread_message = {
                "message_id": thread_basic.get(
                    "message_id"
                ),
                "subject": thread_basic.get(
                    "subject"
                ),
                "from": thread_basic.get(
                    "from"
                ),
                "to": thread_basic.get(
                    "to"
                ),
                "cc": thread_basic.get(
                    "cc"
                ),
                "reply_to": thread_basic.get(
                    "reply_to"
                ),
                "return_path": thread_basic.get(
                    "return_path"
                ),
                "date": thread_basic.get(
                    "date"
                ),
                "body": thread_body.get(
                    "text",
                    "",
                ),
                "headers": (
                    result.get(
                        "headers",
                        {}
                    )
                    if isinstance(
                        result.get(
                            "headers",
                            {}
                        ),
                        dict,
                    )
                    else {}
                ),
            }

            thread_messages = [
                thread_message
            ]

            email_thread_intelligence = (
                analyze_thread_to_dict(
                    thread_messages
                )
            )

            result["email_thread_intelligence"] = (
                email_thread_intelligence
            )

        except Exception as thread_error:
            result["email_thread_intelligence"] = {
                "status": "error",
                "analysis_version": "1.1.0",
                "static_only": True,
                "error": str(
                    thread_error
                ),
            }


        # -------------------------------------
        # EMAIL FORENSICS
        # -------------------------------------

        forensic_analysis = analyze_email_forensics(
            forensic_input,
            verify_authentication=not file.filename.lower().endswith(".msg"),
            smtp_context=(
                ({key: value for key, value in trusted_smtp_context.items() if key != "recipient"} or None) if isinstance(trusted_smtp_context, dict) else None
                if not file.filename.lower().endswith(".msg")
                else None
            ),
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
            authentication_validation = forensic_analysis.get(
                "authentication_analysis", {}
            ).get("validation", {})
            enriched_forensics = analyze_email_forensics(
                forensic_input,
                forensic_ip_intelligence,
                verify_authentication=False,
            )
            enriched_forensics["authentication_analysis"]["validation"] = (
                authentication_validation
            )
            forensic_analysis = enriched_forensics

        result["email_forensics"] = forensic_analysis

        # -------------------------------------
        # CALIBRATED AI EMAIL ANALYSIS
        # -------------------------------------

        try:
            basic_information_for_ai = (
                result.get("basic_information", {})
                if isinstance(
                    result.get("basic_information", {}),
                    dict,
                )
                else {}
            )

            body_for_ai = (
                result.get("body", {})
                if isinstance(
                    result.get("body", {}),
                    dict,
                )
                else {}
            )

            headers_for_ai = (
                result.get("headers", {})
                if isinstance(
                    result.get("headers", {}),
                    dict,
                )
                else {}
            )

            authentication_validation = (
                forensic_analysis.get("authentication_analysis", {}).get(
                    "validation", {}
                )
                if isinstance(
                    forensic_analysis.get("authentication_analysis", {}),
                    dict,
                )
                else {}
            )

            # Build a stable AI input envelope from the parser output.
            # Multiple fallbacks are intentional because parser versions
            # can expose the same field at different levels.
            ai_email = {
                "sender": (
                    basic_information_for_ai.get("from")
                    or result.get("sender")
                    or result.get("from")
                    or headers_for_ai.get("From")
                    or ""
                ),
                "reply_to": (
                    basic_information_for_ai.get("reply_to")
                    or result.get("reply_to")
                    or headers_for_ai.get("Reply-To")
                    or headers_for_ai.get("reply-to")
                    or ""
                ),
                "subject": (
                    basic_information_for_ai.get("subject")
                    or result.get("subject")
                    or ""
                ),
                "body": (
                    body_for_ai.get("text")
                    or body_for_ai.get("plain")
                    or body_for_ai.get("content")
                    or result.get("body_text")
                    or result.get("text")
                    or ""
                ),
                "headers": headers_for_ai,
                "urls": (
                    result.get("urls")
                    or body_for_ai.get("urls")
                    or []
                ),
                "attachments": (
                    result.get("attachments")
                    or []
                ),
                "authentication_validation": authentication_validation,
            }

            ai_result = analyze_email_ai(
                email=ai_email,
                model_dir="models/email_ai",
                fallback_result=result.get(
                    "threat_analysis",
                    {},
                ),
            )

        except Exception as ai_error:
            ai_result = {
                "status": "ERROR",
                "model_ready": False,
                "classification": "UNKNOWN",
                "model_probability": 0.0,
                "calibrated_probability": None,
                "error": str(ai_error),
            }

        result["email_ai"] = ai_result

        # -------------------------------------
        # THREAT INTELLIGENCE / IOC CORRELATION
        # -------------------------------------

        threat_intelligence = {
            "enabled": True,
            "ioc_summary": {
                "total": 0,
                "ip": 0,
                "ip:port": 0,
                "url": 0,
                "domain": 0,
            },
            "iocs": [],
            "matches": {},
            "matched_count": 0,
            "status": "no_iocs",
        }

        try:
            email_body = (
                result.get("body", {}).get("text", "")
                or ""
            )

            normalized_iocs = extract_iocs(
                email_body
            )

            threat_intelligence["ioc_summary"] = (
                summarize_iocs(normalized_iocs)
            )

            threat_intelligence["iocs"] = (
                normalized_iocs
            )

            ioc_values = [
                item.get("ioc")
                for item in normalized_iocs
                if item.get("ioc")
            ]

            if ioc_values:
                matches = lookup_threat_intelligence_batch(
                    ioc_values,
                    limit_per_ioc=20,
                    tenant_id=_request_tenant_id(request),
                )

                threat_intelligence["matches"] = matches

                threat_intelligence["matched_count"] = (
                    len(matches)
                )

                if matches:
                    threat_intelligence["status"] = "matched"
                else:
                    threat_intelligence["status"] = "no_matches"

        except Exception as ioc_error:
            threat_intelligence["status"] = "error"
            threat_intelligence["error"] = str(ioc_error)

        result["threat_intelligence"] = (
            threat_intelligence
        )
                # -------------------------------------
        # THREAT INTELLIGENCE V2 ENGINE
        # -------------------------------------

        try:
            threat_intelligence_v2 = analyze_threat_intelligence_v2(
                indicators=threat_intelligence.get(
                    "iocs",
                    []
                ),
                matches=threat_intelligence.get(
                    "matches",
                    {}
                ),
                ip_intelligence=forensic_ip_intelligence,
            )

            result["threat_intelligence_v2"] = (
                threat_intelligence_v2
            )

        except Exception as v2_error:

            result["threat_intelligence_v2"] = {
                "status": "error",
                "error": str(v2_error),
            }

        # -------------------------------------
        # AI + FORENSICS + TI + IP INTELLIGENCE FUSION
        # -------------------------------------

        try:
            intelligence_fusion = analyze_email_intelligence(
                email=ai_email,
                ai_result=ai_result,
                forensic=forensic_analysis,
                threat_intelligence=threat_intelligence,
                ip_intelligence=forensic_ip_intelligence,
            )

        except Exception as fusion_error:
            intelligence_fusion = {
                "status": "ERROR",
                "engine": "mailtrace-ai-intelligence-fusion",
                "version": "2.3.0",
                "classification": (
                    ai_result.get(
                        "classification",
                        "UNKNOWN",
                    )
                    if isinstance(
                        ai_result,
                        dict,
                    )
                    else "UNKNOWN"
                ),
                "model_probability": (
                    ai_result.get(
                        "calibrated_probability",
                        ai_result.get(
                            "model_probability",
                            0.0,
                        ),
                    )
                    if isinstance(
                        ai_result,
                        dict,
                    )
                    else 0.0
                ),
                "unified_risk_score": 0.0,
                "risk_tier": "LOW",
                "decision": "FUSION_ERROR",
                "error": str(fusion_error),
                "governance": {
                    "read_only": True,
                    "persistence": False,
                    "execution_side_effect": False,
                    "autonomous_destructive_action": False,
                },
            }

        result["intelligence_fusion"] = intelligence_fusion

        # -------------------------------------
        # IOC THREAT SCORE ENRICHMENT
        # -------------------------------------

        ioc_threat_score = calculate_ioc_threat_score(
            threat_intelligence
        )

        result["ioc_threat_score"] = ioc_threat_score

        # Keep the parser's rule score for transparency, but use the
        # AI/forensics/TI fusion score as the authoritative final score.
        rule_threat_score = int(
            result.get("threat_analysis", {}).get(
                "score",
                0
            )
            or 0
        )
        fusion_score = intelligence_fusion.get("unified_risk_score")
        if (
            intelligence_fusion.get("status") == "ANALYZED"
            and isinstance(fusion_score, (int, float))
            and 0 <= fusion_score <= 100
        ):
            combined_threat_score = round(fusion_score)
            score_source = "intelligence_fusion"
        else:
            # Safe fallback when fusion fails: retain the legacy parser + IOC score.
            combined_threat_score = min(
                rule_threat_score + ioc_threat_score.get("score", 0),
                100,
            )
            score_source = "parser_rules_plus_ioc_fallback"

        result["threat_analysis"]["rule_score"] = rule_threat_score
        result["threat_analysis"]["score"] = combined_threat_score
        result["threat_analysis"]["score_source"] = score_source

                # -------------------------------------
        # UPDATE VERDICT / CONFIDENCE
        # -------------------------------------

        if combined_threat_score >= 90:

            result["threat_analysis"]["verdict"] = "CRITICAL"
            result["threat_analysis"]["confidence"] = "HIGH"

        elif combined_threat_score >= 75:

            result["threat_analysis"]["verdict"] = "HIGH RISK"
            result["threat_analysis"]["confidence"] = "HIGH"

        elif combined_threat_score >= 50:

            result["threat_analysis"]["verdict"] = "HIGH RISK"
            result["threat_analysis"]["confidence"] = "HIGH"

        elif combined_threat_score >= 30:

            result["threat_analysis"]["verdict"] = "SUSPICIOUS"
            result["threat_analysis"]["confidence"] = "MEDIUM"

        else:

            result["threat_analysis"]["verdict"] = "LOW RISK"
            result["threat_analysis"]["confidence"] = "LOW"

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
        # EVIDENCE / PRIVACY / INTEGRITY GOVERNANCE
        # -------------------------------------

        evidence_governance = _build_evidence_governance(
            file_content=file_content,
            filename=file.filename,
            investigation_id=investigation_id,
            analysis_result=result,
            tenant_id=_request_tenant_id(request),
        )

        result["evidence_governance"] = (
            evidence_governance
        )

        # -------------------------------------
        # SAVE INVESTIGATION
        # -------------------------------------

        save_investigation(
            tenant_id=_request_tenant_id(request),

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

            smtp_recipient=(
                trusted_smtp_context.get("recipient")
                if isinstance(trusted_smtp_context, dict)
                else None
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


# =========================================================
# EVIDENCE / PRIVACY / INTEGRITY API
# =========================================================

def _require_evidence_tenant_access(evidence_id: str, request: Request):
    record = evidence_custody.get(evidence_id)
    principal = getattr(request.state, "principal", None)
    tenant_id = getattr(principal, "tenant_id", "__local__")
    owner = (record.core_metadata or {}).get("tenant_id")
    if owner != tenant_id:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return record


@app.get("/api/evidence/{evidence_id}")
def get_evidence_record(
    evidence_id: str,
    request: Request,
):
    try:
        record = _require_evidence_tenant_access(evidence_id, request)

        verification = evidence_custody.verify(
            evidence_id
        )

        anchors = integrity_anchoring.list_anchors(
            evidence_id=evidence_id
        )

        return {
            "success": True,
            "evidence": _model_to_dict(
                record
            ),
            "verification": _model_to_dict(
                verification
            ),
            "integrity_anchors": [
                _model_to_dict(item)
                for item in anchors
            ],
        }

    except Exception as error:
        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence lookup failed: "
                + str(error)
            ),
        )


@app.get("/api/evidence/{evidence_id}/integrity")
def verify_evidence_integrity(
    evidence_id: str,
    request: Request,
):
    try:
        _require_evidence_tenant_access(evidence_id, request)
        custody = evidence_custody.verify(evidence_id)

        anchors = integrity_anchoring.list_anchors(
            evidence_id=evidence_id
        )

        anchor_checks = []

        for anchor in anchors:
            verification = (
                integrity_anchoring.verify_anchor(
                    anchor.anchor_id
                )
            )

            anchor_checks.append({
                "anchor_id":
                    anchor.anchor_id,
                "verification":
                    _model_to_dict(
                        verification
                    ),
            })

        return {
            "success": True,
            "evidence_id": evidence_id,
            "custody": _model_to_dict(
                custody
            ),
            "integrity": anchor_checks,
        }

    except Exception as error:
        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence integrity verification failed: "
                + str(error)
            ),
        )


@app.post("/api/privacy/redact")
async def privacy_redact_api(
    payload: dict,
):
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="payload must be an object",
        )

    record = payload.get(
        "record",
        {},
    )

    classification = payload.get(
        "classification"
    )

    mode = payload.get(
        "mode",
        "MASK",
    )

    if not isinstance(record, dict):
        raise HTTPException(
            status_code=400,
            detail="record must be an object",
        )

    try:
        redaction = privacy_governance.redact(
            record,
            classification=classification,
            mode=mode,
        )

        return {
            "success": True,
            "redaction": _model_to_dict(
                redaction
            ),
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=(
                "Privacy redaction failed: "
                + str(error)
            ),
        )


# =========================================================
# REAL-TIME THREAT INTELLIGENCE
# =========================================================

@app.get("/api/threat-intelligence/live")
def get_live_threat_intelligence(request: Request):

    try:

        investigations = get_all_investigations(_request_tenant_id(request))

        events = []

        for investigation in investigations:

            score = int(
                investigation.get(
                    "threat_score",
                    0
                )
                or 0
            )

            verdict = str(
                investigation.get(
                    "threat_verdict",
                    "UNKNOWN"
                )
                or "UNKNOWN"
            ).upper()

            if score >= 90 or verdict == "CRITICAL":
                severity = "CRITICAL"

            elif score >= 70 or verdict in (
                "HIGH",
                "HIGH RISK"
            ):
                severity = "HIGH"

            elif score >= 40 or verdict == "SUSPICIOUS":
                severity = "MEDIUM"

            else:
                severity = "LOW"

            event = {
                "investigation_id":
                    investigation.get(
                        "investigation_id"
                    ),

                "subject":
                    investigation.get(
                        "subject"
                    ) or "Unknown",

                "sender":
                    investigation.get(
                        "sender"
                    ) or "Unknown",

                "recipient":
                    investigation.get(
                        "recipient"
                    ) or "Unknown",

                "threat_score":
                    score,

                "severity":
                    severity,

                "verdict":
                    verdict,

                "confidence":
                    investigation.get(
                        "threat_confidence"
                    ),

                "created_at":
                    investigation.get(
                        "created_at",
                        ""
                    ),

                "ioc_summary": {
                    "total": 0,
                    "ip": 0,
                    "ip:port": 0,
                    "url": 0,
                    "domain": 0
                },

                "iocs": [],

                "threat_matches": {},

                "matched_count": 0,

                "threat_intelligence_status":
                    "not_loaded"
            }

            # ------------------------------------------------
            # LOAD STORED ANALYSIS
            # ------------------------------------------------

            analysis_json = investigation.get(
                "analysis_json"
            )

            if analysis_json:

                try:

                    import json

                    analysis = json.loads(
                        analysis_json
                    )

                    threat_intelligence = (
                        analysis.get(
                            "threat_intelligence",
                            {}
                        )
                        or {}
                    )

                    event["ioc_summary"] = (
                        threat_intelligence.get(
                            "ioc_summary",
                            event["ioc_summary"]
                        )
                    )

                    event["iocs"] = (
                        threat_intelligence.get(
                            "iocs",
                            []
                        )
                    )

                    event["threat_matches"] = (
                        threat_intelligence.get(
                            "matches",
                            {}
                        )
                    )

                    event["matched_count"] = (
                        threat_intelligence.get(
                            "matched_count",
                            0
                        )
                    )

                    event[
                        "threat_intelligence_status"
                    ] = (
                        threat_intelligence.get(
                            "status",
                            "unknown"
                        )
                    )

                except Exception:

                    event[
                        "threat_intelligence_status"
                    ] = "parse_error"

            events.append(event)

        return {
            "success": True,
            "status": "operational",
            "count": len(events),
            "events": events
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load "
                "real-time threat intelligence: "
                + str(error)
            )
        )
@app.get("/api/threat-intelligence/stream")
async def stream_live_threat_intelligence(request: Request):
    """Send a current snapshot immediately, then stream DB changes over SSE."""
    async def updates():
        previous_key = None
        while not await request.is_disconnected():
            try:
                current_key = await asyncio.to_thread(
                    get_investigation_snapshot_marker
                )
                if current_key != previous_key:
                    snapshot = await asyncio.to_thread(
                        get_live_threat_intelligence, request
                    )
                    events = snapshot.get("events", [])
                    latest = events[0] if events else {}
                    event_id = str(latest.get("investigation_id") or "0")
                    yield (
                        f"id: {event_id}\n"
                        f"data: {json.dumps(snapshot, separators=(',', ':'))}\n\n"
                    )
                    previous_key = current_key
                else:
                    yield ": keep-alive\n\n"
            except Exception:
                yield ": update-retry\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        updates(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# =========================================================
# EXTERNAL THREAT INTELLIGENCE ROUTER
# =========================================================

from routes.threat_intelligence import (
    router as threat_intelligence_router
)

app.include_router(
    threat_intelligence_router
)




# =========================================================
# SERVER STARTUP
# =========================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
