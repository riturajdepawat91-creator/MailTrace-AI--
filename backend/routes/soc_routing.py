from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from database.database import (
    configure_soc_queue, configure_employee_region, configure_soc_analyst,
)
from services.case_routing import get_routing

router = APIRouter(prefix="/api/soc/routing", tags=["SOC Routing"])

ADMIN_ROLES = {"soc_lead", "tenant_admin", "platform_admin", "admin"}


def _principal(request: Request):
    principal = getattr(request.state, "principal", None)
    if principal is None or not principal.subject_id:
        raise HTTPException(status_code=401, detail="Authenticated SOC identity is required.")
    return principal


def _require_admin(request: Request):
    principal = _principal(request)
    if not principal.roles.intersection(ADMIN_ROLES):
        raise HTTPException(status_code=403, detail="SOC lead or tenant administrator access is required.")
    return principal


class QueueConfig(BaseModel):
    queue_id: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=2, max_length=120)
    region_key: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    is_central: bool = False
    active: bool = True


class EmployeeRegionConfig(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    region_key: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    active: bool = True


class AnalystConfig(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    region_key: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    max_open_cases: int = Field(default=20, ge=1, le=1000)
    active: bool = True


@router.post("/queues")
def upsert_queue(payload: QueueConfig, request: Request):
    principal = _require_admin(request)
    return {"success": True, "queue": configure_soc_queue(
        principal.tenant_id, payload.queue_id, payload.name, payload.region_key,
        is_central=payload.is_central, active=payload.active,
    )}


@router.post("/employee-region")
def upsert_employee_region(payload: EmployeeRegionConfig, request: Request):
    principal = _require_admin(request)
    return {"success": True, "assignment": configure_employee_region(
        principal.tenant_id, payload.subject_id, payload.region_key, active=payload.active,
    )}


@router.post("/analysts")
def upsert_analyst(payload: AnalystConfig, request: Request):
    principal = _require_admin(request)
    return {"success": True, "analyst": configure_soc_analyst(
        principal.tenant_id, payload.subject_id, payload.region_key,
        max_open_cases=payload.max_open_cases, active=payload.active,
    )}


@router.get("/cases/{case_id}")
def case_routing(case_id: str, request: Request):
    principal = _principal(request)
    if not principal.roles.intersection(ADMIN_ROLES | {"analyst"}):
        raise HTTPException(status_code=403, detail="SOC analyst access is required.")
    routing = get_routing(case_id, principal.tenant_id)
    if routing is None:
        raise HTTPException(status_code=404, detail="No routing record found for this case.")
    return {"success": True, "routing": routing}
