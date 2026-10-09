"""Regional SOC case routing service.

Routing is based only on configured organizational region, never on IP geolocation.
"""
from database.database import route_case_to_soc, get_case_routing


def route_employee_case(case_id: str, tenant_id: str, reporter_subject: str):
    return route_case_to_soc(
        case_id=case_id,
        tenant_id=tenant_id,
        reporter_subject=reporter_subject,
        actor_subject=reporter_subject,
    )


def get_routing(case_id: str, tenant_id: str):
    return get_case_routing(case_id, tenant_id)
