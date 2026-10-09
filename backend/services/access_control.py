"""Environment-configured API key authentication for hosted deployments.

Keys are supplied as SHA-256 digests so a database/config snapshot does not
contain usable credentials. Local development remains loopback-only and does
not need a key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass


_TENANT_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,62}$")


@dataclass(frozen=True)
class ApiPrincipal:
    tenant_id: str
    roles: frozenset[str]
    subject_id: str | None = None
    email: str | None = None


def is_production() -> bool:
    return os.getenv("MAILTRACE_ENV", "development").strip().lower() in {
        "prod", "production"
    }


def configured_api_keys() -> tuple[tuple[str, ApiPrincipal], ...]:
    """Parse MAILTRACE_API_KEYS_JSON; each entry has tenant_id, token_sha256, roles."""
    raw = os.getenv("MAILTRACE_API_KEYS_JSON", "").strip()
    if not raw:
        if is_production():
            raise RuntimeError("MAILTRACE_API_KEYS_JSON is required in production.")
        return ()

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("MAILTRACE_API_KEYS_JSON must be valid JSON.") from error
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("MAILTRACE_API_KEYS_JSON must be a non-empty JSON array.")

    parsed: list[tuple[str, ApiPrincipal]] = []
    seen_digests: set[str] = set()
    tenant_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Every API key entry must be a JSON object.")
        tenant_id = str(entry.get("tenant_id", ""))
        digest = str(entry.get("token_sha256", "")).lower()
        roles_value = entry.get("roles", ["read", "write"])
        if not _TENANT_ID.fullmatch(tenant_id):
            raise RuntimeError("API key tenant_id has an invalid format.")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RuntimeError("API key token_sha256 must be a 64-character SHA-256 digest.")
        if not isinstance(roles_value, list) or not roles_value:
            raise RuntimeError("API key roles must be a non-empty array.")
        roles = frozenset(str(role).lower() for role in roles_value)
        allowed_roles = {
            "read", "write", "admin", "employee", "analyst", "soc_lead",
            "tenant_admin", "platform_admin", "service",
        }
        if not roles <= allowed_roles:
            raise RuntimeError(
                "API key roles may contain only read, write, admin, employee, analyst, "
                "soc_lead, tenant_admin, platform_admin, and service."
            )
        if "employee" in roles and roles & {
            "admin", "analyst", "soc_lead", "tenant_admin", "platform_admin", "service"
        }:
            raise RuntimeError(
                "Employee credentials cannot be combined with SOC, admin, or service roles."
            )
        subject_id = str(entry.get("subject_id", "")).strip() or None
        employee_email = str(entry.get("email", "")).strip().lower() or None
        if "employee" in roles:
            if not {"read", "write"} <= roles:
                raise RuntimeError("Employee credentials must include both read and write roles.")
            if not subject_id or len(subject_id) > 128:
                raise RuntimeError("Employee credentials require a configured subject_id.")
            if (
                not employee_email
                or len(employee_email) > 320
                or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", employee_email)
            ):
                raise RuntimeError("Employee credentials require a valid configured email.")
        if digest in seen_digests:
            raise RuntimeError("Duplicate API key digest configured.")
        seen_digests.add(digest)
        tenant_ids.add(tenant_id)
        parsed.append((digest, ApiPrincipal(tenant_id, roles, subject_id, employee_email)))

    # Until every persistent and file-backed store is tenant-scoped, fail closed
    # instead of presenting a multi-tenant configuration as isolated.
    if len(tenant_ids) > 1:
        raise RuntimeError(
            "Multiple tenants are not enabled yet: tenant isolation for all stores is incomplete."
        )
    return tuple(parsed)


def authenticate_api_key(token: str, entries=None) -> ApiPrincipal | None:
    if not token or len(token) > 512:
        return None
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for digest, principal in configured_api_keys() if entries is None else entries:
        if hmac.compare_digest(candidate, digest):
            return principal
    return None
