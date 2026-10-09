from __future__ import annotations

from typing import Any, Dict, List
import copy
import hashlib
import json


ENGINE_NAME = "soc95-response-verification"
ENGINE_VERSION = "1.0"

VERIFICATION_STATUSES = {
    "NOT_READY",
    "PARTIAL",
    "VERIFIED",
    "FAILED",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _clamp(
    value: Any,
    low: float = 0.0,
    high: float = 100.0,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = low

    return max(
        low,
        min(
            high,
            number,
        ),
    )


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0

    return max(
        0.0,
        min(
            1.0,
            number,
        ),
    )


def _safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _safe_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _clean_values(value: Any) -> List[str]:
    values = value

    if isinstance(values, str):
        values = [values]

    if not isinstance(
        values,
        (list, tuple, set),
    ):
        return []

    result = []

    for item in values:
        text = _text(item)

        if text and text not in result:
            result.append(text)

    return sorted(
        result,
        key=lambda value: value.lower(),
    )


def _deterministic_id(
    prefix: str,
    *parts: Any,
) -> str:

    encoded_parts = []

    for part in parts:

        if isinstance(
            part,
            (dict, list, tuple, set),
        ):

            if isinstance(
                part,
                set,
            ):
                part = sorted(
                    _clean_values(part)
                )

            encoded_parts.append(
                json.dumps(
                    part,
                    sort_keys=True,
                    default=str,
                )
            )

        else:
            encoded_parts.append(
                _text(part)
            )

    material = "|".join(
        encoded_parts
    )

    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"{prefix}-{digest}"


def _action_list(
    response: Dict[str, Any],
) -> List[Dict[str, Any]]:

    actions = response.get(
        "recommended_actions",
        [],
    )

    if not isinstance(
        actions,
        list,
    ):
        return []

    return [
        item
        for item in actions
        if isinstance(item, dict)
    ]


def _normalize_observations(
    verification_context: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:

    raw = verification_context.get(
        "action_results",
        [],
    )

    results = {}

    if isinstance(
        raw,
        dict,
    ):

        iterable = []

        for action_id, value in raw.items():

            if isinstance(
                value,
                dict,
            ):

                item = copy.deepcopy(value)

            else:

                item = {
                    "success": bool(value)
                }

            item["action_id"] = action_id
            iterable.append(item)

    elif isinstance(
        raw,
        list,
    ):

        iterable = [
            item
            for item in raw
            if isinstance(item, dict)
        ]

    else:

        iterable = []

    for item in iterable:

        action_id = _text(
            item.get("action_id")
        )

        if not action_id:
            continue

        results[
            action_id.lower()
        ] = copy.deepcopy(item)

    return results


def _normalize_ioc_observations(
    verification_context: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:

    raw = verification_context.get(
        "ioc_observations",
        [],
    )

    results = {}

    if isinstance(
        raw,
        dict,
    ):

        iterable = []

        for ioc, value in raw.items():

            if isinstance(
                value,
                dict,
            ):

                item = copy.deepcopy(value)

            else:

                item = {
                    "status": value
                }

            item["ioc"] = ioc
            iterable.append(item)

    elif isinstance(
        raw,
        list,
    ):

        iterable = [
            item
            for item in raw
            if isinstance(item, dict)
        ]

    else:

        iterable = []

    for item in iterable:

        ioc = _text(
            item.get("ioc")
        )

        if not ioc:
            continue

        results[
            ioc.lower()
        ] = copy.deepcopy(item)

    return results


def _build_check(
    check_id: str,
    title: str,
    passed: bool,
    severity: str,
    evidence: str = "",
) -> Dict[str, Any]:

    return {
        "check_id": check_id,
        "title": title,
        "passed": bool(passed),
        "severity": severity,
        "evidence": evidence,
    }


def _verification_status(
    checks: List[Dict[str, Any]],
    has_action_observations: bool,
    has_ioc_observations: bool,
    response_state: str,
) -> str:

    if not checks:
        return "NOT_READY"

    failed = [
        item
        for item in checks
        if not item.get("passed")
    ]

    if failed:
        critical_failure = any(
            _upper(
                item.get("severity")
            )
            == "CRITICAL"
            for item in failed
        )

        if critical_failure:
            return "FAILED"

    if (
        response_state == "VERIFIED"
        and has_action_observations
    ):
        if not failed:
            return "VERIFIED"

    if (
        response_state in {
            "EXECUTING",
            "CONTAINED",
            "REMEDIATED",
            "RECOVERY",
            "VERIFIED",
        }
        and (
            has_action_observations
            or has_ioc_observations
        )
    ):
        return "PARTIAL"

    return "NOT_READY"


def _risk_from_state(
    verification_status: str,
    residual_ioc_count: int,
    unknown_ioc_count: int,
    incomplete_actions: int,
) -> float:

    if verification_status == "VERIFIED":
        risk = 10.0
    elif verification_status == "PARTIAL":
        risk = 45.0
    elif verification_status == "FAILED":
        risk = 85.0
    else:
        risk = 65.0

    risk += (
        residual_ioc_count
        * 10.0
    )

    risk += (
        unknown_ioc_count
        * 6.0
    )

    risk += (
        incomplete_actions
        * 8.0
    )

    return _clamp(
        risk,
        0.0,
        100.0,
    )


def _score_checks(
    checks: List[Dict[str, Any]],
) -> float:

    if not checks:
        return 0.0

    passed = sum(
        1
        for item in checks
        if item.get("passed")
    )

    return _clamp(
        (
            passed
            / len(checks)
        )
        * 100.0
    )


def verify_response(
    response: Any,
    verification_context: Any = None,
) -> Dict[str, Any]:

    if not isinstance(
        response,
        dict,
    ):

        return {
            "engine": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "success": False,
            "error": "Response object is required.",
            "verification_status": "NOT_READY",
            "simulated": True,
            "persistence": False,
            "execution_side_effect": False,
        }

    source = copy.deepcopy(
        response
    )

    context = (
        copy.deepcopy(
            verification_context
        )
        if isinstance(
            verification_context,
            dict,
        )
        else {}
    )

    response_id = _text(
        source.get(
            "response_id"
        )
    )

    response_state = _upper(
        source.get(
            "status"
        )
    )

    actions = _action_list(
        source
    )

    action_observations = (
        _normalize_observations(
            context
        )
    )

    ioc_observations = (
        _normalize_ioc_observations(
            context
        )
    )

    checks = []

    # --------------------------------------------------------
    # Response state check
    # --------------------------------------------------------

    checks.append(
        _build_check(
            "RESPONSE_STATE",
            "Response reached a verification-capable state",
            response_state in {
                "EXECUTING",
                "CONTAINED",
                "REMEDIATED",
                "RECOVERY",
                "VERIFIED",
                "ROLLBACK",
            },
            "HIGH",
            (
                f"Current response state: "
                f"{response_state or 'UNKNOWN'}"
            ),
        )
    )

    # --------------------------------------------------------
    # Action verification
    # --------------------------------------------------------

    action_records = []

    incomplete_actions = 0

    for action in actions:

        action_id = _text(
            action.get(
                "action_id"
            )
        )

        observation = (
            action_observations.get(
                action_id.lower()
            )
        )

        execution_status = _upper(
            action.get(
                "execution_status"
            )
        )

        action_status = _upper(
            action.get(
                "status"
            )
        )

        observed_success = None

        if observation is not None:

            if (
                "success"
                in observation
            ):

                observed_success = bool(
                    observation.get(
                        "success"
                    )
                )

            else:

                observed_status = _upper(
                    observation.get(
                        "status"
                    )
                )

                observed_success = (
                    observed_status
                    in {
                        "SUCCESS",
                        "COMPLETED",
                        "VERIFIED",
                        "CONTAINED",
                        "REMEDIATED",
                    }
                )

        simulated_complete = (
            execution_status
            == "SIMULATED_EXECUTED"
            or action_status
            == "EXECUTED"
        )

        verified_action = (
            observed_success is True
            or (
                simulated_complete
                and _upper(
                    action.get(
                        "verification_status"
                    )
                )
                == "SIMULATED_VERIFIED"
                and bool(
                    context.get(
                        "allow_simulated_verification",
                        False,
                    )
                )
            )
        )

        if not verified_action:
            incomplete_actions += 1

        action_records.append(
            {
                "action_id": action_id,
                "action_type": _text(
                    action.get(
                        "action_type"
                    )
                ),
                "execution_status": execution_status,
                "verification_status": _upper(
                    action.get(
                        "verification_status"
                    )
                ),
                "observed": (
                    observation is not None
                ),
                "observed_success": (
                    observed_success
                ),
                "verified": verified_action,
                "evidence": (
                    _text(
                        observation.get(
                            "evidence"
                        )
                    )
                    if observation
                    else ""
                ),
            }
        )

    checks.append(
        _build_check(
            "ACTION_OBSERVATIONS",
            "Response actions have explicit verification evidence",
            len(actions) > 0
            and len(action_observations)
            >= len(actions),
            "HIGH",
            (
                f"Actions={len(actions)}, "
                f"observations={len(action_observations)}"
            ),
        )
    )

    checks.append(
        _build_check(
            "ACTION_COMPLETION",
            incomplete_actions == 0
            and len(actions) > 0,
            "CRITICAL",
            (
                f"Incomplete or unverified "
                f"actions: {incomplete_actions}"
            ),
        )
    )

    # --------------------------------------------------------
    # IOC verification
    # --------------------------------------------------------

    response_iocs = _clean_values(
        source.get(
            "iocs",
            [],
        )
    )

    residual_iocs = []
    unknown_iocs = []
    verified_iocs = []

    for ioc in response_iocs:

        observation = (
            ioc_observations.get(
                ioc.lower()
            )
        )

        if observation is None:

            unknown_iocs.append(ioc)
            continue

        status = _upper(
            observation.get(
                "status"
            )
        )

        if status in {
            "ACTIVE",
            "MALICIOUS",
            "DETECTED",
            "PRESENT",
        }:

            residual_iocs.append(ioc)

        elif status in {
            "INACTIVE",
            "BLOCKED",
            "CLEAN",
            "REMOVED",
            "NOT_PRESENT",
        }:

            verified_iocs.append(ioc)

        else:

            unknown_iocs.append(ioc)

    if response_iocs:

        checks.append(
            _build_check(
                "IOC_OBSERVATIONS",
                "Response IOCs have post-response observations",
                len(
                    ioc_observations
                ) >= len(
                    response_iocs
                ),
                "HIGH",
                (
                    f"IOCs={len(response_iocs)}, "
                    f"observations={len(ioc_observations)}"
                ),
            )
        )

        checks.append(
            _build_check(
                "IOC_RESIDUAL_THREAT",
                "No verified active/malicious IOC remains",
                len(
                    residual_iocs
                ) == 0,
                "CRITICAL",
                (
                    f"Residual IOCs: "
                    f"{len(residual_iocs)}"
                ),
            )
        )

    else:

        checks.append(
            _build_check(
                "IOC_SCOPE",
                "No response IOCs require verification",
                True,
                "INFO",
                "No IOCs were attached to the response.",
            )
        )

    # --------------------------------------------------------
    # Simulation guard
    # --------------------------------------------------------

    checks.append(
        _build_check(
            "NO_SIDE_EFFECT",
            all(
                item.get(
                    "execution_side_effect"
                )
                is False
                for item in actions
                if "execution_side_effect"
                in item
            ),
            "CRITICAL",
            "Verification engine does not execute response actions.",
        )
    )

    # --------------------------------------------------------
    # Evidence requirement
    # --------------------------------------------------------

    evidence_count = sum(
        1
        for item in action_records
        if _text(
            item.get(
                "evidence"
            )
        )
    )

    evidence_count += sum(
        1
        for item in ioc_observations.values()
        if _text(
            item.get(
                "evidence"
            )
        )
    )

    checks.append(
        _build_check(
            "VERIFICATION_EVIDENCE",
            "Verification contains explicit evidence",
            evidence_count > 0,
            "HIGH",
            (
                f"Evidence records: "
                f"{evidence_count}"
            ),
        )
    )

    verification_status = _verification_status(
        checks=checks,
        has_action_observations=(
            len(action_observations) > 0
        ),
        has_ioc_observations=(
            len(ioc_observations) > 0
        ),
        response_state=response_state,
    )

    check_score = _score_checks(
        checks
    )

    residual_risk = _risk_from_state(
        verification_status=verification_status,
        residual_ioc_count=len(
            residual_iocs
        ),
        unknown_ioc_count=len(
            unknown_iocs
        ),
        incomplete_actions=incomplete_actions,
    )

    if verification_status == "VERIFIED":

        confidence = _confidence(
            (
                check_score / 100.0
            )
            * 0.85
            + (
                min(
                    evidence_count,
                    10,
                )
                / 10.0
            )
            * 0.15
        )

    elif verification_status == "PARTIAL":

        confidence = _confidence(
            (
                check_score / 100.0
            )
            * 0.65
        )

    elif verification_status == "FAILED":

        confidence = _confidence(
            0.80
            + (
                1.0
                - check_score / 100.0
            )
            * 0.15
        )

    else:

        confidence = _confidence(
            0.20
            + (
                check_score / 100.0
            )
            * 0.30
        )

    close_recommended = (
        verification_status
        == "VERIFIED"
        and residual_risk
        <= 20.0
        and incomplete_actions
        == 0
        and len(
            residual_iocs
        )
        == 0
        and evidence_count
        > 0
    )

    if verification_status == "VERIFIED":
        recommendation = (
            "CLOSE_RECOMMENDED"
            if close_recommended
            else "HOLD_FOR_ADDITIONAL_VALIDATION"
        )
    elif verification_status == "FAILED":
        recommendation = (
            "DO_NOT_CLOSE"
        )
    elif verification_status == "PARTIAL":
        recommendation = (
            "HOLD_FOR_ADDITIONAL_VALIDATION"
        )
    else:
        recommendation = (
            "VERIFICATION_REQUIRED"
        )

    verification_id = _deterministic_id(
        "VER",
        response_id,
        verification_status,
        action_records,
        residual_iocs,
        unknown_iocs,
        context,
    )

    return {
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "success": True,
        "verification_id": verification_id,
        "response_id": response_id,
        "response_status": response_state,
        "verification_status": verification_status,
        "verification_score": round(
            check_score,
            4,
        ),
        "confidence": round(
            confidence,
            6,
        ),
        "residual_risk": round(
            residual_risk,
            4,
        ),
        "close_recommended": close_recommended,
        "recommendation": recommendation,
        "checks": checks,
        "check_count": len(checks),
        "passed_check_count": sum(
            1
            for item in checks
            if item.get("passed")
        ),
        "action_results": action_records,
        "action_count": len(actions),
        "verified_action_count": sum(
            1
            for item in action_records
            if item.get("verified")
        ),
        "incomplete_action_count": incomplete_actions,
        "ioc_results": {
            "verified_inactive": sorted(
                verified_iocs
            ),
            "residual_active": sorted(
                residual_iocs
            ),
            "unknown": sorted(
                unknown_iocs
            ),
        },
        "evidence_count": evidence_count,
        "simulated": True,
        "persistence": False,
        "execution_side_effect": False,
        "capabilities": {
            "post_response_validation": True,
            "action_verification": True,
            "ioc_verification": True,
            "residual_risk_assessment": True,
            "close_recommendation": True,
            "evidence_tracking": True,
            "real_world_execution": False,
            "persistence": False,
        },
    }