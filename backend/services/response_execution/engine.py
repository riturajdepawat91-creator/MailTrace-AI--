from __future__ import annotations

from typing import Any, Dict, List, Optional
import copy
import hashlib


ENGINE_NAME = "soc95-response-execution"
ENGINE_VERSION = "2.0"

VALID_OPERATIONS = {
    "APPROVE",
    "REJECT",
    "EXECUTE",
    "VERIFY",
    "ROLLBACK",
    "CLOSE",
}

VALID_STATES = {
    "PLANNED",
    "PENDING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "EXECUTING",
    "CONTAINED",
    "REMEDIATED",
    "RECOVERY",
    "VERIFIED",
    "ROLLBACK",
    "CLOSED",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _deterministic_id(prefix: str, *parts: Any) -> str:
    material = "|".join(_text(part) for part in parts)
    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _action_list(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = response.get("recommended_actions", [])
    if not isinstance(actions, list):
        return []

    return [
        item
        for item in actions
        if isinstance(item, dict)
    ]


def _normalize_action_ids(action_ids: Any) -> List[str]:
    if action_ids is None:
        return []

    if isinstance(action_ids, str):
        action_ids = [action_ids]

    if not isinstance(action_ids, (list, tuple, set)):
        return []

    values = {
        _text(item)
        for item in action_ids
        if _text(item)
    }

    return sorted(values)


def _selected_actions(
    response: Dict[str, Any],
    action_ids: List[str],
) -> List[Dict[str, Any]]:

    actions = _action_list(response)

    if not action_ids:
        return copy.deepcopy(actions)

    wanted = {
        value.lower()
        for value in action_ids
    }

    selected = []

    for action in actions:
        action_id = _text(
            action.get("action_id")
        )

        if action_id.lower() in wanted:
            selected.append(
                copy.deepcopy(action)
            )

    return selected


def _all_approved(actions: List[Dict[str, Any]]) -> bool:
    if not actions:
        return False

    return all(
        _text(
            action.get("approval_status")
        ).upper()
        == "APPROVED"
        for action in actions
    )


def _append_audit(
    audit: List[Dict[str, Any]],
    response_id: str,
    event_type: str,
    operation: str,
    actor: str,
    reason: str,
) -> None:

    audit.append(
        {
            "event_id": _deterministic_id(
                "AUD",
                response_id,
                operation,
                actor,
                reason,
            ),
            "event_type": event_type,
            "response_id": response_id,
            "operation": operation,
            "actor": actor,
            "reason": reason,
            "timestamp": None,
            "timestamp_status": "UNKNOWN",
            "source": ENGINE_NAME,
            "simulated": True,
        }
    )


def _append_lifecycle(
    lifecycle: List[Dict[str, Any]],
    response_id: str,
    from_state: Optional[str],
    to_state: str,
    operation: str,
) -> None:

    lifecycle.append(
        {
            "transition_id": _deterministic_id(
                "TRN",
                response_id,
                operation,
                from_state,
                to_state,
            ),
            "from": from_state,
            "to": to_state,
            "operation": operation,
            "timestamp": None,
            "timestamp_status": "UNKNOWN",
            "simulated": True,
        }
    )


def _transition_allowed(
    state: str,
    operation: str,
) -> bool:

    transitions = {
        "PLANNED": {
            "APPROVE",
            "REJECT",
        },
        "PENDING_APPROVAL": {
            "APPROVE",
            "REJECT",
        },
        "APPROVED": {
            "EXECUTE",
        },
        "EXECUTING": {
            "VERIFY",
            "ROLLBACK",
        },
        "CONTAINED": {
            "VERIFY",
            "ROLLBACK",
            "CLOSE",
        },
        "REMEDIATED": {
            "VERIFY",
            "ROLLBACK",
            "CLOSE",
        },
        "RECOVERY": {
            "VERIFY",
        },
        "VERIFIED": {
            "CLOSE",
            "ROLLBACK",
        },
        "ROLLBACK": {
            "VERIFY",
            "CLOSE",
        },
    }

    return operation in transitions.get(
        state,
        set(),
    )


def _base_failure(error: str) -> Dict[str, Any]:
    return {
        "success": False,
        "error": error,
        "engine": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "simulated": True,
        "persistence": False,
        "execution_side_effect": False,
    }


def _apply_approval(
    response: Dict[str, Any],
    operation: str,
    actor: str,
    reason: str,
    action_ids: List[str],
) -> Dict[str, Any]:

    current = _text(
        response.get("status")
    ).upper()

    if current == "PLANNED":
        effective_state = "PLANNED"
        transition_from = "PLANNED"
    elif current == "PENDING_APPROVAL":
        effective_state = "PENDING_APPROVAL"
        transition_from = "PENDING_APPROVAL"
    else:
        effective_state = current
        transition_from = current

    if not _transition_allowed(
        effective_state,
        operation,
    ):
        return _base_failure(
            f"Operation {operation} is not allowed from state {current}."
        )

    selected = _selected_actions(
        response,
        action_ids,
    )

    if action_ids and len(selected) != len(action_ids):
        return _base_failure(
            "One or more action_ids were not found."
        )

    if not selected:
        return _base_failure(
            "No response actions available."
        )

    new_response = copy.deepcopy(response)

    response_id = _text(
        new_response.get("response_id")
    )

    selected_ids = {
        _text(
            action.get("action_id")
        ).lower()
        for action in selected
    }

    if operation == "APPROVE":

        for item in new_response.get(
            "recommended_actions",
            [],
        ):

            item_id = _text(
                item.get("action_id")
            ).lower()

            if item_id in selected_ids:
                item["approval_status"] = "APPROVED"
                item["status"] = "APPROVED"

        all_approved = _all_approved(
            new_response.get(
                "recommended_actions",
                [],
            )
        )

        new_state = (
            "APPROVED"
            if all_approved
            else "PENDING_APPROVAL"
        )

        event = "RESPONSE_APPROVED"

        response_state = _safe_dict(
            new_response.get(
                "response_state"
            )
        )

        response_state["status"] = new_state
        response_state["approval_state"] = (
            "APPROVED"
            if all_approved
            else "PENDING"
        )

        new_response["response_state"] = response_state

        # CRITICAL FIX:
        # Keep top-level response status synchronized.
        new_response["status"] = new_state

        analyst_state = _safe_dict(
            new_response.get(
                "analyst_state"
            )
        )

        analyst_state["decision"] = (
            "APPROVED"
            if all_approved
            else "PARTIALLY_APPROVED"
        )
        analyst_state["approved_by"] = actor

        new_response["analyst_state"] = analyst_state

    else:

        for item in new_response.get(
            "recommended_actions",
            [],
        ):

            item["approval_status"] = "REJECTED"
            item["status"] = "REJECTED"

        new_state = "REJECTED"
        event = "RESPONSE_REJECTED"

        response_state = _safe_dict(
            new_response.get(
                "response_state"
            )
        )

        response_state["status"] = new_state
        response_state["approval_state"] = "REJECTED"

        new_response["response_state"] = response_state
        new_response["status"] = new_state

        analyst_state = _safe_dict(
            new_response.get(
                "analyst_state"
            )
        )

        analyst_state["decision"] = "REJECTED"
        analyst_state["rejected_by"] = actor

        new_response["analyst_state"] = analyst_state

    lifecycle = list(
        new_response.get(
            "lifecycle",
            [],
        )
    )

    _append_lifecycle(
        lifecycle,
        response_id,
        transition_from,
        new_state,
        operation,
    )

    new_response["lifecycle"] = lifecycle

    audit = list(
        new_response.get(
            "audit",
            [],
        )
    )

    _append_audit(
        audit,
        response_id,
        event,
        operation,
        actor,
        reason,
    )

    new_response["audit"] = audit

    return {
        "success": True,
        "response": new_response,
        "operation": operation,
        "simulated": True,
    }


def _apply_execute(
    response: Dict[str, Any],
    actor: str,
    reason: str,
    action_ids: List[str],
) -> Dict[str, Any]:

    state = _text(
        response.get("status")
    ).upper()

    if state != "APPROVED":
        return _base_failure(
            "EXECUTE requires response state APPROVED."
        )

    selected = _selected_actions(
        response,
        action_ids,
    )

    if not selected:
        return _base_failure(
            "No response actions available for execution."
        )

    if not _all_approved(selected):
        return _base_failure(
            "Every selected action must be approved before execution."
        )

    new_response = copy.deepcopy(response)

    response_id = _text(
        new_response.get("response_id")
    )

    selected_ids = {
        _text(
            action.get("action_id")
        ).lower()
        for action in selected
    }

    executed_count = 0

    for item in new_response.get(
        "recommended_actions",
        [],
    ):

        item_id = _text(
            item.get("action_id")
        ).lower()

        if item_id not in selected_ids:
            continue

        item["execution_status"] = "SIMULATED_EXECUTED"
        item["status"] = "EXECUTED"
        item["execution_side_effect"] = False

        executed_count += 1

    response_state = _safe_dict(
        new_response.get(
            "response_state"
        )
    )

    response_state["status"] = "EXECUTING"
    response_state["execution_state"] = "SIMULATED"

    new_response["response_state"] = response_state
    new_response["status"] = "EXECUTING"

    lifecycle = list(
        new_response.get(
            "lifecycle",
            [],
        )
    )

    _append_lifecycle(
        lifecycle,
        response_id,
        "APPROVED",
        "EXECUTING",
        "EXECUTE",
    )

    new_response["lifecycle"] = lifecycle

    audit = list(
        new_response.get(
            "audit",
            [],
        )
    )

    _append_audit(
        audit,
        response_id,
        "RESPONSE_EXECUTED_SIMULATED",
        "EXECUTE",
        actor,
        reason,
    )

    new_response["audit"] = audit

    return {
        "success": True,
        "response": new_response,
        "operation": "EXECUTE",
        "simulated": True,
        "executed_action_count": executed_count,
    }


def _apply_verify(
    response: Dict[str, Any],
    actor: str,
    reason: str,
) -> Dict[str, Any]:

    state = _text(
        response.get("status")
    ).upper()

    allowed_states = {
        "EXECUTING",
        "CONTAINED",
        "REMEDIATED",
        "RECOVERY",
        "ROLLBACK",
    }

    if state not in allowed_states:
        return _base_failure(
            "VERIFY requires an executing, containment, remediation, recovery, or rollback state."
        )

    new_response = copy.deepcopy(response)

    response_id = _text(
        new_response.get("response_id")
    )

    for item in new_response.get(
        "recommended_actions",
        [],
    ):

        item["verification_status"] = "SIMULATED_VERIFIED"

    response_state = _safe_dict(
        new_response.get(
            "response_state"
        )
    )

    response_state["status"] = "VERIFIED"
    response_state["verification"] = "VERIFIED"
    response_state["verification_state"] = "SIMULATED_VERIFIED"

    new_response["response_state"] = response_state
    new_response["status"] = "VERIFIED"

    lifecycle = list(
        new_response.get(
            "lifecycle",
            [],
        )
    )

    _append_lifecycle(
        lifecycle,
        response_id,
        state,
        "VERIFIED",
        "VERIFY",
    )

    new_response["lifecycle"] = lifecycle

    audit = list(
        new_response.get(
            "audit",
            [],
        )
    )

    _append_audit(
        audit,
        response_id,
        "RESPONSE_VERIFIED_SIMULATED",
        "VERIFY",
        actor,
        reason,
    )

    new_response["audit"] = audit

    return {
        "success": True,
        "response": new_response,
        "operation": "VERIFY",
        "simulated": True,
    }


def _apply_rollback(
    response: Dict[str, Any],
    actor: str,
    reason: str,
) -> Dict[str, Any]:

    state = _text(
        response.get("status")
    ).upper()

    allowed_states = {
        "EXECUTING",
        "CONTAINED",
        "REMEDIATED",
        "VERIFIED",
    }

    if state not in allowed_states:
        return _base_failure(
            "ROLLBACK is only allowed after execution or downstream response states."
        )

    new_response = copy.deepcopy(response)

    response_id = _text(
        new_response.get("response_id")
    )

    for item in new_response.get(
        "recommended_actions",
        [],
    ):

        if item.get(
            "reversible",
            False,
        ):

            item["execution_status"] = (
                "ROLLED_BACK_SIMULATED"
            )
            item["verification_status"] = (
                "NOT_VERIFIED"
            )
            item["status"] = "ROLLED_BACK"
            item["rollback_status"] = (
                "SIMULATED_ROLLED_BACK"
            )

        else:

            item["rollback_status"] = (
                "NOT_REVERSIBLE"
            )

    response_state = _safe_dict(
        new_response.get(
            "response_state"
        )
    )

    response_state["status"] = "ROLLBACK"
    response_state["rollback_state"] = "SIMULATED"

    new_response["response_state"] = response_state
    new_response["status"] = "ROLLBACK"

    lifecycle = list(
        new_response.get(
            "lifecycle",
            [],
        )
    )

    _append_lifecycle(
        lifecycle,
        response_id,
        state,
        "ROLLBACK",
        "ROLLBACK",
    )

    new_response["lifecycle"] = lifecycle

    audit = list(
        new_response.get(
            "audit",
            [],
        )
    )

    _append_audit(
        audit,
        response_id,
        "RESPONSE_ROLLBACK_SIMULATED",
        "ROLLBACK",
        actor,
        reason,
    )

    new_response["audit"] = audit

    return {
        "success": True,
        "response": new_response,
        "operation": "ROLLBACK",
        "simulated": True,
    }


def _apply_close(
    response: Dict[str, Any],
    actor: str,
    reason: str,
) -> Dict[str, Any]:

    state = _text(
        response.get("status")
    ).upper()

    if state not in {
        "CONTAINED",
        "REMEDIATED",
        "VERIFIED",
        "ROLLBACK",
    }:

        return _base_failure(
            "CLOSE requires a completed response state."
        )

    new_response = copy.deepcopy(response)

    response_id = _text(
        new_response.get("response_id")
    )

    response_state = _safe_dict(
        new_response.get(
            "response_state"
        )
    )

    response_state["status"] = "CLOSED"

    new_response["response_state"] = response_state
    new_response["status"] = "CLOSED"

    lifecycle = list(
        new_response.get(
            "lifecycle",
            [],
        )
    )

    _append_lifecycle(
        lifecycle,
        response_id,
        state,
        "CLOSED",
        "CLOSE",
    )

    new_response["lifecycle"] = lifecycle

    audit = list(
        new_response.get(
            "audit",
            [],
        )
    )

    _append_audit(
        audit,
        response_id,
        "RESPONSE_CLOSED",
        "CLOSE",
        actor,
        reason,
    )

    new_response["audit"] = audit

    return {
        "success": True,
        "response": new_response,
        "operation": "CLOSE",
        "simulated": True,
    }


def transition_response(
    response: Any,
    operation: str,
    actor: str = "",
    reason: str = "",
    action_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:

    source = (
        response
        if isinstance(response, dict)
        else {}
    )

    if not source:
        return _base_failure(
            "Response object is required."
        )

    operation = _text(
        operation
    ).upper()

    if operation not in VALID_OPERATIONS:
        return _base_failure(
            f"Unsupported operation: {operation}"
        )

    normalized_action_ids = _normalize_action_ids(
        action_ids
    )

    actor = (
        _text(actor)
        or "ANALYST"
    )

    reason = _text(reason)

    if operation in {
        "APPROVE",
        "REJECT",
    }:

        result = _apply_approval(
            source,
            operation,
            actor,
            reason,
            normalized_action_ids,
        )

    elif operation == "EXECUTE":

        result = _apply_execute(
            source,
            actor,
            reason,
            normalized_action_ids,
        )

    elif operation == "VERIFY":

        result = _apply_verify(
            source,
            actor,
            reason,
        )

    elif operation == "ROLLBACK":

        result = _apply_rollback(
            source,
            actor,
            reason,
        )

    elif operation == "CLOSE":

        result = _apply_close(
            source,
            actor,
            reason,
        )

    else:

        result = _base_failure(
            "Unsupported operation."
        )

    result["engine"] = ENGINE_NAME
    result["version"] = ENGINE_VERSION
    result["persistence"] = False
    result["simulated"] = True
    result["execution_side_effect"] = False

    return result