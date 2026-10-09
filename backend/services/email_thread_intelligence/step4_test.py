import json

from services.email_thread_intelligence import (
    analyze_thread_to_dict,
)


def run_case(name, messages):
    result = analyze_thread_to_dict(messages)

    print("")
    print("=" * 60)
    print(name)
    print("=" * 60)

    print(json.dumps({
        "verdict": result["hijacking_assessment"]["verdict"],
        "hijacking_risk": result["hijacking_assessment"]["risk_score"],
        "calibrated_risk": result["risk_breakdown"]["calibrated_risk_score"],
        "structural_risk": result["risk_breakdown"]["structural_risk"],
        "contextual_risk": result["risk_breakdown"]["contextual_risk"],
        "correlation_bonus": result["risk_breakdown"]["correlation_bonus"],
        "evidence_count": result["risk_breakdown"]["evidence_count"],
        "priority": result["analyst_summary"]["priority"],
    }, indent=2))

    return result


# ============================================================
# CASE 1 — CLEAN
# ============================================================

clean = run_case(
    "CASE 1 — CLEAN THREAD",
    [
        {
            "message_id": "<a@company.example>",
            "subject": "Project update",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Here is the project update.",
        },
        {
            "message_id": "<b@company.example>",
            "in_reply_to": "<a@company.example>",
            "references": "<a@company.example>",
            "subject": "Re: Project update",
            "from": "bob@company.example",
            "to": "alice@company.example",
            "body": "Thanks, received.",
        },
    ],
)

assert clean["hijacking_assessment"]["verdict"] == \
    "NO_HIJACK_INDICATORS"

assert clean["risk_breakdown"]["calibrated_risk_score"] == 0.0

assert clean["analyst_summary"]["priority"] == \
    "NO_ACTION"


# ============================================================
# CASE 2 — CORRELATED HIJACK
# ============================================================

hijack = run_case(
    "CASE 2 — CORRELATED HIJACK",
    [
        {
            "message_id": "<p1@company.example>",
            "subject": "Invoice review",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Please review invoice 9001.",
        },
        {
            "message_id": "<p2@company.example>",
            "in_reply_to": "<p1@company.example>",
            "references": "<p1@company.example>",
            "subject": "Re: Invoice review",
            "from": "bob@company.example",
            "to": "alice@company.example",
            "body": "> Please review invoice 9001.\nI am checking it.",
        },
        {
            "message_id": "<p3@evil.example>",
            "in_reply_to": "<p2@company.example>",
            "references": "<p1@company.example> <p2@company.example>",
            "subject": "Re: Invoice review",
            "from": "attacker@evil.example",
            "to": "alice@company.example",
            "body": (
                "The bank account changed. "
                "Please send the invoice payment immediately "
                "to the new account."
            ),
        },
    ],
)

assert hijack["hijacking_assessment"]["verdict"] == \
    "POTENTIAL_CONVERSATION_HIJACK"

assert hijack["risk_breakdown"]["signal_weight_total"] > 0

assert hijack["risk_breakdown"]["correlation_bonus"] > 0

assert hijack["risk_breakdown"]["calibrated_risk_score"] >= 70

assert hijack["analyst_summary"]["priority"] == \
    "IMMEDIATE_REVIEW"

assert len(
    hijack["analyst_summary"]["verification_steps"]
) >= 2


# ============================================================
# CASE 3 — STRUCTURAL DUPLICATE MESSAGE-ID
# ============================================================

structural = run_case(
    "CASE 3 — STRUCTURAL ANOMALY",
    [
        {
            "message_id": "<x1@example.com>",
            "subject": "Case",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "Start.",
        },
        {
            "message_id": "<x1@example.com>",
            "in_reply_to": "<x1@example.com>",
            "subject": "Re: Case",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Duplicate identity.",
        },
    ],
)

assert structural["risk_breakdown"]["evidence_count"] >= 1

assert structural["risk_breakdown"]["anomaly_weight_total"] >= 35.0

assert structural["risk_breakdown"]["calibrated_risk_score"] >= 35.0

assert structural["analyst_summary"]["priority"] in (
    "REVIEW",
    "HIGH_PRIORITY",
)


# ============================================================
# CASE 4 — GRAPH CYCLE
# ============================================================

cycle = run_case(
    "CASE 4 — GRAPH CYCLE",
    [
        {
            "message_id": "<a@example.com>",
            "in_reply_to": "<b@example.com>",
            "references": "<b@example.com>",
            "subject": "Cycle",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "Cycle A.",
        },
        {
            "message_id": "<b@example.com>",
            "in_reply_to": "<a@example.com>",
            "references": "<a@example.com>",
            "subject": "Re: Cycle",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Cycle B.",
        },
    ],
)

assert cycle["risk_breakdown"]["evidence_count"] >= 1

assert cycle["risk_breakdown"]["anomaly_weight_total"] >= 35.0

assert cycle["risk_breakdown"]["calibrated_risk_score"] >= 35.0


# ============================================================
# CASE 5 — HOSTILE / EMPTY INPUT
# ============================================================

hostile = run_case(
    "CASE 5 — HOSTILE INPUT",
    None,
)

assert hostile["thread_depth"] == 0

assert hostile["static_only"] is True

assert hostile["risk_breakdown"]["calibrated_risk_score"] == 0.0


# ============================================================
# CASE 6 — DETERMINISM
# ============================================================

again_a = analyze_thread_to_dict(
    [
        {
            "message_id": "<d1@example.com>",
            "subject": "Payment",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Review this payment.",
        },
        {
            "message_id": "<d2@evil.example>",
            "in_reply_to": "<d1@example.com>",
            "references": "<d1@example.com>",
            "subject": "Re: Payment",
            "from": "attacker@evil.example",
            "to": "alice@company.example",
            "body": "The bank account changed. Pay immediately.",
        },
    ]
)

again_b = analyze_thread_to_dict(
    [
        {
            "message_id": "<d1@example.com>",
            "subject": "Payment",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Review this payment.",
        },
        {
            "message_id": "<d2@evil.example>",
            "in_reply_to": "<d1@example.com>",
            "references": "<d1@example.com>",
            "subject": "Re: Payment",
            "from": "attacker@evil.example",
            "to": "alice@company.example",
            "body": "The bank account changed. Pay immediately.",
        },
    ]
)

assert again_a == again_b

print("")
print("=" * 60)
print("THREAD STEP 4 SOC-ORIENTED TESTS: PASS")
print("=" * 60)
