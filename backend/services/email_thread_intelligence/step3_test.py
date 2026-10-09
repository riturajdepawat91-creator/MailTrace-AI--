import json

from services.email_thread_intelligence import analyze_thread_to_dict


def run(name, messages):
    result = analyze_thread_to_dict(messages)

    print("")
    print("============================================================")
    print(name)
    print("============================================================")

    print(
        json.dumps(
            {
                "verdict": result["hijacking_assessment"]["verdict"],
                "severity": result["hijacking_assessment"]["severity"],
                "hijack_risk": result["hijacking_assessment"]["risk_score"],
                "signal_count": result["hijacking_assessment"]["signal_count"],
                "signals": result["hijacking_assessment"]["signals"],
                "continuity": result["continuity"],
                "anomalies": result["anomalies"],
                "evidence_ids": [
                    item["evidence_id"]
                    for item in result["evidence"]
                ],
            },
            indent=2,
        )
    )

    return result


# ------------------------------------------------------------
# CASE 1: Normal conversation — no hijack
# ------------------------------------------------------------

normal = run(
    "CASE 1 — NORMAL BUSINESS THREAD",
    [
        {
            "message_id": "<n1@example.com>",
            "subject": "Project status",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Can you send the latest project status?",
        },
        {
            "message_id": "<n2@example.com>",
            "in_reply_to": "<n1@example.com>",
            "references": "<n1@example.com>",
            "subject": "Re: Project status",
            "from": "bob@company.example",
            "to": "alice@company.example",
            "body": "> Can you send the latest project status?\nHere is the latest update.",
        },
        {
            "message_id": "<n3@example.com>",
            "in_reply_to": "<n2@example.com>",
            "references": "<n1@example.com> <n2@example.com>",
            "subject": "Re: Project status",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Thanks, received.",
        },
    ],
)

assert normal["hijacking_assessment"]["verdict"] == "NO_HIJACK_INDICATORS"
assert normal["hijacking_assessment"]["risk_score"] == 0.0


# ------------------------------------------------------------
# CASE 2: Normal participant escalation — should NOT be hijack
# ------------------------------------------------------------

escalation = run(
    "CASE 2 — NORMAL PARTICIPANT ESCALATION",
    [
        {
            "message_id": "<e1@company.example>",
            "subject": "Project approval",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Please review the project.",
        },
        {
            "message_id": "<e2@company.example>",
            "in_reply_to": "<e1@company.example>",
            "references": "<e1@company.example>",
            "subject": "Re: Project approval",
            "from": "bob@company.example",
            "to": "alice@company.example, cfo@company.example",
            "body": "> Please review the project.\nI am adding our CFO for visibility.",
        },
        {
            "message_id": "<e3@company.example>",
            "in_reply_to": "<e2@company.example>",
            "references": "<e1@company.example> <e2@company.example>",
            "subject": "Re: Project approval",
            "from": "cfo@company.example",
            "to": "alice@company.example, bob@company.example",
            "body": "Approved.",
        },
    ],
)

assert escalation["hijacking_assessment"]["verdict"] != "POTENTIAL_CONVERSATION_HIJACK"


# ------------------------------------------------------------
# CASE 3: External participant + payment context shift
# ------------------------------------------------------------

payment_hijack = run(
    "CASE 3 — EXTERNAL PARTICIPANT + PAYMENT CONTEXT SHIFT",
    [
        {
            "message_id": "<p1@company.example>",
            "subject": "Invoice 8821",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Please review invoice 8821.",
        },
        {
            "message_id": "<p2@company.example>",
            "in_reply_to": "<p1@company.example>",
            "references": "<p1@company.example>",
            "subject": "Re: Invoice 8821",
            "from": "bob@company.example",
            "to": "alice@company.example",
            "body": "> Please review invoice 8821.\nI will check it.",
        },
        {
            "message_id": "<p3@evil.example>",
            "in_reply_to": "<p2@company.example>",
            "references": "<p1@company.example> <p2@company.example>",
            "subject": "Re: Invoice 8821",
            "from": "attacker@evil.example",
            "to": "alice@company.example",
            "body": "The bank account changed. Please send the invoice payment to the new bank account immediately.",
        },
    ],
)

assert payment_hijack["hijacking_assessment"]["verdict"] == "POTENTIAL_CONVERSATION_HIJACK"
assert payment_hijack["hijacking_assessment"]["risk_score"] >= 55.0
assert payment_hijack["continuity"]["external_boundary_changes"] >= 1
assert payment_hijack["continuity"]["context_shift_count"] >= 1


# ------------------------------------------------------------
# CASE 4: Credential context shift by a late sender
# ------------------------------------------------------------

credential_hijack = run(
    "CASE 4 — LATE CREDENTIAL REQUEST",
    [
        {
            "message_id": "<c1@company.example>",
            "subject": "Account support",
            "from": "alice@company.example",
            "to": "helpdesk@company.example",
            "body": "My account is working normally.",
        },
        {
            "message_id": "<c2@company.example>",
            "in_reply_to": "<c1@company.example>",
            "references": "<c1@company.example>",
            "subject": "Re: Account support",
            "from": "helpdesk@company.example",
            "to": "alice@company.example",
            "body": "> My account is working normally.\nWe are reviewing the issue.",
        },
        {
            "message_id": "<c3@external.example>",
            "in_reply_to": "<c2@company.example>",
            "references": "<c1@company.example> <c2@company.example>",
            "subject": "Re: Account support",
            "from": "support@external.example",
            "to": "alice@company.example",
            "body": "Please provide your password and verification code immediately so we can restore access.",
        },
    ],
)

assert credential_hijack["hijacking_assessment"]["verdict"] == "POTENTIAL_CONVERSATION_HIJACK"
assert credential_hijack["continuity"]["context_shift_count"] >= 1


# ------------------------------------------------------------
# CASE 5: Quoted context + high-risk new content
# ------------------------------------------------------------

quoted_shift = run(
    "CASE 5 — QUOTED CONTEXT / NEW HIGH-RISK CONTENT",
    [
        {
            "message_id": "<q1@company.example>",
            "subject": "Vendor discussion",
            "from": "alice@company.example",
            "to": "bob@company.example",
            "body": "Please confirm the vendor details.",
        },
        {
            "message_id": "<q2@external.example>",
            "in_reply_to": "<q1@company.example>",
            "references": "<q1@company.example>",
            "subject": "Re: Vendor discussion",
            "from": "vendor@external.example",
            "to": "alice@company.example",
            "body": "> Please confirm the vendor details.\n> We are checking this.\n> Thanks.\nPlease send the bank transfer immediately to the new account.",
        },
    ],
)

assert quoted_shift["hijacking_assessment"]["signal_count"] >= 1
assert quoted_shift["continuity"]["context_shift_count"] >= 1


# ------------------------------------------------------------
# CASE 6: Hostile/bounded inputs
# ------------------------------------------------------------

hostile = analyze_thread_to_dict(
    None
)

assert hostile["thread_depth"] == 0
assert hostile["static_only"] is True
assert isinstance(hostile["hijacking_assessment"], dict)

huge = analyze_thread_to_dict(
    [
        {
            "message_id": "<huge@example.com>",
            "subject": "A" * 5000000,
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "x" * 5000000,
        }
    ]
)

assert huge["thread_depth"] == 1
assert huge["static_only"] is True


# ------------------------------------------------------------
# Determinism
# ------------------------------------------------------------

first = analyze_thread_to_dict(
    [
        {
            "message_id": "<d1@example.com>",
            "subject": "Normal",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "Hello.",
        },
        {
            "message_id": "<d2@example.com>",
            "in_reply_to": "<d1@example.com>",
            "references": "<d1@example.com>",
            "subject": "Re: Normal",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Hello back.",
        },
    ]
)

second = analyze_thread_to_dict(
    [
        {
            "message_id": "<d1@example.com>",
            "subject": "Normal",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "Hello.",
        },
        {
            "message_id": "<d2@example.com>",
            "in_reply_to": "<d1@example.com>",
            "references": "<d1@example.com>",
            "subject": "Re: Normal",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Hello back.",
        },
    ]
)

assert first == second

print("")
print("============================================================")
print("THREAD STEP 3 SOC-ORIENTED TESTS: PASS")
print("============================================================")
