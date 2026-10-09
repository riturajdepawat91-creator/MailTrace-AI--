import sys

from services.email_ai.features import (
    reconstruct_attack_chain,
)


PASS = 0
FAIL = 0


def check(
    name,
    condition,
    result=None,
):

    global PASS
    global FAIL

    if condition:

        PASS += 1

        print(
            f"[PASS] {name}"
        )

    else:

        FAIL += 1

        print(
            f"[FAIL] {name}"
        )

        if result is not None:

            print(result)


print("=" * 78)

print(
    "MAILTRACE AI - ATTACK CHAIN ADVERSARIAL AUDIT"
)

print("=" * 78)


# ==========================================================
# CASE 1
# Legitimate email
# ==========================================================

email = {
    "sender": "newsletter@example.com",
    "reply_to": "",
    "subject": "Monthly Newsletter",
    "body": "Here are this month's updates.",
    "urls": [],
    "attachments": [],
}

result = reconstruct_attack_chain(email)

check(
    "legitimate email does not detect attack chain",
    result["attack_detected"] is False,
    result,
)

check(
    "legitimate email has zero stages",
    result["stage_count"] == 0,
    result,
)

check(
    "legitimate email has no attack chain status",
    result["chain_status"] == "NO_ATTACK_CHAIN",
    result,
)


# ==========================================================
# CASE 2
# Empty input
# ==========================================================

result = reconstruct_attack_chain({})

check(
    "empty input does not crash",
    isinstance(result, dict),
    result,
)

check(
    "empty input has zero stages",
    result["stage_count"] == 0,
    result,
)


# ==========================================================
# CASE 3
# Credential phishing
# ==========================================================

email = {
    "sender": "security@micros0ft.xyz",
    "subject": "Verify Your Password",
    "body": (
        "Your account will be suspended. "
        "Verify your password immediately."
    ),
    "urls": [
        "http://evil.example/login"
    ],
}

result = reconstruct_attack_chain(email)

stage_ids = [
    stage["id"]
    for stage in result["stages"]
]

check(
    "credential phishing detects attack",
    result["attack_detected"] is True,
    result,
)

check(
    "credential phishing detects initial access",
    "initial_access" in stage_ids,
    result,
)

check(
    "credential phishing detects credential access",
    "credential_access" in stage_ids,
    result,
)


# ==========================================================
# CASE 4
# Malicious attachment
# ==========================================================

email = {
    "sender": "invoice@unknown.xyz",
    "subject": "Invoice Attached",
    "body": "Please review attached invoice.",
    "attachments": [
        "invoice.pdf.exe"
    ],
}

result = reconstruct_attack_chain(email)

stage_ids = [
    stage["id"]
    for stage in result["stages"]
]

check(
    "malicious attachment detects initial access",
    "initial_access" in stage_ids,
    result,
)

check(
    "malicious attachment detects execution",
    "execution" in stage_ids,
    result,
)


# ==========================================================
# CASE 5
# Full multi-stage attack
# ==========================================================

email = {
    "sender": (
        "Microsoft Security "
        "<security@micros0ft.xyz>"
    ),

    "reply_to": "attacker@gmail.com",

    "subject": (
        "URGENT SECURITY ALERT!!!"
    ),

    "body": (
        "Your account will be suspended. "
        "Verify your password immediately."
    ),

    "urls": [
        "http://192.168.1.10/login",
        "http://xn--secure-9db.example.xyz/login",
    ],

    "attachments": [
        "invoice.pdf.exe",
        "payment.xlsm",
    ],
}

result = reconstruct_attack_chain(email)

check(
    "full attack detects attack chain",
    result["attack_detected"] is True,
    result,
)

check(
    "full attack is multi-stage",
    result["chain_status"] == "MULTI_STAGE",
    result,
)

check(
    "full attack detects multiple stages",
    result["stage_count"] >= 3,
    result,
)

check(
    "full attack has high completeness",
    result["chain_completeness_score"] >= 60,
    result,
)


# ==========================================================
# CASE 6
# Stage ordering
# ==========================================================

orders = [
    stage["order"]
    for stage in result["stages"]
]

check(
    "attack stages are correctly ordered",
    orders == sorted(orders),
    result,
)


# ==========================================================
# CASE 7
# Duplicate stage prevention
# ==========================================================

stage_ids = [
    stage["id"]
    for stage in result["stages"]
]

check(
    "attack chain has no duplicate stages",
    len(stage_ids) == len(set(stage_ids)),
    result,
)


# ==========================================================
# CASE 8
# Confidence validation
# ==========================================================

confidences = [

    stage["confidence"]

    for stage in result["stages"]

]

check(
    "all stage confidence values are valid",

    all(

        isinstance(
            confidence,
            (int, float)
        )

        and 0 <= confidence <= 100

        for confidence
        in confidences

    ),

    result,
)


# ==========================================================
# CASE 9
# Completeness score validation
# ==========================================================

score = result[
    "chain_completeness_score"
]

check(
    "completeness score is valid",

    isinstance(
        score,
        (int, float)
    )

    and 0 <= score <= 100,

    result,
)


# ==========================================================
# CASE 10
# Objective inference
# ==========================================================

check(
    "credential attack infers meaningful objective",

    result[
        "likely_objective"
    ]

    != "No Clear Attack Objective",

    result,
)


# ==========================================================
# CASE 11
# Malformed fields
# ==========================================================

email = {

    "sender": None,

    "reply_to": 123,

    "subject": None,

    "body": None,

    "urls": "not-a-list",

    "attachments": None,

}

try:

    result = reconstruct_attack_chain(email)

    check(
        "malformed fields do not crash",

        isinstance(
            result,
            dict
        ),

        result,
    )

except Exception as exc:

    check(
        "malformed fields do not crash",

        False,

        {
            "error": repr(exc)
        },
    )


# ==========================================================
# CASE 12
# Invalid top-level input
# ==========================================================

try:

    result = reconstruct_attack_chain(
        "invalid-input"
    )

    check(
        "invalid top-level input handled safely",

        isinstance(
            result,
            dict
        ),

        result,
    )

except Exception as exc:

    check(
        "invalid top-level input handled safely",

        False,

        {
            "error": repr(exc)
        },
    )


# ==========================================================
# CASE 13
# Result schema validation
# ==========================================================

required_fields = {

    "attack_detected",

    "chain_status",

    "stages",

    "stage_count",

    "primary_attack_path",

    "chain_completeness_score",

    "likely_objective",

    "attack_sophistication",

    "mitre_technique_count",

}

check(
    "result contains complete schema",

    required_fields.issubset(
        set(result.keys())
    ),

    result,
)


# ==========================================================
# RESULT
# ==========================================================

print()

print("=" * 78)

print(
    f"ATTACK_CHAIN_AUDIT_RESULT: "
    f"{PASS} PASS / {FAIL} FAIL"
)

print("=" * 78)


if FAIL > 0:

    sys.exit(1)


sys.exit(0)
