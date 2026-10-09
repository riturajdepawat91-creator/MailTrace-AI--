import sys

from services.email_ai.features import analyze_mitre_attack


PASS = 0
FAIL = 0


def check(name, condition, result=None):

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
    "MAILTRACE AI - MITRE ATT&CK ADVERSARIAL AUDIT"
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

result = analyze_mitre_attack(email)

check(
    "legitimate email does not trigger MITRE detection",
    result["mitre_detected"] is False,
    result,
)

check(
    "legitimate email has zero techniques",
    result["technique_count"] == 0,
    result,
)


# ==========================================================
# CASE 2
# Empty email
# ==========================================================

result = analyze_mitre_attack({})

check(
    "empty email does not crash",
    isinstance(result, dict),
    result,
)

check(
    "empty email has no techniques",
    result["technique_count"] == 0,
    result,
)


# ==========================================================
# CASE 3
# Normal newsletter
# ==========================================================

email = {
    "sender": "updates@company.com",
    "subject": "Product Updates",
    "body": "Check out our latest features.",
}

result = analyze_mitre_attack(email)

check(
    "newsletter avoids MITRE phishing detection",
    result["mitre_detected"] is False,
    result,
)


# ==========================================================
# CASE 4
# Brand impersonation
# ==========================================================

email = {
    "sender": (
        "Microsoft Security "
        "<security@micros0ft.xyz>"
    ),
    "subject": "Security Notification",
    "body": "Please review your account.",
}

result = analyze_mitre_attack(email)

technique_ids = [
    item["id"]
    for item in result["techniques"]
]

check(
    "brand impersonation detects masquerading",
    "T1036" in technique_ids,
    result,
)


# ==========================================================
# CASE 5
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

result = analyze_mitre_attack(email)

technique_ids = [
    item["id"]
    for item in result["techniques"]
]

check(
    "credential phishing detects phishing",
    "T1566" in technique_ids,
    result,
)

check(
    "credential phishing detects input capture",
    "T1056" in technique_ids,
    result,
)


# ==========================================================
# CASE 6
# Malicious attachment
# ==========================================================

email = {
    "sender": "invoice@unknown.xyz",
    "subject": "Invoice Attached",
    "body": "Please review the attached invoice.",
    "attachments": [
        "invoice.pdf.exe"
    ],
}

result = analyze_mitre_attack(email)

technique_ids = [
    item["id"]
    for item in result["techniques"]
]

check(
    "malicious attachment detects spearphishing attachment",
    "T1566.001" in technique_ids,
    result,
)

check(
    "malicious attachment detects user execution",
    "T1204" in technique_ids,
    result,
)


# ==========================================================
# CASE 7
# Suspicious infrastructure
# ==========================================================

email = {
    "sender": "security@unknown.xyz",
    "subject": "Security Alert",
    "body": "Click the link immediately.",
    "urls": [
        "http://192.168.1.10/login"
    ],
}

result = analyze_mitre_attack(email)

technique_ids = [
    item["id"]
    for item in result["techniques"]
]

check(
    "suspicious infrastructure maps to resource development",
    "T1583" in technique_ids,
    result,
)


# ==========================================================
# CASE 8
# Full multi-stage attack
# ==========================================================

email = {
    "sender": (
        "Microsoft Security "
        "<security@micros0ft.xyz>"
    ),
    "reply_to": "attacker@gmail.com",
    "subject": "URGENT SECURITY ALERT!!!",
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

result = analyze_mitre_attack(email)

check(
    "full attack triggers MITRE detection",
    result["mitre_detected"] is True,
    result,
)

check(
    "full attack detects multiple techniques",
    result["technique_count"] >= 5,
    result,
)

check(
    "full attack has high coverage score",
    result["coverage_score"] >= 70,
    result,
)


# ==========================================================
# CASE 9
# Duplicate technique detection
# ==========================================================

technique_ids = [
    technique["id"]
    for technique in result["techniques"]
]

check(
    "no duplicate MITRE techniques",
    len(technique_ids) == len(set(technique_ids)),
    result,
)


# ==========================================================
# CASE 10
# Tactic consistency audit
# ==========================================================

technique_tactics = {
    technique["tactic"]
    for technique in result["techniques"]
}

declared_tactics = set(
    result["tactics"]
)

check(
    "all declared tactics have supporting techniques",
    declared_tactics.issubset(
        technique_tactics
    ),
    result,
)


# ==========================================================
# CASE 11
# Malformed input
# ==========================================================

email = {
    "sender": None,
    "reply_to": None,
    "subject": 12345,
    "body": None,
    "urls": "not-a-list",
    "attachments": None,
}

try:

    result = analyze_mitre_attack(email)

    check(
        "malformed input does not crash",
        isinstance(result, dict),
        result,
    )

except Exception as exc:

    check(
        "malformed input does not crash",
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

    result = analyze_mitre_attack(
        "invalid-input"
    )

    check(
        "invalid top-level input handled safely",
        isinstance(result, dict),
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
# RESULT
# ==========================================================

print()

print("=" * 78)

print(
    f"MITRE_ATTACK_AUDIT_RESULT: "
    f"{PASS} PASS / {FAIL} FAIL"
)

print("=" * 78)


if FAIL > 0:

    sys.exit(1)


sys.exit(0)
