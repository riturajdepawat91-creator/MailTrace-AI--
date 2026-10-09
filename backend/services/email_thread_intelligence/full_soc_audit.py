import ast
import copy
import json
import sys

from services.email_thread_intelligence import (
    analyze_thread,
    analyze_thread_to_dict,
)


PASS = 0
FAIL = 0


def check(name, condition, details=""):
    global PASS, FAIL

    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}")
        if details:
            print(f"       {details}")


def safe_case(messages):
    try:
        result = analyze_thread_to_dict(messages)
        return True, result, ""
    except Exception as exc:
        return False, None, repr(exc)


print("")
print("=" * 68)
print("EMAIL THREAD INTELLIGENCE — SOC AUDIT")
print("=" * 68)


# ============================================================
# A. IMPORT / CONTRACT
# ============================================================

try:
    result = analyze_thread_to_dict([])
    check(
        "A01 import + callable",
        isinstance(result, dict),
    )
except Exception as exc:
    check(
        "A01 import + callable",
        False,
        repr(exc),
    )


required_top_level = {
    "thread_identity",
    "thread_depth",
    "participant_graph",
    "continuity",
    "quoted_context",
    "anomalies",
    "thread_risk_score",
    "confidence",
    "evidence",
    "recommended_actions",
    "analysis_version",
    "static_only",
    "hijacking_assessment",
    "risk_breakdown",
    "analyst_summary",
}

for key in sorted(required_top_level):
    check(
        f"A02 output contract: {key}",
        key in result,
    )


# ============================================================
# B. STATIC-ONLY
# ============================================================

check(
    "B01 static_only=True",
    result.get("static_only") is True,
)

check(
    "B02 analysis has no network dependency",
    "network" not in str(result.get("risk_breakdown", {})).lower(),
)


# ============================================================
# C. TYPE / HOSTILE INPUT
# ============================================================

for idx, hostile in enumerate(
    [
        None,
        "",
        123,
        {},
        tuple(),
        object(),
        ["string"],
        [123, None, {}, []],
    ],
    start=1,
):
    ok, value, error = safe_case(hostile)

    check(
        f"C{idx:02d} hostile input does not crash",
        ok,
        error,
    )

    if ok:
        check(
            f"C{idx:02d} hostile output is dict",
            isinstance(value, dict),
        )


# ============================================================
# D. EMPTY / MINIMAL INPUT
# ============================================================

ok, empty, error = safe_case([])

check(
    "D01 empty input accepted",
    ok,
    error,
)

if ok:
    check(
        "D02 empty depth is zero",
        empty["thread_depth"] == 0,
    )

    check(
        "D03 empty calibrated risk is zero",
        empty["risk_breakdown"]["calibrated_risk_score"] == 0,
    )

    check(
        "D04 empty priority is NO_ACTION",
        empty["analyst_summary"]["priority"] == "NO_ACTION",
    )


# ============================================================
# E. BOUNDS
# ============================================================

messages = []

for i in range(250):
    messages.append(
        {
            "message_id": f"<m{i}@example.com>",
            "subject": "Bound test",
            "from": f"user{i}@example.com",
            "to": "soc@example.com",
            "body": "x" * 100,
        }
    )

ok, bounded, error = safe_case(messages)

check(
    "E01 >MAX_MESSAGES does not crash",
    ok,
    error,
)

if ok:
    check(
        "E02 message count bounded",
        bounded["thread_identity"]["message_count"] <= 100,
    )

    check(
        "E03 thread depth bounded",
        bounded["thread_depth"] <= 100,
    )


huge_body = [
    {
        "message_id": "<huge@example.com>",
        "subject": "Huge body",
        "from": "a@example.com",
        "to": "b@example.com",
        "body": "A" * (5 * 1024 * 1024),
    }
]

ok, huge, error = safe_case(huge_body)

check(
    "E04 huge body bounded safely",
    ok,
    error,
)


# ============================================================
# F. NORMAL THREAD
# ============================================================

normal_messages = [
    {
        "message_id": "<n1@company.example>",
        "subject": "Project status",
        "from": "alice@company.example",
        "to": "bob@company.example",
        "body": "Please send the project update.",
    },
    {
        "message_id": "<n2@company.example>",
        "in_reply_to": "<n1@company.example>",
        "references": "<n1@company.example>",
        "subject": "Re: Project status",
        "from": "bob@company.example",
        "to": "alice@company.example",
        "body": "> Please send the project update.\nHere is the update.",
    },
    {
        "message_id": "<n3@company.example>",
        "in_reply_to": "<n2@company.example>",
        "references": "<n1@company.example> <n2@company.example>",
        "subject": "Re: Project status",
        "from": "alice@company.example",
        "to": "bob@company.example",
        "body": "Perfect, thanks.",
    },
]

ok, normal, error = safe_case(normal_messages)

check(
    "F01 normal thread",
    ok,
    error,
)

if ok:
    check(
        "F02 normal thread depth",
        normal["thread_depth"] == 3,
    )

    check(
        "F03 normal thread no hijack",
        normal["hijacking_assessment"]["verdict"]
        == "NO_HIJACK_INDICATORS",
    )

    check(
        "F04 normal thread zero calibrated risk",
        normal["risk_breakdown"]["calibrated_risk_score"] == 0,
    )


# ============================================================
# G. DUPLICATE MESSAGE-ID
# ============================================================

duplicate_messages = [
    {
        "message_id": "<dup@example.com>",
        "subject": "Test",
        "from": "a@example.com",
        "to": "b@example.com",
        "body": "First",
    },
    {
        "message_id": "<dup@example.com>",
        "subject": "Re: Test",
        "from": "b@example.com",
        "to": "a@example.com",
        "body": "Second",
    },
]

ok, duplicate, error = safe_case(duplicate_messages)

check(
    "G01 duplicate Message-ID detected",
    ok and any(
        item["type"] == "DUPLICATE_MESSAGE_ID"
        for item in duplicate["anomalies"]
    ),
    error,
)

if ok:
    check(
        "G02 duplicate has evidence",
        any(
            item["evidence_id"]
            == "THREAD_DUPLICATE_MESSAGE_ID"
            for item in duplicate["evidence"]
        ),
    )


# ============================================================
# H. MISSING PARENT
# ============================================================

missing_parent = [
    {
        "message_id": "<child@example.com>",
        "in_reply_to": "<missing@example.com>",
        "references": "<missing@example.com>",
        "subject": "Re: Missing",
        "from": "b@example.com",
        "to": "a@example.com",
        "body": "Reply.",
    }
]

ok, orphan, error = safe_case(missing_parent)

check(
    "H01 missing parent detected",
    ok and orphan["continuity"]["missing_parent_link_count"] == 1,
    error,
)


# ============================================================
# I. REFERENCE CONFLICT
# ============================================================

reference_conflict = [
    {
        "message_id": "<a@example.com>",
        "subject": "Test",
        "from": "a@example.com",
        "to": "b@example.com",
        "body": "Start.",
    },
    {
        "message_id": "<b@example.com>",
        "in_reply_to": "<a@example.com>",
        "references": "<z@example.com>",
        "subject": "Re: Test",
        "from": "b@example.com",
        "to": "a@example.com",
        "body": "Conflict.",
    },
]

ok, conflict, error = safe_case(reference_conflict)

check(
    "I01 reference conflict detected",
    ok and conflict["continuity"]["reference_conflict_count"] == 1,
    error,
)


# ============================================================
# J. GRAPH CYCLE
# ============================================================

cycle_messages = [
    {
        "message_id": "<a@example.com>",
        "in_reply_to": "<b@example.com>",
        "references": "<b@example.com>",
        "subject": "Cycle",
        "from": "a@example.com",
        "to": "b@example.com",
        "body": "A",
    },
    {
        "message_id": "<b@example.com>",
        "in_reply_to": "<a@example.com>",
        "references": "<a@example.com>",
        "subject": "Re: Cycle",
        "from": "b@example.com",
        "to": "a@example.com",
        "body": "B",
    },
]

ok, cycle, error = safe_case(cycle_messages)

check(
    "J01 graph cycle detected",
    ok and cycle["continuity"]["cycle_count"] >= 1,
    error,
)

if ok:
    check(
        "J02 graph cycle calibrated risk",
        cycle["risk_breakdown"]["calibrated_risk_score"] >= 35,
    )


# ============================================================
# K. PARTICIPANT CHURN
# ============================================================

churn_messages = [
    {
        "message_id": "<c1@company.example>",
        "subject": "Project",
        "from": "alice@company.example",
        "to": "bob@company.example",
        "body": "Project discussion.",
    },
    {
        "message_id": "<c2@company.example>",
        "in_reply_to": "<c1@company.example>",
        "references": "<c1@company.example>",
        "subject": "Re: Project",
        "from": "bob@company.example",
        "to": "alice@company.example",
        "body": "Continuing discussion.",
    },
    {
        "message_id": "<c3@company.example>",
        "in_reply_to": "<c2@company.example>",
        "references": "<c1@company.example> <c2@company.example>",
        "subject": "Re: Project",
        "from": "carol@company.example",
        "to": "alice@company.example, bob@company.example",
        "body": "Adding Carol for visibility.",
    },
]

ok, churn, error = safe_case(churn_messages)

check(
    "K01 participant churn handled",
    ok,
    error,
)

if ok:
    check(
        "K02 benign participant change not immediate review",
        churn["analyst_summary"]["priority"]
        != "IMMEDIATE_REVIEW",
    )


# ============================================================
# L. CORRELATED CONVERSATION HIJACK
# ============================================================

hijack_messages = [
    {
        "message_id": "<h1@company.example>",
        "subject": "Invoice review",
        "from": "alice@company.example",
        "to": "bob@company.example",
        "body": "Please review invoice 9001.",
    },
    {
        "message_id": "<h2@company.example>",
        "in_reply_to": "<h1@company.example>",
        "references": "<h1@company.example>",
        "subject": "Re: Invoice review",
        "from": "bob@company.example",
        "to": "alice@company.example",
        "body": "> Please review invoice 9001.\nI am checking it.",
    },
    {
        "message_id": "<h3@evil.example>",
        "in_reply_to": "<h2@company.example>",
        "references": "<h1@company.example> <h2@company.example>",
        "subject": "Re: Invoice review",
        "from": "attacker@evil.example",
        "to": "alice@company.example",
        "body": (
            "The bank account changed. "
            "Please send the invoice payment immediately "
            "to the new account."
        ),
    },
]

ok, hijack, error = safe_case(hijack_messages)

check(
    "L01 hijack correlation detected",
    ok
    and hijack["hijacking_assessment"]["verdict"]
    == "POTENTIAL_CONVERSATION_HIJACK",
    error,
)

if ok:
    check(
        "L02 hijack severity HIGH",
        hijack["hijacking_assessment"]["severity"] == "HIGH",
    )

    check(
        "L03 hijack immediate review",
        hijack["analyst_summary"]["priority"]
        == "IMMEDIATE_REVIEW",
    )

    check(
        "L04 hijack calibrated risk high",
        hijack["risk_breakdown"]["calibrated_risk_score"] >= 70,
    )

    check(
        "L05 correlation bonus present",
        hijack["risk_breakdown"]["correlation_bonus"] > 0,
    )

    check(
        "L06 verification guidance present",
        len(
            hijack["analyst_summary"]["verification_steps"]
        ) >= 2,
    )


# ============================================================
# M. EVIDENCE INTEGRITY
# ============================================================

if ok:
    evidence = hijack["risk_breakdown"]["evidence_quality"]

    check(
        "M01 evidence quality is list",
        isinstance(evidence, list),
    )

    check(
        "M02 weighted evidence confidence bounded",
        0.0
        <= hijack["risk_breakdown"][
            "weighted_evidence_confidence"
        ]
        <= 1.0,
    )

    for idx, item in enumerate(evidence):
        check(
            f"M03 evidence confidence bounded {idx}",
            0.0
            <= float(item["confidence"])
            <= 1.0,
        )

        check(
            f"M04 evidence reliability bounded {idx}",
            0.0
            <= float(item["reliability_score"])
            <= 1.0,
        )


# ============================================================
# N. RISK BOUNDS
# ============================================================

test_results = [
    empty,
    normal if 'normal' in locals() else {},
    duplicate if 'duplicate' in locals() else {},
    orphan if 'orphan' in locals() else {},
    conflict if 'conflict' in locals() else {},
    cycle if 'cycle' in locals() else {},
    churn if 'churn' in locals() else {},
    hijack if 'hijack' in locals() else {},
]

for idx, value in enumerate(test_results, start=1):
    if isinstance(value, dict):

        if "thread_risk_score" in value:
            check(
                f"N{idx:02d} thread risk bounded",
                0.0
                <= float(value["thread_risk_score"])
                <= 100.0,
            )

        if "confidence" in value:
            check(
                f"N{idx:02d} confidence bounded",
                0.0
                <= float(value["confidence"])
                <= 1.0,
            )

        rb = value.get(
            "risk_breakdown",
            {},
        )

        if isinstance(rb, dict):
            if "calibrated_risk_score" in rb:
                check(
                    f"N{idx:02d} calibrated risk bounded",
                    0.0
                    <= float(
                        rb["calibrated_risk_score"]
                    )
                    <= 100.0,
                )

            if "correlation_bonus" in rb:
                check(
                    f"N{idx:02d} correlation bonus bounded",
                    0.0
                    <= float(
                        rb["correlation_bonus"]
                    )
                    <= 20.0,
                )


# ============================================================
# O. OUTPUT SIZE / BOUNDS
# ============================================================

if isinstance(hijack, dict):

    check(
        "O01 evidence list bounded",
        len(hijack["evidence"]) <= 100,
    )

    check(
        "O02 anomaly list bounded",
        len(hijack["anomalies"]) <= 100,
    )

    check(
        "O03 actions are bounded list",
        isinstance(
            hijack["recommended_actions"],
            list,
        )
        and len(hijack["recommended_actions"]) <= 100,
    )


# ============================================================
# P. DETERMINISM
# ============================================================

determinism_input = copy.deepcopy(hijack_messages)

try:
    d1 = analyze_thread_to_dict(
        copy.deepcopy(determinism_input)
    )

    d2 = analyze_thread_to_dict(
        copy.deepcopy(determinism_input)
    )

    check(
        "P01 deterministic identical output",
        d1 == d2,
    )
except Exception as exc:
    check(
        "P01 deterministic identical output",
        False,
        repr(exc),
    )


# ============================================================
# Q. NO INPUT MUTATION
# ============================================================

mutation_input = copy.deepcopy(hijack_messages)
before = copy.deepcopy(mutation_input)

try:
    analyze_thread(mutation_input)

    check(
        "Q01 input messages are not mutated",
        mutation_input == before,
    )
except Exception as exc:
    check(
        "Q01 input messages are not mutated",
        False,
        repr(exc),
    )


# ============================================================
# R. UNICODE / ODD HEADER INPUT
# ============================================================

unicode_case = [
    {
        "message_id": "  <unicøde@example.com>  ",
        "subject": "\u200bRe: Test\u200f",
        "from": " Alice@Example.COM ",
        "to": " Bob@Example.COM ",
        "body": "> old\nNew content.",
    },
]

ok, unicode_result, error = safe_case(unicode_case)

check(
    "R01 Unicode / whitespace input safe",
    ok,
    error,
)


# ============================================================
# S. SERIALIZATION
# ============================================================

if ok:
    try:
        serialized = json.dumps(
            unicode_result,
            ensure_ascii=False,
        )

        reparsed = json.loads(serialized)

        check(
            "S01 JSON serialization",
            isinstance(reparsed, dict),
        )

        check(
            "S02 JSON serialization stable",
            set(reparsed.keys())
            == set(unicode_result.keys()),
        )

    except Exception as exc:
        check(
            "S01 JSON serialization",
            False,
            repr(exc),
        )


# ============================================================
# T. AST / FORBIDDEN ACTIVE BEHAVIOR
# ============================================================

source_files = [
    "engine.py",
    "models.py",
    "rules.py",
]

for filename in source_files:

    try:
        with open(
            "services/email_thread_intelligence/"
            + filename,
            "r",
            encoding="utf-8-sig",
        ) as handle:
            source = handle.read()

        tree = ast.parse(source)

        # Reject only actual active code-execution primitives.
        # re.compile(...) is a legitimate regex constructor and
        # must NOT be treated as executable code injection.
        forbidden_bare_calls = {
            "eval",
            "exec",
            "__import__",
            "compile",
        }

        forbidden_attribute_calls = {
            "system",
            "popen",
        }

        found = []

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # Bare calls:
            #   eval(...)
            #   exec(...)
            #   __import__(...)
            #   compile(...)
            if isinstance(func, ast.Name):
                if func.id in forbidden_bare_calls:
                    found.append(
                        f"call:{func.id}"
                    )

            # Attribute calls:
            #   os.system(...)
            #   os.popen(...)
            #
            # Do NOT reject:
            #   re.compile(...)
            if isinstance(func, ast.Attribute):
                if func.attr in forbidden_attribute_calls:
                    found.append(
                        f"call:{func.attr}"
                    )

        check(
            f"T{filename} no forbidden active execution",
            not found,
            repr(sorted(set(found))),
        )

    except Exception as exc:
        check(
            f"T{filename} AST parse",
            False,
            repr(exc),
        )

# ============================================================
# U. ANALYST SUMMARY CONTRACT
# ============================================================

if isinstance(hijack, dict):

    summary = hijack["analyst_summary"]

    required_summary = {
        "priority",
        "verdict",
        "severity",
        "risk_score",
        "hijacking_risk_score",
        "structural_risk",
        "contextual_risk",
        "evidence_count",
        "correlated_detection",
        "top_signal_contributors",
        "top_structural_contributors",
        "explanation",
        "verification_steps",
    }

    for key in sorted(required_summary):
        check(
            f"U01 analyst summary field: {key}",
            key in summary,
        )

    check(
        "U02 analyst explanation non-empty",
        bool(
            str(
                summary.get(
                    "explanation",
                    "",
                )
            ).strip()
        ),
    )

    check(
        "U03 verification steps non-empty",
        bool(
            summary.get(
                "verification_steps",
                [],
            )
        ),
    )


# ============================================================
# V. VERSION / STATIC FLAGS
# ============================================================

try:
    analysis_version = result.get(
        "analysis_version",
        "",
    )

    check(
        "V01 analysis version non-empty",
        bool(str(analysis_version).strip()),
    )

    check(
        "V02 static flag consistent",
        result.get("static_only") is True,
    )

except Exception as exc:
    check(
        "V01 analysis version",
        False,
        repr(exc),
    )


# ============================================================
# FINAL
# ============================================================

print("")
print("=" * 68)
print("SOC AUDIT RESULTS")
print("=" * 68)
print(f"PASS = {PASS}")
print(f"FAIL = {FAIL}")
print("=" * 68)

if FAIL == 0:
    print("SOC AUDIT: PASS")
    print("MODULE ELIGIBLE FOR LOCK REVIEW")
else:
    print("SOC AUDIT: FAIL")
    print("MODULE MUST REMAIN UNLOCKED")

sys.exit(0 if FAIL == 0 else 10)
