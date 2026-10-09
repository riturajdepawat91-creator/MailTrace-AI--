import json

from services.email_thread_intelligence import analyze_thread_to_dict


def run_case(name, messages):
    result = analyze_thread_to_dict(messages)
    print("")
    print("============================================================")
    print(name)
    print("============================================================")
    print(json.dumps(result, indent=2))
    return result


# ------------------------------------------------------------
# CASE 1: Normal thread
# ------------------------------------------------------------

normal = run_case(
    "CASE 1 — NORMAL THREAD",
    [
        {
            "message_id": "<m1@example.com>",
            "subject": "Invoice review",
            "from": "alice@example.com",
            "to": "bob@example.com",
            "body": "Please review.",
        },
        {
            "message_id": "<m2@example.com>",
            "in_reply_to": "<m1@example.com>",
            "references": "<m1@example.com>",
            "subject": "Re: Invoice review",
            "from": "bob@example.com",
            "to": "alice@example.com",
            "body": "> Previous message\nPlease find the update.",
        },
        {
            "message_id": "<m3@example.com>",
            "in_reply_to": "<m2@example.com>",
            "references": "<m1@example.com> <m2@example.com>",
            "subject": "Re: Invoice review",
            "from": "alice@example.com",
            "to": "bob@example.com",
            "body": "Approved.",
        },
    ],
)

assert normal["thread_depth"] == 3
assert normal["continuity"]["missing_parent_link_count"] == 0
assert normal["continuity"]["duplicate_message_id_count"] == 0
assert normal["continuity"]["cycle_count"] == 0
assert normal["continuity"]["canonical_parent_links"] == 2
assert normal["thread_identity"]["root_message_id"] == "<m1@example.com>"


# ------------------------------------------------------------
# CASE 2: Missing parent / orphan
# ------------------------------------------------------------

orphan = run_case(
    "CASE 2 — MISSING PARENT",
    [
        {
            "message_id": "<child@example.com>",
            "in_reply_to": "<missing@example.com>",
            "references": "<missing@example.com>",
            "subject": "Re: Payment",
            "from": "alice@example.com",
            "to": "bob@example.com",
            "body": "Following up.",
        },
    ],
)

assert orphan["continuity"]["missing_parent_link_count"] == 1
assert orphan["continuity"]["orphan_count"] == 1
assert any(
    item["type"] == "MISSING_PARENT_LINK"
    for item in orphan["anomalies"]
)


# ------------------------------------------------------------
# CASE 3: Duplicate Message-ID
# ------------------------------------------------------------

duplicate = run_case(
    "CASE 3 — DUPLICATE MESSAGE ID",
    [
        {
            "message_id": "<dup@example.com>",
            "subject": "Test",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "One",
        },
        {
            "message_id": "<dup@example.com>",
            "in_reply_to": "<dup@example.com>",
            "subject": "Re: Test",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Two",
        },
    ],
)

assert duplicate["continuity"]["duplicate_message_id_count"] == 1
assert any(
    item["type"] == "DUPLICATE_MESSAGE_ID"
    for item in duplicate["anomalies"]
)


# ------------------------------------------------------------
# CASE 4: Reference conflict
# ------------------------------------------------------------

reference_conflict = run_case(
    "CASE 4 — REFERENCE CONFLICT",
    [
        {
            "message_id": "<m1@example.com>",
            "subject": "Case",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "Start",
        },
        {
            "message_id": "<m2@example.com>",
            "in_reply_to": "<m1@example.com>",
            "references": "<different@example.com>",
            "subject": "Re: Case",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "Reply",
        },
    ],
)

assert reference_conflict["continuity"]["reference_conflict_count"] == 1
assert any(
    item["type"] == "REFERENCE_CHAIN_CONFLICT"
    for item in reference_conflict["anomalies"]
)


# ------------------------------------------------------------
# CASE 5: Cycle
# ------------------------------------------------------------

cycle = run_case(
    "CASE 5 — GRAPH CYCLE",
    [
        {
            "message_id": "<a@example.com>",
            "in_reply_to": "<b@example.com>",
            "subject": "Cycle",
            "from": "a@example.com",
            "to": "b@example.com",
            "body": "A",
        },
        {
            "message_id": "<b@example.com>",
            "in_reply_to": "<a@example.com>",
            "subject": "Re: Cycle",
            "from": "b@example.com",
            "to": "a@example.com",
            "body": "B",
        },
    ],
)

assert cycle["continuity"]["cycle_count"] >= 1
assert any(
    item["type"] == "THREAD_GRAPH_CYCLE"
    for item in cycle["anomalies"]
)
assert cycle["thread_risk_score"] >= 35.0


# ------------------------------------------------------------
# CASE 6: Hostile / bounded input
# ------------------------------------------------------------

hostile = analyze_thread_to_dict(
    "not-a-list"
)

assert isinstance(hostile, dict)
assert hostile["thread_depth"] == 0
assert hostile["static_only"] is True


print("")
print("============================================================")
print("THREAD STEP 2 SMOKE + RECONSTRUCTION ASSERTIONS: PASS")
print("============================================================")
