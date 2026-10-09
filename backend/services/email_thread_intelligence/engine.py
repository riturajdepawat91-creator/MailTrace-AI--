from __future__ import annotations

from collections import Counter, defaultdict
import re
from typing import Any

from .models import (
    ANALYSIS_VERSION,
    MODULE_NAME,
    STATIC_ONLY,
    ThreadAnalysisResult,
    ThreadEvidence,
)
from .rules import (
    MAX_ANOMALIES,
    MAX_EVIDENCE,
    MAX_MESSAGES,
    MAX_TEXT_CHARS,
    detect_quoted_content,
    extract_email,
    extract_emails,
    normalize_message_id,
    normalize_references,
    normalize_subject,
)


INTENT_PATTERNS: dict[str, tuple[str, ...]] = {
    "PAYMENT": (
        "wire transfer",
        "bank transfer",
        "send payment",
        "make payment",
        "pay invoice",
        "payment",
        "bank account",
        "beneficiary",
        "account number",
        "routing number",
    ),
    "CREDENTIAL": (
        "password",
        "passcode",
        "otp",
        "one time password",
        "verification code",
        "login",
        "sign in",
        "credential",
    ),
    "ACCESS": (
        "grant access",
        "approve access",
        "reset account",
        "reset password",
        "unlock account",
        "administrator access",
        "admin access",
        "permission",
    ),
    "SENSITIVE_INFORMATION": (
        "social security",
        "tax id",
        "national id",
        "identity document",
        "confidential information",
        "sensitive information",
        "personal information",
    ),
    "DOCUMENT": (
        "invoice",
        "purchase order",
        "contract",
        "document",
        "attachment",
        "statement",
        "receipt",
    ),
    "URGENT_ACTION": (
        "urgent",
        "immediately",
        "as soon as possible",
        "today",
        "right away",
        "act now",
    ),
}


def _bounded_messages(messages: Any) -> list[dict[str, Any]]:
    if not isinstance(messages, list):
        return []

    result: list[dict[str, Any]] = []

    for item in messages[:MAX_MESSAGES]:
        if isinstance(item, dict):
            result.append(item)

    return result


def _bounded_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value[:MAX_TEXT_CHARS]


def _participant_graph(
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    participants: set[str] = set()
    edges: Counter[tuple[str, str]] = Counter()

    for message in messages:
        sender = extract_email(
            message.get("from")
            or message.get("sender")
        )

        recipients: list[str] = []

        for key in ("to", "cc"):
            recipients.extend(
                extract_emails(message.get(key))
            )

        if sender:
            participants.add(sender)

        for recipient in recipients:
            participants.add(recipient)

            if sender:
                edges[(sender, recipient)] += 1

    return {
        "participant_count": len(participants),
        "participants": sorted(participants)[:500],
        "interaction_edges": [
            {
                "from": source,
                "to": target,
                "count": count,
            }
            for (source, target), count
            in edges.most_common(1000)
        ],
    }


def _build_message_records(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for index, message in enumerate(messages):
        message_id = normalize_message_id(
            message.get("message_id")
        )

        in_reply_to = normalize_message_id(
            message.get("in_reply_to")
        )

        references = normalize_references(
            message.get("references")
        )

        sender = extract_email(
            message.get("from")
            or message.get("sender")
        )

        subject = normalize_subject(
            message.get("subject")
        )

        recipients: list[str] = []

        for key in ("to", "cc"):
            recipients.extend(
                extract_emails(message.get(key))
            )

        body = _bounded_text(message.get("body"))

        records.append(
            {
                "index": index,
                "message_id": message_id,
                "in_reply_to": in_reply_to,
                "references": references,
                "sender": sender,
                "sender_domain": _domain(sender),
                "recipients": sorted(set(recipients)),
                "recipient_domains": sorted(
                    {
                        _domain(item)
                        for item in recipients
                        if _domain(item)
                    }
                ),
                "subject": subject,
                "body": body,
                "quoted_context": detect_quoted_content(body),
                "new_content": _extract_new_content(body),
                "intent": _detect_intent(body),
            }
        )

    return records


def _domain(email: str) -> str:
    if not isinstance(email, str):
        return ""

    value = email.strip().casefold()

    if "@" not in value:
        return ""

    domain = value.rsplit("@", 1)[-1].strip()

    if not domain:
        return ""

    return domain


def _extract_new_content(body: Any) -> str:
    text = _bounded_text(body)

    if not text:
        return ""

    output: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith(">"):
            continue

        if re.match(
            r"(?i)^(from|sent|to|cc|subject)\s*:",
            stripped,
        ):
            continue

        output.append(line)

    return "\n".join(output).strip()[:MAX_TEXT_CHARS]


def _detect_intent(text: Any) -> list[str]:
    bounded = _bounded_text(text).casefold()

    if not bounded:
        return []

    found: list[str] = []

    for category, patterns in INTENT_PATTERNS.items():
        if any(pattern in bounded for pattern in patterns):
            found.append(category)

    return found


def _detect_cycles(
    graph: dict[str, list[str]],
) -> list[list[str]]:
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)

        for child in graph.get(node, []):
            child_state = state.get(child, 0)

            if child_state == 0:
                visit(child)

            elif child_state == 1 and child in stack:
                start = stack.index(child)
                cycle = stack[start:] + [child]

                if cycle not in cycles:
                    cycles.append(cycle)

        stack.pop()
        state[node] = 2

    for node in graph:
        if state.get(node, 0) == 0:
            visit(node)

    return cycles[:MAX_ANOMALIES]


def _reconstruct_thread(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    observed_ids = {
        record["message_id"]
        for record in records
        if record["message_id"]
    }

    parent_by_child: dict[str, str] = {}
    children_by_parent: dict[str, list[str]] = defaultdict(list)

    missing_parent_links: list[dict[str, Any]] = []
    reference_conflicts: list[dict[str, Any]] = []

    for record in records:
        child = record["message_id"]

        if not child:
            continue

        candidate_parent = ""

        if record["in_reply_to"]:
            candidate_parent = record["in_reply_to"]

        elif record["references"]:
            candidate_parent = record["references"][-1]

        if candidate_parent:
            parent_by_child[child] = candidate_parent

            if candidate_parent in observed_ids:
                children_by_parent[candidate_parent].append(child)
            else:
                missing_parent_links.append(
                    {
                        "child": child,
                        "parent": candidate_parent,
                        "source": (
                            "in_reply_to"
                            if record["in_reply_to"]
                            else "references"
                        ),
                    }
                )

        refs = record["references"]

        if (
            record["in_reply_to"]
            and refs
            and record["in_reply_to"] not in refs
        ):
            reference_conflicts.append(
                {
                    "message_id": child,
                    "in_reply_to": record["in_reply_to"],
                    "references": refs[:50],
                }
            )

    graph = {
        parent: list(children)
        for parent, children in children_by_parent.items()
    }

    cycles = _detect_cycles(graph)

    roots = sorted(
        observed_ids.difference(parent_by_child.keys())
    )

    orphans = sorted(
        {
            item["child"]
            for item in missing_parent_links
        }
    )

    return {
        "observed_message_ids": sorted(observed_ids)[:MAX_MESSAGES],
        "parent_by_child": dict(
            list(parent_by_child.items())[:MAX_MESSAGES]
        ),
        "children_by_parent": graph,
        "root_message_ids": roots[:MAX_MESSAGES],
        "orphan_message_ids": orphans[:MAX_MESSAGES],
        "missing_parent_links": missing_parent_links[
            :MAX_ANOMALIES
        ],
        "reference_conflicts": reference_conflicts[
            :MAX_ANOMALIES
        ],
        "cycles": cycles,
    }


def _subject_lineage(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    subjects = [
        record["subject"]
        for record in records
        if record["subject"]
    ]

    unique_subjects = list(dict.fromkeys(subjects))

    transitions: list[dict[str, Any]] = []

    for index in range(1, len(records)):
        previous = records[index - 1]["subject"]
        current = records[index]["subject"]

        if previous and current and previous != current:
            transitions.append(
                {
                    "from_index": index - 1,
                    "to_index": index,
                    "from_subject": previous,
                    "to_subject": current,
                }
            )

    return {
        "unique_normalized_subject_count": len(unique_subjects),
        "subjects": unique_subjects[:MAX_MESSAGES],
        "subject_transition_count": len(transitions),
        "subject_transitions": transitions[
            :MAX_ANOMALIES
        ],
        "stable_subject_lineage": len(unique_subjects) <= 1,
    }


def _sender_lineage(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    senders = [
        record["sender"]
        for record in records
        if record["sender"]
    ]

    unique_senders = list(dict.fromkeys(senders))

    transitions: list[dict[str, Any]] = []

    for index in range(1, len(records)):
        previous = records[index - 1]["sender"]
        current = records[index]["sender"]

        if previous and current and previous != current:
            transitions.append(
                {
                    "from_index": index - 1,
                    "to_index": index,
                    "from_sender": previous,
                    "to_sender": current,
                }
            )

    return {
        "unique_sender_count": len(unique_senders),
        "senders": unique_senders[:MAX_MESSAGES],
        "sender_transition_count": len(transitions),
        "sender_transitions": transitions[
            :MAX_ANOMALIES
        ],
    }


def _participant_churn(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    if not records:
        return {
            "baseline_participants": [],
            "new_participants": [],
            "new_domains": [],
            "participant_injection_count": 0,
            "external_boundary_changes": 0,
        }

    baseline_window = records[: min(2, len(records))]

    baseline_participants = sorted(
        {
            person
            for record in baseline_window
            for person in (
                ([record["sender"]] if record["sender"] else [])
                + record["recipients"]
            )
        }
    )

    baseline_domains = {
        _domain(person)
        for person in baseline_participants
        if _domain(person)
    }

    observed_participants: set[str] = set()
    new_participants: list[dict[str, Any]] = []
    new_domains: set[str] = set()
    injections = 0
    boundary_changes = 0

    for index, record in enumerate(records):
        current_people = set(record["recipients"])

        if record["sender"]:
            current_people.add(record["sender"])

        for person in sorted(current_people):
            domain = _domain(person)

            if (
                person not in observed_participants
                and person not in baseline_participants
                and index >= len(baseline_window)
            ):
                injections += 1

                item = {
                    "index": index,
                    "participant": person,
                    "domain": domain,
                    "new_domain": (
                        bool(domain)
                        and domain not in baseline_domains
                    ),
                }

                new_participants.append(item)

                if (
                    domain
                    and domain not in baseline_domains
                ):
                    new_domains.add(domain)
                    boundary_changes += 1

            observed_participants.add(person)

    return {
        "baseline_participants": baseline_participants[:500],
        "new_participants": new_participants[:MAX_ANOMALIES],
        "new_domains": sorted(new_domains)[:MAX_ANOMALIES],
        "participant_injection_count": injections,
        "external_boundary_changes": boundary_changes,
    }


def _reply_target_analysis(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    transitions: list[dict[str, Any]] = []

    for index in range(1, len(records)):
        previous = records[index - 1]
        current = records[index]

        previous_expected = set(previous["recipients"])

        sender = current["sender"]

        sender_matches_prior_recipient = (
            bool(sender)
            and sender in previous_expected
        )

        current_target_set = set(current["recipients"])

        prior_sender = previous["sender"]

        unexpected_target_change = bool(
            prior_sender
            and current_target_set
            and prior_sender not in current_target_set
            and not sender_matches_prior_recipient
        )

        if unexpected_target_change:
            transitions.append(
                {
                    "index": index,
                    "prior_sender": prior_sender,
                    "current_sender": sender,
                    "prior_recipients": sorted(previous_expected),
                    "current_recipients": sorted(current_target_set),
                    "sender_matched_prior_recipient": (
                        sender_matches_prior_recipient
                    ),
                }
            )

    return {
        "unexpected_reply_target_changes": transitions[
            :MAX_ANOMALIES
        ],
        "count": len(transitions),
    }


def _context_shift_analysis(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    shifts: list[dict[str, Any]] = []

    high_risk_intents = {
        "PAYMENT",
        "CREDENTIAL",
        "ACCESS",
        "SENSITIVE_INFORMATION",
    }

    for index in range(1, len(records)):
        previous = records[index - 1]
        current = records[index]

        previous_intents = set(previous["intent"])
        current_intents = set(current["intent"])

        newly_introduced = sorted(
            current_intents.difference(previous_intents)
        )

        high_risk_new = sorted(
            set(newly_introduced).intersection(
                high_risk_intents
            )
        )

        sender_changed = (
            previous["sender"]
            and current["sender"]
            and previous["sender"] != current["sender"]
        )

        subject_changed = (
            previous["subject"]
            and current["subject"]
            and previous["subject"] != current["subject"]
        )

        new_participant = current["sender"] not in {
            record["sender"]
            for record in records[:index]
            if record["sender"]
        }

        if (
            high_risk_new
            and (
                sender_changed
                or subject_changed
                or new_participant
            )
        ):
            shifts.append(
                {
                    "index": index,
                    "previous_sender": previous["sender"],
                    "current_sender": current["sender"],
                    "previous_intents": sorted(previous_intents),
                    "current_intents": sorted(current_intents),
                    "newly_introduced_intents": newly_introduced,
                    "high_risk_new_intents": high_risk_new,
                    "sender_changed": bool(sender_changed),
                    "subject_changed": bool(subject_changed),
                    "new_participant": bool(new_participant),
                }
            )

    return {
        "count": len(shifts),
        "shifts": shifts[:MAX_ANOMALIES],
    }


def _quoted_context_analysis(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    assessments: list[dict[str, Any]] = []

    high_risk_intents = {
        "PAYMENT",
        "CREDENTIAL",
        "ACCESS",
        "SENSITIVE_INFORMATION",
    }

    for index, record in enumerate(records):
        quote = record["quoted_context"]
        new_content = record["new_content"]
        new_intents = set(_detect_intent(new_content))

        quoted_lines = int(
            quote.get("quoted_line_count", 0)
        )

        total_lines = max(
            len(record["body"].splitlines()),
            1,
        )

        quoted_ratio = round(
            min(1.0, quoted_lines / total_lines),
            3,
        )

        if quoted_ratio >= 0.70 and new_intents.intersection(
            high_risk_intents
        ):
            assessments.append(
                {
                    "index": index,
                    "quoted_ratio": quoted_ratio,
                    "new_content_intents": sorted(new_intents),
                    "high_risk_new_intents": sorted(
                        new_intents.intersection(
                            high_risk_intents
                        )
                    ),
                }
            )

    return {
        "count": len(assessments),
        "assessments": assessments[:MAX_ANOMALIES],
    }


def _role_switch_analysis(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    sender_roles: dict[str, set[str]] = defaultdict(set)

    for index, record in enumerate(records):
        sender = record["sender"]

        if not sender:
            continue

        role = "INITIAL_SENDER" if index == 0 else "THREAD_PARTICIPANT"

        if sender in {
            recipient
            for item in records[:index]
            for recipient in item["recipients"]
        }:
            role = "PRIOR_RECIPIENT"

        sender_roles[sender].add(role)

    late_new_senders: list[str] = []

    seen: set[str] = set()

    for index, record in enumerate(records):
        sender = record["sender"]

        if not sender:
            continue

        if (
            index >= 2
            and sender not in seen
        ):
            late_new_senders.append(sender)

        seen.add(sender)

    return {
        "sender_roles": {
            sender: sorted(roles)
            for sender, roles in list(
                sender_roles.items()
            )[:500]
        },
        "late_new_sender_count": len(
            late_new_senders
        ),
        "late_new_senders": late_new_senders[
            :MAX_ANOMALIES
        ],
    }


def _build_hijacking_assessment(
    records: list[dict[str, Any]],
    churn: dict[str, Any],
    reply_targets: dict[str, Any],
    context_shift: dict[str, Any],
    quoted_analysis: dict[str, Any],
    role_analysis: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[ThreadEvidence]]:
    signals: list[dict[str, Any]] = []
    evidence: list[ThreadEvidence] = []

    if churn["participant_injection_count"] > 0:
        signals.append(
            {
                "signal": "THREAD_NEW_PARTICIPANT",
                "weight": 8.0,
                "count": churn[
                    "participant_injection_count"
                ],
            }
        )

    if churn["external_boundary_changes"] > 0:
        signals.append(
            {
                "signal": "THREAD_EXTERNAL_BOUNDARY_CHANGE",
                "weight": 12.0,
                "count": churn[
                    "external_boundary_changes"
                ],
            }
        )

    if role_analysis["late_new_sender_count"] > 0:
        signals.append(
            {
                "signal": "THREAD_SENDER_ROLE_SWITCH",
                "weight": 8.0,
                "count": role_analysis[
                    "late_new_sender_count"
                ],
            }
        )

    if reply_targets["count"] > 0:
        signals.append(
            {
                "signal": "THREAD_REPLY_TARGET_CHANGE",
                "weight": 14.0,
                "count": reply_targets["count"],
            }
        )

    if context_shift["count"] > 0:
        signals.append(
            {
                "signal": "THREAD_CONTEXT_SHIFT",
                "weight": 25.0,
                "count": context_shift["count"],
            }
        )

    if quoted_analysis["count"] > 0:
        signals.append(
            {
                "signal": "THREAD_QUOTED_CONTEXT_MISMATCH",
                "weight": 12.0,
                "count": quoted_analysis[
                    "count"
                ],
            }
        )

    score = min(
        100.0,
        round(
            sum(item["weight"] for item in signals),
            2,
        ),
    )

    distinct_signal_count = len(signals)

    if (
        context_shift["count"] > 0
        and (
            churn["external_boundary_changes"] > 0
            or reply_targets["count"] > 0
        )
    ):
        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_POTENTIAL_CONVERSATION_HIJACK",
                category="conversation_hijacking",
                severity="HIGH",
                confidence=0.94,
                description=(
                    "A late conversation participant or reply-target "
                    "change coincides with a newly introduced high-risk "
                    "request context."
                ),
                details={
                    "context_shifts": context_shift[
                        "shifts"
                    ][:20],
                    "new_participants": churn[
                        "new_participants"
                    ][:20],
                    "reply_target_changes": reply_targets[
                        "unexpected_reply_target_changes"
                    ][:20],
                },
            )
        )

    if churn["external_boundary_changes"] > 0:
        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_EXTERNAL_PARTICIPANT_INJECTION",
                category="participant_integrity",
                severity="MEDIUM",
                confidence=0.82,
                description=(
                    "A participant from a previously unseen domain "
                    "was introduced later in the supplied thread."
                ),
                details={
                    "new_domains": churn["new_domains"][
                        :50
                    ],
                    "new_participants": churn[
                        "new_participants"
                    ][:50],
                },
            )
        )

    if reply_targets["count"] > 0:
        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_REPLY_TARGET_CHANGE",
                category="conversation_integrity",
                severity="MEDIUM",
                confidence=0.84,
                description=(
                    "A later message changes the expected reply-target "
                    "pattern in the supplied conversation."
                ),
                details={
                    "changes": reply_targets[
                        "unexpected_reply_target_changes"
                    ][:50],
                },
            )
        )

    if context_shift["count"] > 0:
        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_CONTEXT_SHIFT",
                category="context_integrity",
                severity="HIGH",
                confidence=0.90,
                description=(
                    "A later message introduces a high-risk request "
                    "intent after a different preceding conversation context."
                ),
                details={
                    "shifts": context_shift[
                        "shifts"
                    ][:50],
                },
            )
        )

    if quoted_analysis["count"] > 0:
        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_QUOTED_CONTEXT_MISMATCH",
                category="content_integrity",
                severity="MEDIUM",
                confidence=0.78,
                description=(
                    "A message is dominated by quoted material while "
                    "its new content introduces a high-risk intent."
                ),
                details={
                    "assessments": quoted_analysis[
                        "assessments"
                    ][:50],
                },
            )
        )

    # Correlation bonus: multiple independent signals are stronger
    # than any single participant change.
    if distinct_signal_count >= 3:
        score = min(100.0, round(score + 12.0, 2))

    if distinct_signal_count >= 4:
        score = min(100.0, round(score + 8.0, 2))

    if (
        score >= 55.0
        and context_shift["count"] > 0
        and (
            churn["external_boundary_changes"] > 0
            or reply_targets["count"] > 0
        )
    ):
        verdict = "POTENTIAL_CONVERSATION_HIJACK"
        severity = "HIGH"
    elif score >= 35.0:
        verdict = "STRUCTURAL_CONVERSATION_ANOMALY"
        severity = "MEDIUM"
    elif score > 0:
        verdict = "LOW_CONTEXT_ANOMALY"
        severity = "LOW"
    else:
        verdict = "NO_HIJACK_INDICATORS"
        severity = "INFO"

    return (
        {
            "verdict": verdict,
            "severity": severity,
            "risk_score": score,
            "signal_count": distinct_signal_count,
            "signals": signals,
            "correlated_detection": (
                distinct_signal_count >= 3
            ),
        },
        signals,
        evidence,
    )


def _calibrate_risk_breakdown(
    anomalies: list[dict[str, Any]],
    hijacking_assessment: dict[str, Any],
    evidence: list[ThreadEvidence],
) -> dict[str, Any]:
    severity_weights = {
        "HIGH": 35.0,
        "MEDIUM": 18.0,
        "LOW": 7.0,
        "INFO": 0.0,
    }

    anomaly_contributions: list[dict[str, Any]] = []

    for anomaly in anomalies[:MAX_ANOMALIES]:
        severity = str(
            anomaly.get("severity", "INFO")
        ).upper()

        base_score = severity_weights.get(
            severity,
            0.0,
        )

        anomaly_contributions.append(
            {
                "type": anomaly.get(
                    "type",
                    "",
                ),
                "severity": severity,
                "base_score": base_score,
                "calibrated_contribution": base_score,
            }
        )

    signal_contributions: list[dict[str, Any]] = []

    for signal in hijacking_assessment.get(
        "signals",
        [],
    )[:MAX_ANOMALIES]:

        weight = float(
            signal.get(
                "weight",
                0.0,
            )
            or 0.0
        )

        occurrences = max(
            1,
            int(
                signal.get(
                    "count",
                    1,
                )
                or 1
            ),
        )

        bounded_factor = min(
            2.0,
            1.0 + ((occurrences - 1) * 0.25),
        )

        contribution = round(
            weight * bounded_factor,
            2,
        )

        signal_contributions.append(
            {
                "signal": signal.get(
                    "signal",
                    "",
                ),
                "occurrences": occurrences,
                "base_weight": weight,
                "calibrated_contribution": contribution,
            }
        )

    anomaly_total = min(
        100.0,
        round(
            sum(
                item["calibrated_contribution"]
                for item in anomaly_contributions
            ),
            2,
        ),
    )

    signal_total = min(
        100.0,
        round(
            sum(
                item["calibrated_contribution"]
                for item in signal_contributions
            ),
            2,
        ),
    )

    signal_count = int(
        hijacking_assessment.get(
            "signal_count",
            0,
        )
        or 0
    )

    correlation_bonus = 0.0

    if signal_count >= 3:
        correlation_bonus += 12.0

    if signal_count >= 4:
        correlation_bonus += 8.0

    correlation_bonus = min(
        20.0,
        correlation_bonus,
    )

    # Evidence quality is confidence weighted by severity.
    evidence_quality: list[dict[str, Any]] = []

    for item in evidence[:MAX_EVIDENCE]:

        confidence = float(
            item.confidence
            if isinstance(
                item,
                ThreadEvidence,
            )
            else item.get(
                "confidence",
                0.0,
            )
        )

        severity = str(
            item.severity
            if isinstance(
                item,
                ThreadEvidence,
            )
            else item.get(
                "severity",
                "INFO",
            )
        ).upper()

        severity_factor = {
            "HIGH": 1.00,
            "MEDIUM": 0.70,
            "LOW": 0.35,
            "INFO": 0.00,
        }.get(
            severity,
            0.0,
        )

        reliability_score = round(
            confidence * severity_factor,
            3,
        )

        evidence_quality.append(
            {
                "evidence_id": (
                    item.evidence_id
                    if isinstance(
                        item,
                        ThreadEvidence,
                    )
                    else item.get(
                        "evidence_id",
                        "",
                    )
                ),
                "severity": severity,
                "confidence": round(
                    confidence,
                    3,
                ),
                "reliability_score": reliability_score,
            }
        )

    weighted_evidence_confidence = (
        round(
            sum(
                item["reliability_score"]
                for item in evidence_quality
            ) / len(evidence_quality),
            3,
        )
        if evidence_quality
        else 0.0
    )

    # Two independent dimensions:
    #   structural risk
    #   contextual/hijacking risk
    #
    # Do not blindly sum both — that would double count related
    # signals. Use the stronger dimension plus a bounded synergy.
    structural_risk = anomaly_total
    contextual_risk = min(
        100.0,
        round(
            signal_total + correlation_bonus,
            2,
        ),
    )

    if structural_risk and contextual_risk:
        calibrated_risk_score = min(
            100.0,
            round(
                max(
                    structural_risk,
                    contextual_risk,
                )
                + min(
                    15.0,
                    min(
                        structural_risk,
                        contextual_risk,
                    ) * 0.25,
                ),
                2,
            ),
        )
    else:
        calibrated_risk_score = round(
            max(
                structural_risk,
                contextual_risk,
            ),
            2,
        )

    return {
        "anomaly_contributions": anomaly_contributions,
        "signal_contributions": signal_contributions,
        "anomaly_weight_total": anomaly_total,
        "signal_weight_total": signal_total,
        "correlation_bonus": round(
            correlation_bonus,
            2,
        ),
        "structural_risk": round(
            structural_risk,
            2,
        ),
        "contextual_risk": round(
            contextual_risk,
            2,
        ),
        "calibrated_risk_score": round(
            calibrated_risk_score,
            2,
        ),
        "evidence_quality": evidence_quality,
        "weighted_evidence_confidence": (
            weighted_evidence_confidence
        ),
        "evidence_count": len(
            evidence_quality
        ),
        "calibration_method": (
            "max_dimension_with_bounded_"
            "cross_dimension_synergy"
        ),
    }


def _build_analyst_summary(
    hijacking_assessment: dict[str, Any],
    risk_breakdown: dict[str, Any],
) -> dict[str, Any]:

    verdict = str(
        hijacking_assessment.get(
            "verdict",
            "NO_HIJACK_INDICATORS",
        )
    )

    calibrated_risk = float(
        risk_breakdown.get(
            "calibrated_risk_score",
            0.0,
        )
        or 0.0
    )

    if verdict == "POTENTIAL_CONVERSATION_HIJACK":
        priority = "IMMEDIATE_REVIEW"
    elif calibrated_risk >= 70:
        priority = "HIGH_PRIORITY"
    elif calibrated_risk >= 35:
        priority = "REVIEW"
    elif calibrated_risk > 0:
        priority = "LOW_PRIORITY"
    else:
        priority = "NO_ACTION"

    top_signals = sorted(
        risk_breakdown.get(
            "signal_contributions",
            [],
        ),
        key=lambda item: item.get(
            "calibrated_contribution",
            0.0,
        ),
        reverse=True,
    )[:5]

    top_anomalies = sorted(
        risk_breakdown.get(
            "anomaly_contributions",
            [],
        ),
        key=lambda item: item.get(
            "calibrated_contribution",
            0.0,
        ),
        reverse=True,
    )[:5]

    if verdict == "POTENTIAL_CONVERSATION_HIJACK":
        explanation = (
            "Correlated participant, reply-target, and context indicators "
            "support a potential conversation-hijacking assessment."
        )
    elif calibrated_risk >= 35:
        explanation = (
            "Conversation-level structural or contextual anomalies "
            "require analyst review."
        )
    else:
        explanation = (
            "No material conversation-level hijacking risk was identified."
        )

    verification_steps: list[str] = []

    if top_anomalies:
        verification_steps.append(
            "Validate the highest-weight structural anomalies against raw message headers."
        )

    if top_signals:
        verification_steps.append(
            "Verify the highest-weight contextual signals against the preceding conversation."
        )

    if verdict == "POTENTIAL_CONVERSATION_HIJACK":
        verification_steps.append(
            "Confirm payment, credential, access, or sensitive-data instructions through an independent channel."
        )

    if not verification_steps:
        verification_steps.append(
            "No additional conversation-level verification is required from this module alone."
        )

    return {
        "priority": priority,
        "verdict": verdict,
        "severity": hijacking_assessment.get(
            "severity",
            "INFO",
        ),
        "risk_score": round(
            calibrated_risk,
            2,
        ),
        "hijacking_risk_score": round(
            float(
                hijacking_assessment.get(
                    "risk_score",
                    0.0,
                )
                or 0.0
            ),
            2,
        ),
        "structural_risk": risk_breakdown.get(
            "structural_risk",
            0.0,
        ),
        "contextual_risk": risk_breakdown.get(
            "contextual_risk",
            0.0,
        ),
        "evidence_count": risk_breakdown.get(
            "evidence_count",
            0,
        ),
        "correlated_detection": bool(
            hijacking_assessment.get(
                "correlated_detection",
                False,
            )
        ),
        "top_signal_contributors": top_signals,
        "top_structural_contributors": top_anomalies,
        "explanation": explanation,
        "verification_steps": verification_steps,
    }

def analyze_thread(
    messages: Any,
) -> ThreadAnalysisResult:
    items = _bounded_messages(messages)
    records = _build_message_records(items)
    reconstruction = _reconstruct_thread(records)

    evidence: list[ThreadEvidence] = []
    anomalies: list[dict[str, Any]] = []

    duplicate_ids = [
        value
        for value, count in Counter(
            record["message_id"]
            for record in records
            if record["message_id"]
        ).items()
        if count > 1
    ]

    if duplicate_ids:
        anomalies.append(
            {
                "type": "DUPLICATE_MESSAGE_ID",
                "severity": "HIGH",
                "count": len(duplicate_ids),
                "message_ids": duplicate_ids[:50],
            }
        )

        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_DUPLICATE_MESSAGE_ID",
                category="identity_integrity",
                severity="HIGH",
                confidence=0.99,
                description=(
                    "Duplicate Message-ID values were observed "
                    "within the supplied conversation."
                ),
                details={
                    "message_ids": duplicate_ids[:50],
                },
            )
        )

    missing_parent_links = reconstruction[
        "missing_parent_links"
    ]

    if missing_parent_links:
        anomalies.append(
            {
                "type": "MISSING_PARENT_LINK",
                "severity": "MEDIUM",
                "count": len(missing_parent_links),
            }
        )

        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_MISSING_PARENT_LINK",
                category="thread_continuity",
                severity="MEDIUM",
                confidence=0.94,
                description=(
                    "A reply/reference points to a message "
                    "that is not present in the supplied thread."
                ),
                details={
                    "links": missing_parent_links[:50],
                },
            )
        )

    reference_conflicts = reconstruction[
        "reference_conflicts"
    ]

    if reference_conflicts:
        anomalies.append(
            {
                "type": "REFERENCE_CHAIN_CONFLICT",
                "severity": "MEDIUM",
                "count": len(reference_conflicts),
            }
        )

        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_REFERENCE_CONFLICT",
                category="thread_continuity",
                severity="MEDIUM",
                confidence=0.91,
                description=(
                    "In-Reply-To and References headers "
                    "contain inconsistent parent information."
                ),
                details={
                    "conflicts": reference_conflicts[:50],
                },
            )
        )

    cycles = reconstruction["cycles"]

    if cycles:
        anomalies.append(
            {
                "type": "THREAD_GRAPH_CYCLE",
                "severity": "HIGH",
                "count": len(cycles),
            }
        )

        evidence.append(
            ThreadEvidence(
                evidence_id="THREAD_GRAPH_CYCLE",
                category="thread_integrity",
                severity="HIGH",
                confidence=0.98,
                description=(
                    "The reconstructed message relationship graph "
                    "contains a cycle."
                ),
                details={
                    "cycles": cycles[:20],
                },
            )
        )

    subject_info = _subject_lineage(records)
    sender_info = _sender_lineage(records)

    if (
        subject_info["subject_transition_count"] > 0
        and len(records) >= 3
    ):
        anomalies.append(
            {
                "type": "SUBJECT_LINEAGE_CHANGE",
                "severity": "LOW",
                "count": subject_info[
                    "subject_transition_count"
                ],
            }
        )

    sender_churn = sender_info["sender_transition_count"]

    if sender_churn >= 3:
        anomalies.append(
            {
                "type": "HIGH_SENDER_CHURN",
                "severity": "MEDIUM",
                "count": sender_churn,
            }
        )

    churn = _participant_churn(records)
    reply_targets = _reply_target_analysis(records)
    context_shift = _context_shift_analysis(records)
    quoted_analysis = _quoted_context_analysis(records)
    role_analysis = _role_switch_analysis(records)

    (
        hijacking_assessment,
        hijack_signals,
        hijack_evidence,
    ) = _build_hijacking_assessment(
        records,
        churn,
        reply_targets,
        context_shift,
        quoted_analysis,
        role_analysis,
    )

    evidence.extend(hijack_evidence)

    # --------------------------------------------------------
    # Step 4 — SOC evidence/risk calibration
    # --------------------------------------------------------

    risk_breakdown = _calibrate_risk_breakdown(
        anomalies=anomalies,
        hijacking_assessment=hijacking_assessment,
        evidence=evidence,
    )

    analyst_summary = _build_analyst_summary(
        hijacking_assessment=hijacking_assessment,
        risk_breakdown=risk_breakdown,
    )

    if context_shift["count"] > 0:
        anomalies.append(
            {
                "type": "THREAD_CONTEXT_SHIFT",
                "severity": "HIGH",
                "count": context_shift["count"],
            }
        )

    if churn["participant_injection_count"] > 0:
        anomalies.append(
            {
                "type": "THREAD_PARTICIPANT_CHURN",
                "severity": "LOW",
                "count": churn[
                    "participant_injection_count"
                ],
            }
        )

    if reply_targets["count"] > 0:
        anomalies.append(
            {
                "type": "THREAD_REPLY_TARGET_CHANGE",
                "severity": "MEDIUM",
                "count": reply_targets["count"],
            }
        )

    if quoted_analysis["count"] > 0:
        anomalies.append(
            {
                "type": "THREAD_QUOTED_CONTEXT_MISMATCH",
                "severity": "MEDIUM",
                "count": quoted_analysis[
                    "count"
                ],
            }
        )

    participant_graph = _participant_graph(items)

    quoted_messages = sum(
        1
        for record in records
        if record["quoted_context"][
            "quoted_content_detected"
        ]
    )

    observed_ids = reconstruction[
        "observed_message_ids"
    ]

    root_ids = reconstruction["root_message_ids"]

    root_message_id = (
        root_ids[0]
        if root_ids
        else (
            observed_ids[0]
            if observed_ids
            else ""
        )
    )

    latest_message_id = (
        records[-1]["message_id"]
        if records
        else ""
    )

    continuity = {
        "message_id_count": len(observed_ids),
        "duplicate_message_id_count": len(duplicate_ids),
        "missing_parent_link_count": len(
            missing_parent_links
        ),
        "reference_conflict_count": len(
            reference_conflicts
        ),
        "cycle_count": len(cycles),
        "root_count": len(root_ids),
        "orphan_count": len(
            reconstruction["orphan_message_ids"]
        ),
        "message_order_preserved": True,
        "canonical_parent_links": len(
            reconstruction["parent_by_child"]
        ),
        "participant_injection_count": churn[
            "participant_injection_count"
        ],
        "external_boundary_changes": churn[
            "external_boundary_changes"
        ],
        "unexpected_reply_target_changes": reply_targets[
            "count"
        ],
        "context_shift_count": context_shift[
            "count"
        ],
    }

    score = 0.0

    severity_weights = {
        "HIGH": 35.0,
        "MEDIUM": 18.0,
        "LOW": 7.0,
    }

    for anomaly in anomalies:
        score += severity_weights.get(
            anomaly.get("severity"),
            0.0,
        )

    # Hijacking assessment is already independently bounded.
    # Give its score influence without double-counting every signal.
    score += hijacking_assessment["risk_score"] * 0.35

    score = min(round(score, 2), 100.0)

    evidence_count = len(evidence)

    if not records:
        confidence = 0.10
    elif evidence_count == 0:
        confidence = 0.95
    else:
        confidence = min(
            0.99,
            round(
                0.72 + (min(evidence_count, 5) * 0.05),
                2,
            ),
        )

    actions: list[str] = []

    if duplicate_ids:
        actions.append(
            "Investigate duplicate Message-ID values for possible thread identity manipulation."
        )

    if missing_parent_links:
        actions.append(
            "Verify missing parent messages and preserve the original message source."
        )

    if reference_conflicts:
        actions.append(
            "Compare In-Reply-To and References headers against the raw message headers."
        )

    if cycles:
        actions.append(
            "Treat the reconstructed conversation graph as structurally inconsistent and review raw headers."
        )

    if churn["external_boundary_changes"] > 0:
        actions.append(
            "Validate newly introduced participant domains before trusting later thread instructions."
        )

    if context_shift["count"] > 0:
        actions.append(
            "Review the first message introducing the new high-risk request context against the preceding conversation."
        )

    if reply_targets["count"] > 0:
        actions.append(
            "Verify later reply recipients against the original conversation participants."
        )

    if hijacking_assessment["verdict"] == "POTENTIAL_CONVERSATION_HIJACK":
        actions.append(
            "Escalate the conversation for manual verification before acting on payment, credential, access, or sensitive-information requests."
        )

    if not actions:
        actions.append(
            "No structural thread integrity action is required from this module alone."
        )

    return ThreadAnalysisResult(
        thread_identity={
            "module": MODULE_NAME,
            "root_message_id": root_message_id,
            "root_message_ids": root_ids[:MAX_MESSAGES],
            "latest_message_id": latest_message_id,
            "normalized_subject": (
                records[0]["subject"]
                if records
                else ""
            ),
            "message_count": len(records),
        },
        thread_depth=len(records),
        participant_graph=participant_graph,
        continuity=continuity,
        quoted_context={
            "messages_with_quoted_content": quoted_messages,
            "per_message": [
                record["quoted_context"]
                for record in records
            ][:MAX_MESSAGES],
        },
        anomalies=anomalies[:MAX_ANOMALIES],
        thread_risk_score=score,
        confidence=confidence,
        evidence=evidence[:MAX_EVIDENCE],
        recommended_actions=actions,
        analysis_version=ANALYSIS_VERSION,
        static_only=STATIC_ONLY,
        hijacking_assessment=hijacking_assessment,
        risk_breakdown=risk_breakdown,
        analyst_summary=analyst_summary,
    )


def analyze_thread_to_dict(
    messages: Any,
) -> dict[str, Any]:
    return analyze_thread(messages).to_dict()
