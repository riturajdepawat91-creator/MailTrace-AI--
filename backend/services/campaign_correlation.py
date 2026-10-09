"""Evidence-based cross-investigation campaign correlation.

Only threat-intelligence-backed indicators and explicit campaign labels are
used as links. Sender domains and subjects are intentionally not correlation
signals because they create noisy, misleading clusters.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any


def _analysis_for(investigation: dict[str, Any]) -> dict[str, Any]:
    analysis = investigation.get("analysis")
    if isinstance(analysis, dict):
        return analysis
    raw = investigation.get("analysis_json") or "{}"
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _matched_indicators(analysis: dict[str, Any]) -> dict[str, set[str]]:
    """Return normalized IOC -> display-value map only for known TI matches."""
    intelligence = analysis.get("threat_intelligence") or {}
    matches = intelligence.get("matches") or {}
    if not isinstance(matches, dict):
        return {}

    ioc_types = {}
    for item in intelligence.get("iocs") or []:
        if isinstance(item, dict) and item.get("ioc"):
            ioc_types[str(item["ioc"]).strip().casefold()] = str(
                item.get("ioc_type") or "unknown"
            ).casefold()

    result: dict[str, set[str]] = defaultdict(set)
    for raw_ioc, records in matches.items():
        if not raw_ioc or not records:
            continue
        normalized = str(raw_ioc).strip().casefold().rstrip(".")
        if not normalized:
            continue
        # Ignore ubiquitous identity and cloud-provider domains. They are poor
        # campaign evidence even if present in an intelligence feed.
        ioc_type = ioc_types.get(normalized, "")
        if ioc_type in {"domain", "url"} and re.search(
            r"(^|\.)(gmail\.com|google\.com|microsoft\.com|outlook\.com|"
            r"office\.com|office365\.com|amazonaws\.com|cloudfront\.net|"
            r"azureedge\.net|windows\.net|linkedin\.com|facebook\.com)$",
            normalized,
        ):
            continue
        result[normalized].add(str(raw_ioc).strip())
    return dict(result)


def _explicit_campaign_labels(analysis: dict[str, Any]) -> dict[str, str]:
    matches = (analysis.get("threat_intelligence") or {}).get("matches") or {}
    labels: dict[str, str] = {}
    if not isinstance(matches, dict):
        return labels
    for records in matches.values():
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            continue
        for record in records:
            if isinstance(record, dict) and record.get("campaign"):
                label = re.sub(r"\s+", " ", str(record["campaign"]).strip())
                if label:
                    labels.setdefault(label.casefold(), label)
    return labels


def _severity(investigation: dict[str, Any]) -> str:
    score = _score(investigation)
    verdict = str(investigation.get("threat_verdict") or "").upper()
    if score >= 90 or verdict == "CRITICAL":
        return "CRITICAL"
    if score >= 70 or verdict in {"HIGH", "HIGH RISK"}:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _score(investigation: dict[str, Any]) -> int:
    try:
        return max(0, min(100, int(float(investigation.get("threat_score") or 0))))
    except (TypeError, ValueError):
        return 0


def _date_key(value: Any) -> str:
    if not value:
        return ""
    return str(value)


def _shared_indicator_type(component: set[str], indicator: str, nodes: dict[str, dict[str, Any]]) -> str:
    for investigation_id in sorted(component):
        analysis = _analysis_for(nodes[investigation_id]["item"])
        for item in (analysis.get("threat_intelligence") or {}).get("iocs") or []:
            if isinstance(item, dict) and str(item.get("ioc") or "").strip().casefold().rstrip(".") == indicator:
                return str(item.get("ioc_type") or "unknown")
    return "unknown"


def correlate_campaigns(investigations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build stable, explainable campaign clusters from actual shared evidence."""
    nodes: dict[str, dict[str, Any]] = {}
    ioc_members: dict[str, set[str]] = defaultdict(set)
    label_members: dict[str, set[str]] = defaultdict(set)
    ioc_display: dict[str, set[str]] = defaultdict(set)
    label_display: dict[str, str] = {}

    for item in investigations:
        investigation_id = str(item.get("investigation_id") or "").strip()
        if not investigation_id:
            continue
        analysis = _analysis_for(item)
        indicators = _matched_indicators(analysis)
        labels = _explicit_campaign_labels(analysis)
        nodes[investigation_id] = {"item": item, "indicators": set(indicators), "labels": set(labels)}
        for key, displays in indicators.items():
            ioc_members[key].add(investigation_id)
            ioc_display[key].update(displays)
        for label, display in labels.items():
            label_members[label].add(investigation_id)
            label_display.setdefault(label, display)

    # Build connected components through repeat intel-backed indicators or
    # shared feed campaign labels. A lone email never becomes a campaign.
    graph: dict[str, set[str]] = defaultdict(set)

    def connect_members(members: set[str]) -> None:
        """Connect a shared-evidence group with O(n) edges, not a full clique."""
        ordered = sorted(members)
        if len(ordered) < 2:
            return
        anchor = ordered[0]
        for member in ordered[1:]:
            graph[anchor].add(member)
            graph[member].add(anchor)

    for members in ioc_members.values():
        connect_members(members)
    for members in label_members.values():
        connect_members(members)

    clusters = []
    visited: set[str] = set()
    for seed in sorted(graph):
        if seed in visited:
            continue
        stack = [seed]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            stack.extend(graph[current] - component)
        visited.update(component)
        if len(component) < 2:
            continue

        shared_iocs = sorted(
            indicator for indicator, members in ioc_members.items()
            if len(members.intersection(component)) > 1
        )
        shared_labels = sorted(
            label for label, members in label_members.items()
            if len(members.intersection(component)) > 1
        )
        if not shared_iocs and not shared_labels:
            continue

        members = [nodes[key]["item"] for key in sorted(component)]
        all_scores = [_score(member) for member in members]
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        severity = max((_severity(member) for member in members), key=severity_order.get)
        canonical_evidence = "|".join(shared_iocs + [f"campaign:{label}" for label in shared_labels])
        canonical_members = "|".join(sorted(component))
        digest = hashlib.sha256(f"{canonical_members}|{canonical_evidence}".encode()).hexdigest()[:12].upper()
        if shared_labels:
            name = f"Threat campaign: {label_display[shared_labels[0]]}"
        else:
            name = f"Correlated threat activity · {sorted(ioc_display[shared_iocs[0]])[0]}"
        evidence_parts = []
        if shared_iocs:
            evidence_parts.append(f"{len(shared_iocs)} shared threat-intelligence indicator(s)")
        if shared_labels:
            evidence_parts.append(f"known campaign label: {label_display[shared_labels[0]]}")
        clusters.append({
            "campaign_id": f"CMP-{digest}",
            "name": name,
            "severity": severity,
            "description": "Linked by " + " and ".join(evidence_parts) + ".",
            "correlation_reason": "; ".join(evidence_parts),
            "shared_indicators": [
                {"value": sorted(ioc_display[ioc])[0], "type": _shared_indicator_type(component, ioc, nodes)}
                for ioc in shared_iocs
            ],
            "email_count": len(members),
            "indicator_count": len(shared_iocs),
            "status": "ACTIVE",
            "threat_score": max(all_scores, default=0),
            "created_at": max((_date_key(member.get("created_at")) for member in members), default=""),
            "investigation_ids": sorted(component),
            "investigations": [{
                "investigation_id": member.get("investigation_id", ""),
                "subject": member.get("subject") or "No Subject",
                "sender": member.get("sender") or "Unknown",
                "recipient": member.get("recipient") or "Unknown",
                "threat_score": _score(member),
                "threat_verdict": str(member.get("threat_verdict") or "UNKNOWN").upper(),
                "threat_confidence": member.get("threat_confidence") or "UNKNOWN",
                "created_at": member.get("created_at") or "",
                "status": "OPEN",
            } for member in members],
        })

    return sorted(clusters, key=lambda campaign: (campaign["threat_score"], campaign["email_count"]), reverse=True)
