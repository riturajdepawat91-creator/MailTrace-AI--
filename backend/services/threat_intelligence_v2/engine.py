from collections import Counter
from datetime import datetime, timezone
import hashlib


from services.detection_correlation import correlate_detections
from services.incident_management import manage_incidents
SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10,
    "UNKNOWN": 0
}


IOC_TYPE_WEIGHTS = {
    "hash": 1.30,
    "sha256": 1.30,
    "sha1": 1.25,
    "md5": 1.20,

    "url": 1.20,
    "ip:port": 1.18,
    "domain": 1.12,
    "ip": 1.08,
    "email": 1.00,

    "unknown": 0.90
}


from services.investigation_management import investigate_incidents

def _severity_from_score(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def _safe_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


SOURCE_RELIABILITY_PROFILES = {
    "virustotal": {"reliability": 0.96, "family": "commercial-intel"},
    "abuseipdb": {"reliability": 0.92, "family": "abuse-reporting"},
    "spamhaus": {"reliability": 0.95, "family": "reputation-feed"},
    "greynoise": {"reliability": 0.93, "family": "network-observation"},
    "talos": {"reliability": 0.94, "family": "commercial-intel"},
    "microsoft": {"reliability": 0.96, "family": "vendor-intel"},
    "google": {"reliability": 0.96, "family": "vendor-intel"},
    "otx": {"reliability": 0.84, "family": "community-intel"},
    "alienvault": {"reliability": 0.84, "family": "community-intel"},
    "urlhaus": {"reliability": 0.88, "family": "community-feed"},
    "phishtank": {"reliability": 0.82, "family": "community-feed"},
    "misp": {"reliability": 0.90, "family": "sharing-platform"},
    "crowdsec": {"reliability": 0.84, "family": "community-intel"},
}

def _normalize_source_name(source):
    value = str(source or "").strip().lower()
    return " ".join(value.split())

def _source_profile(source):
    normalized = _normalize_source_name(source)

    for key, profile in SOURCE_RELIABILITY_PROFILES.items():
        if key in normalized:
            return {
                "source": normalized or "unknown",
                "reliability": float(profile["reliability"]),
                "family": profile["family"],
            }

    return {
        "source": normalized or "unknown",
        "reliability": 0.55,
        "family": "unknown",
    }


def _parse_evidence_timestamp(value):
    if value is None:
        return None

    try:
        from datetime import datetime, timezone

        text = str(value).strip()

        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def _evidence_temporal_profile(record, now=None):
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)

    # Stable contract for every evidence record.
    # Unknown timestamps are conservative and never raise.
    if not isinstance(record, dict):
        return {
            "temporal_status": "UNKNOWN",
            "age_hours": None,
            "freshness_factor": 0.50,
            "timestamp_source": None,
        }

    timestamp_candidates = (
        ("last_seen", record.get("last_seen")),
        ("updated_at", record.get("updated_at")),
        ("first_seen", record.get("first_seen")),
    )

    selected_name = None
    selected_time = None

    for name, value in timestamp_candidates:
        parsed = _parse_evidence_timestamp(value)

        if parsed is not None:
            selected_name = name
            selected_time = parsed
            break

    if selected_time is None:
        return {
            "temporal_status": "UNKNOWN",
            "age_hours": None,
            "freshness_factor": 0.50,
            "timestamp_source": None,
        }

    age_hours = max(
        0.0,
        (now - selected_time).total_seconds() / 3600.0
    )

    # Authoritative semantic freshness classification.
    if age_hours <= 24.0:
        freshness_factor = 1.00
        temporal_status = "FRESH"

    elif age_hours <= 72.0:
        freshness_factor = 0.95
        temporal_status = "RECENT"

    elif age_hours <= 168.0:
        freshness_factor = 0.88
        temporal_status = "CURRENT"

    elif age_hours <= 720.0:
        freshness_factor = 0.72
        temporal_status = "AGING"

    elif age_hours <= 2160.0:
        freshness_factor = 0.55
        temporal_status = "STALE"

    else:
        freshness_factor = 0.40
        temporal_status = "HISTORICAL"

    return {
        "temporal_status": temporal_status,
        "age_hours": round(age_hours, 2),
        "freshness_factor": freshness_factor,
        "timestamp_source": selected_name,
    }


def _evaluate_source_evidence(matched_records):
    records = matched_records if isinstance(matched_records, list) else []

    unique_records = []
    fingerprints = set()
    duplicate_count = 0

    source_names = set()
    source_families = set()
    source_reliabilities = []

    for record in records:
        if not isinstance(record, dict):
            continue

        source = record.get("source") or record.get("feed") or "unknown"
        profile = _source_profile(source)

        source_names.add(profile["source"])
        source_families.add(profile["family"])
        source_reliabilities.append(profile["reliability"])

        fingerprint = (
            profile["source"],
            str(record.get("threat_type") or "").strip().lower(),
            str(record.get("malware") or "").strip().lower(),
            str(record.get("reference") or "").strip().lower(),
            str(record.get("verdict") or record.get("result") or "").strip().lower(),
        )

        if fingerprint in fingerprints:
            duplicate_count += 1
            continue

        fingerprints.add(fingerprint)
        unique_records.append(record)

    average_reliability = (
        sum(source_reliabilities) / len(source_reliabilities)
        if source_reliabilities
        else 0.55
    )

    independent_source_count = len(
        {family for family in source_families if family != "unknown"}
    )

    unknown_family_present = "unknown" in source_families

    reliability_grade = (
        "VERY_HIGH" if average_reliability >= 0.92
        else "HIGH" if average_reliability >= 0.82
        else "MODERATE" if average_reliability >= 0.68
        else "LOW"
    )

    evidence_diversity = min(
        round(
            independent_source_count / max(len(source_names), 1),
            3,
        ),
        1.0,
    )

    return {
        "unique_records": unique_records,
        "unique_evidence_count": len(unique_records),
        "duplicate_evidence_count": duplicate_count,
        "source_names": sorted(source_names),
        "independent_source_count": independent_source_count,
        "source_families": sorted(source_families),
        "unknown_source_family": unknown_family_present,
        "source_reliability": round(average_reliability, 3),
        "source_reliability_grade": reliability_grade,
        "evidence_diversity": evidence_diversity,
    }

def _evidence_verdict_profile(records):
    """
    Return conservative explicit verdict telemetry for raw evidence.

    UNKNOWN never becomes BENIGN. Only explicit contradictory
    polarity is treated as a conflict signal.
    """
    records = records if isinstance(records, list) else []

    malicious_values = {
        "malicious",
        "malware",
        "phishing",
        "blacklisted",
        "blocked",
        "hostile",
        "compromised",
        "bad",
        "badware",
        "threat",
        "malicious_ip",
        "malicious_url",
        "malicious_domain",
    }

    benign_values = {
        "benign",
        "clean",
        "safe",
        "harmless",
        "legitimate",
        "trusted",
        "good",
        "no_threat",
        "not_malicious",
    }

    suspicious_values = {
        "suspicious",
        "questionable",
        "likely_malicious",
        "potentially_malicious",
        "gray",
        "grey",
    }

    counts = {
        "MALICIOUS": 0,
        "BENIGN": 0,
        "SUSPICIOUS": 0,
        "UNKNOWN": 0,
    }

    seen = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        source = str(
            record.get("source")
            or record.get("feed")
            or "unknown"
        ).strip().lower()

        verdict_raw = (
            record.get("verdict")
            or record.get("result")
            or record.get("classification")
            or record.get("status")
            or record.get("detection")
            or record.get("threat_type")
        )

        normalized = (
            str(verdict_raw or "")
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )

        if normalized in malicious_values:
            verdict = "MALICIOUS"
        elif normalized in benign_values:
            verdict = "BENIGN"
        elif normalized in suspicious_values:
            verdict = "SUSPICIOUS"
        else:
            verdict = "UNKNOWN"

        fingerprint = (
            source,
            verdict,
            str(record.get("reference") or "").strip().lower(),
            str(record.get("threat_type") or "").strip().lower(),
            str(record.get("malware") or "").strip().lower(),
        )

        if fingerprint in seen:
            continue

        seen.add(fingerprint)
        counts[verdict] += 1

    return {
        "verdict_counts": counts,
        "explicit_conflict": (
            counts["MALICIOUS"] > 0
            and counts["BENIGN"] > 0
        ),
        "known_positive": (
            counts["MALICIOUS"]
            + counts["SUSPICIOUS"]
        ),
        "known_negative": counts["BENIGN"],
    }


def _build_campaign_graph(
    correlation_map,
    matches
):
    """
    Build deterministic graph-ready IOC relationships from
    already-enriched Threat Intelligence V2 evidence.

    This is an enrichment layer only:
    - no existing IOC field is removed
    - no existing relationship is discarded
    - duplicate pair relationships are collapsed
    - graph confidence is bounded to 0..1
    """

    if not isinstance(correlation_map, dict):
        correlation_map = {}

    if not isinstance(matches, dict):
        matches = {}

    relationship_weights = {
        "shared_campaign": 1.00,
        "shared_actor": 0.95,
        "url_domain": 0.95,
        "shared_malware": 0.85,
        "shared_mitre": 0.80,
        "shared_threat_source": 0.60,
    }

    strong_relationships = {
        "shared_campaign",
        "shared_actor",
        "url_domain",
        "shared_malware",
        "shared_mitre",
    }

    nodes = {}
    evidence_metadata = {}

    # -----------------------------------------------------
    # Deterministic node construction.
    # -----------------------------------------------------

    for key, item in correlation_map.items():

        if not isinstance(item, dict):
            continue

        indicator = item.get("indicator") or key

        if not indicator:
            continue

        indicator = str(indicator)

        nodes[indicator] = {
            "id": indicator,
            "indicator": indicator,
            "type": str(
                item.get(
                    "type",
                    "unknown"
                )
            ).lower(),
            "risk_score": round(
                float(
                    item.get(
                        "risk_score",
                        0
                    ) or 0
                ),
                2
            ),
            "severity": item.get(
                "severity",
                "INFO"
            ),
            "confidence": round(
                float(
                    item.get(
                        "confidence",
                        0
                    ) or 0
                ),
                3
            ),
            "sources": sorted(
                set(
                    str(source)
                    for source in _safe_list(
                        item.get("sources")
                    )
                    if source
                )
            ),
            "mitre_attack": sorted(
                set(
                    str(technique)
                    for technique in _safe_list(
                        item.get("mitre_attack")
                    )
                    if technique
                )
            )
        }

        raw_records = _safe_list(
            matches.get(
                key,
                matches.get(
                    indicator,
                    []
                )
            )
        )

        campaigns = set()
        actors = set()
        malware = set()
        kill_chain = set()

        for record in raw_records:

            if not isinstance(record, dict):
                continue

            for field, target in (
                ("campaign", campaigns),
                ("campaign_id", campaigns),
                ("actor", actors),
                ("threat_actor", actors),
                ("malware", malware),
                ("family", malware),
                ("kill_chain", kill_chain),
            ):

                value = record.get(field)

                for candidate in _safe_list(value):

                    if candidate:
                        target.add(
                            str(candidate).strip()
                        )

        evidence_metadata[indicator] = {
            "campaigns": sorted(campaigns),
            "actors": sorted(actors),
            "malware": sorted(malware),
            "kill_chain": sorted(kill_chain)
        }

    # -----------------------------------------------------
    # Pairwise relationship construction.
    # -----------------------------------------------------

    sorted_indicators = sorted(
        nodes.keys(),
        key=lambda value: str(value).lower()
    )

    edges_by_key = {}

    def add_edge(
        source,
        target,
        relationship,
        evidence
    ):

        if source == target:
            return

        if not source or not target:
            return

        pair = tuple(
            sorted(
                (
                    str(source),
                    str(target)
                ),
                key=lambda value: value.lower()
            )
        )

        edge_key = (
            pair[0],
            pair[1],
            relationship
        )

        weight = relationship_weights.get(
            relationship,
            0.50
        )

        existing = edges_by_key.get(
            edge_key
        )

        if existing is None:

            edges_by_key[edge_key] = {
                "source": pair[0],
                "target": pair[1],
                "relationship": relationship,
                "strength": (
                    "HIGH"
                    if weight >= 0.90
                    else (
                        "MEDIUM"
                        if weight >= 0.75
                        else "LOW"
                    )
                ),
                "confidence": round(
                    weight,
                    3
                ),
                "evidence": sorted(
                    set(
                        str(value)
                        for value in _safe_list(
                            evidence
                        )
                        if value
                    )
                )
            }

        else:

            existing["evidence"] = sorted(
                set(
                    existing.get(
                        "evidence",
                        []
                    )
                    + [
                        str(value)
                        for value in _safe_list(
                            evidence
                        )
                        if value
                    ]
                )
            )

    # -----------------------------------------------------
    # URL -> Domain infrastructure relation.
    # -----------------------------------------------------

    for source in sorted_indicators:

        source_type = nodes[
            source
        ].get(
            "type",
            "unknown"
        )

        if source_type != "url":
            continue

        source_lower = source.lower()

        for target in sorted_indicators:

            if target == source:
                continue

            target_type = nodes[
                target
            ].get(
                "type",
                "unknown"
            )

            if target_type != "domain":
                continue

            target_lower = target.lower()

            if target_lower and target_lower in source_lower:

                add_edge(
                    source,
                    target,
                    "url_domain",
                    [
                        "url_contains_domain"
                    ]
                )

    # -----------------------------------------------------
    # Shared evidence dimensions.
    # -----------------------------------------------------

    dimension_maps = {
        "shared_campaign": {},
        "shared_actor": {},
        "shared_malware": {},
    }

    for indicator in sorted_indicators:

        metadata = evidence_metadata.get(
            indicator,
            {}
        )

        for relationship, field in (
            (
                "shared_campaign",
                "campaigns"
            ),
            (
                "shared_actor",
                "actors"
            ),
            (
                "shared_malware",
                "malware"
            ),
        ):

            for value in metadata.get(
                field,
                []
            ):

                if not value:
                    continue

                dimension_maps[
                    relationship
                ].setdefault(
                    str(value).lower(),
                    []
                ).append(
                    indicator
                )

    for relationship, value_map in (
        dimension_maps.items()
    ):

        for shared_value, related in sorted(
            value_map.items()
        ):

            unique_related = sorted(
                set(
                    related
                ),
                key=lambda value:
                value.lower()
            )

            if len(unique_related) < 2:
                continue

            for index, source in enumerate(
                unique_related
            ):

                for target in unique_related[
                    index + 1:
                ]:

                    add_edge(
                        source,
                        target,
                        relationship,
                        [
                            shared_value
                        ]
                    )

    # -----------------------------------------------------
    # Shared MITRE relationship.
    # -----------------------------------------------------

    mitre_map = {}

    for indicator in sorted_indicators:

        for technique in nodes[
            indicator
        ].get(
            "mitre_attack",
            []
        ):

            if not technique:
                continue

            mitre_map.setdefault(
                str(technique).lower(),
                []
            ).append(
                indicator
            )

    for technique, related in sorted(
        mitre_map.items()
    ):

        unique_related = sorted(
            set(
                related
            ),
            key=lambda value:
            value.lower()
        )

        if len(unique_related) < 2:
            continue

        for index, source in enumerate(
            unique_related
        ):

            for target in unique_related[
                index + 1:
            ]:

                add_edge(
                    source,
                    target,
                    "shared_mitre",
                    [
                        technique
                    ]
                )

    # -----------------------------------------------------
    # Shared threat source relationship.
    # -----------------------------------------------------

    source_map = {}

    for indicator in sorted_indicators:

        for source in nodes[
            indicator
        ].get(
            "sources",
            []
        ):

            if not source:
                continue

            source_map.setdefault(
                str(source).lower(),
                []
            ).append(
                indicator
            )

    for shared_source, related in sorted(
        source_map.items()
    ):

        unique_related = sorted(
            set(
                related
            ),
            key=lambda value:
            value.lower()
        )

        if len(unique_related) < 2:
            continue

        for index, source in enumerate(
            unique_related
        ):

            for target in unique_related[
                index + 1:
            ]:

                add_edge(
                    source,
                    target,
                    "shared_threat_source",
                    [
                        shared_source
                    ]
                )

    edges = sorted(
        edges_by_key.values(),
        key=lambda edge: (
            edge.get(
                "source",
                ""
            ).lower(),
            edge.get(
                "target",
                ""
            ).lower(),
            edge.get(
                "relationship",
                ""
            )
        )
    )

    # -----------------------------------------------------
    # Connected components / campaign clusters.
    # -----------------------------------------------------

    parent = {
        indicator: indicator
        for indicator in sorted_indicators
    }

    def find(node):
        current = node

        while parent.get(
            current,
            current
        ) != current:

            parent[current] = parent.get(
                parent[current],
                parent[current]
            )

            current = parent[current]

        return current

    def union(left, right):

        left_root = find(
            left
        )

        right_root = find(
            right
        )

        if left_root == right_root:
            return

        if left_root.lower() < right_root.lower():
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    for edge in edges:

        union(
            edge.get(
                "source"
            ),
            edge.get(
                "target"
            )
        )

    component_map = {}

    for indicator in sorted_indicators:

        root = find(
            indicator
        )

        component_map.setdefault(
            root,
            []
        ).append(
            indicator
        )

    campaign_clusters = []

    for root, members in sorted(
        component_map.items(),
        key=lambda item:
        str(item[0]).lower()
    ):

        unique_members = sorted(
            set(
                members
            ),
            key=lambda value:
            value.lower()
        )

        if len(unique_members) < 2:
            continue

        cluster_edges = [
            edge
            for edge in edges
            if (
                edge.get(
                    "source"
                ) in unique_members
                and
                edge.get(
                    "target"
                ) in unique_members
            )
        ]

        strong_edges = [
            edge
            for edge in cluster_edges
            if edge.get(
                "relationship"
            ) in strong_relationships
        ]

        relationship_types = sorted(
            set(
                edge.get(
                    "relationship"
                )
                for edge in cluster_edges
                if edge.get(
                    "relationship"
                )
            )
        )

        cluster_scores = [
            float(
                nodes[
                    member
                ].get(
                    "risk_score",
                    0
                ) or 0
            )
            for member in unique_members
            if member in nodes
        ]

        cluster_confidence_values = [
            float(
                nodes[
                    member
                ].get(
                    "confidence",
                    0
                ) or 0
            )
            for member in unique_members
            if member in nodes
        ]

        avg_risk = (
            sum(
                cluster_scores
            ) / len(
                cluster_scores
            )
            if cluster_scores
            else 0.0
        )

        avg_confidence = (
            sum(
                cluster_confidence_values
            ) / len(
                cluster_confidence_values
            )
            if cluster_confidence_values
            else 0.0
        )

        edge_density = (
            len(cluster_edges)
            /
            max(
                (
                    len(unique_members)
                    * (
                        len(unique_members)
                        - 1
                    )
                    / 2.0
                ),
                1.0
            )
        )

        strong_ratio = (
            len(strong_edges)
            /
            max(
                len(cluster_edges),
                1
            )
        )

        size_factor = min(
            len(unique_members)
            / 5.0,
            1.0
        )

        campaign_confidence = (
            (
                edge_density
                * 0.25
            )
            + (
                strong_ratio
                * 0.30
            )
            + (
                min(
                    avg_risk / 100.0,
                    1.0
                )
                * 0.20
            )
            + (
                min(
                    avg_confidence,
                    1.0
                )
                * 0.15
            )
            + (
                size_factor
                * 0.10
            )
        )

        campaign_confidence = round(
            max(
                0.0,
                min(
                    campaign_confidence,
                    1.0
                )
            ),
            3
        )

        risk_level = (
            "HIGH"
            if campaign_confidence >= 0.75
            else (
                "MEDIUM"
                if campaign_confidence >= 0.45
                else "LOW"
            )
        )

        campaign_clusters.append({
            "cluster_id": (
                "campaign-"
                + str(
                    len(
                        campaign_clusters
                    ) + 1
                ).zfill(3)
            ),
            "members": unique_members,
            "size": len(
                unique_members
            ),
            "relationship_count": len(
                cluster_edges
            ),
            "strong_relationship_count": len(
                strong_edges
            ),
            "relationship_types": (
                relationship_types
            ),
            "average_risk_score": round(
                avg_risk,
                2
            ),
            "average_indicator_confidence": round(
                avg_confidence,
                3
            ),
            "campaign_confidence": (
                campaign_confidence
            ),
            "risk_level": risk_level
        })

    graph_nodes = [
        nodes[
            indicator
        ]
        for indicator in sorted(
            nodes.keys(),
            key=lambda value:
            value.lower()
        )
    ]

    graph = {
        "nodes": graph_nodes,
        "edges": edges,
        "node_count": len(
            graph_nodes
        ),
        "edge_count": len(
            edges
        ),
        "cluster_count": len(
            campaign_clusters
        )
    }

    strong_edge_count = len([
        edge
        for edge in edges
        if edge.get(
            "relationship"
        ) in strong_relationships
    ])

    overall_campaign_confidence = 0.0

    if campaign_clusters:

        overall_campaign_confidence = max(
            cluster.get(
                "campaign_confidence",
                0
            )
            for cluster in campaign_clusters
        )

    campaign_bonus = min(
        round(
            strong_edge_count * 0.75
            + len(campaign_clusters) * 0.50,
            2
        ),
        6.0
    )

    return {
        "graph": graph,
        "campaign_clusters": (
            campaign_clusters
        ),
        "campaign_confidence": round(
            overall_campaign_confidence,
            3
        ),
        "strong_relationship_count": (
            strong_edge_count
        ),
        "campaign_graph_bonus": (
            campaign_bonus
        )
    }


def _build_historical_recurrence_intelligence(
    correlation_map,
    matches
):
    """
    Historical recurrence analysis for already-enriched IOCs.

    Duplicate copies of the same observation are collapsed.
    Distinct dates/months indicate recurrence.
    Missing timestamps remain conservative.
    """

    if not isinstance(
        correlation_map,
        dict
    ):
        correlation_map = {}

    if not isinstance(
        matches,
        dict
    ):
        matches = {}

    timestamp_fields = (
        "last_seen",
        "first_seen",
        "timestamp",
        "observed_at",
        "seen_at",
        "date",
        "created_at",
        "updated_at",
    )

    def parse_timestamp(value):

        if value is None:
            return None

        if isinstance(
            value,
            datetime
        ):

            if value.tzinfo is None:
                value = value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(
                timezone.utc
            )

        raw = str(
            value
        ).strip()

        if not raw:
            return None

        normalized = raw.replace(
            "Z",
            "+00:00"
        )

        try:

            result = datetime.fromisoformat(
                normalized
            )

            if result.tzinfo is None:
                result = result.replace(
                    tzinfo=timezone.utc
                )

            return result.astimezone(
                timezone.utc
            )

        except Exception:
            pass

        formats = (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%m-%Y %H:%M:%S",
            "%d-%m-%Y",
        )

        for fmt in formats:

            try:

                return datetime.strptime(
                    raw,
                    fmt
                ).replace(
                    tzinfo=timezone.utc
                )

            except Exception:
                continue

        return None

    recurrence_map = {}

    for key, item in sorted(
        correlation_map.items(),
        key=lambda pair:
        str(pair[0]).lower()
    ):

        if not isinstance(
            item,
            dict
        ):
            continue

        indicator = (
            item.get("indicator")
            or key
        )

        if not indicator:
            continue

        indicator = str(
            indicator
        )

        records = _safe_list(
            matches.get(
                key,
                matches.get(
                    indicator,
                    []
                )
            )
        )

        raw_count = 0
        unique_observations = {}
        sources = set()

        for record in records:

            if not isinstance(
                record,
                dict
            ):
                continue

            raw_count += 1

            source = str(
                record.get(
                    "source"
                )
                or record.get(
                    "feed"
                )
                or "unknown"
            ).strip()

            if source and source.lower() != "unknown":
                sources.add(
                    source
                )

            timestamp = None

            for field in timestamp_fields:

                timestamp = parse_timestamp(
                    record.get(
                        field
                    )
                )

                if timestamp is not None:
                    break

            reference = str(
                record.get(
                    "reference"
                )
                or record.get(
                    "external_id"
                )
                or ""
            ).strip().lower()

            threat_type = str(
                record.get(
                    "threat_type"
                )
                or ""
            ).strip().lower()

            malware = str(
                record.get(
                    "malware"
                )
                or ""
            ).strip().lower()

            observation_key = (
                source.lower(),
                reference,
                threat_type,
                malware,
                (
                    timestamp.isoformat()
                    if timestamp is not None
                    else ""
                )
            )

            unique_observations.setdefault(
                observation_key,
                {
                    "timestamp": timestamp,
                    "source": source
                }
            )

        parsed = [
            item
            for item in unique_observations.values()
            if item.get(
                "timestamp"
            ) is not None
        ]

        parsed.sort(
            key=lambda item:
            (
                item.get(
                    "timestamp"
                ),
                item.get(
                    "source",
                    ""
                ).lower()
            )
        )

        dates = sorted(
            set(
                item[
                    "timestamp"
                ].date().isoformat()
                for item in parsed
            )
        )

        months = sorted(
            set(
                item[
                    "timestamp"
                ].strftime("%Y-%m")
                for item in parsed
            )
        )

        timestamps = sorted(
            set(
                item[
                    "timestamp"
                ].isoformat()
                for item in parsed
            )
        )

        first_seen = (
            parsed[0]["timestamp"].isoformat()
            if parsed
            else None
        )

        last_seen = (
            parsed[-1]["timestamp"].isoformat()
            if parsed
            else None
        )

        persistence_days = 0.0

        if len(parsed) >= 2:

            persistence_days = max(
                (
                    parsed[-1]["timestamp"]
                    -
                    parsed[0]["timestamp"]
                ).total_seconds()
                / 86400.0,
                0.0
            )

        date_count = len(
            dates
        )

        month_count = len(
            months
        )

        recurrence_count = max(
            date_count,
            month_count
        )

        recurring = (
            recurrence_count >= 2
        )

        persistent = (
            month_count >= 2
        )

        if not parsed:

            status = "NO_HISTORY"

        elif persistent:

            status = "PERSISTENT"

        elif recurring:

            status = "RECURRING"

        else:

            status = "SINGLE_PERIOD"

        recurrence_factor = min(
            recurrence_count / 4.0,
            1.0
        )

        span_factor = min(
            persistence_days / 30.0,
            1.0
        )

        source_factor = min(
            len(sources) / 3.0,
            1.0
        )

        observation_factor = min(
            len(unique_observations) / 5.0,
            1.0
        )

        confidence = (
            recurrence_factor * 0.35
            + span_factor * 0.25
            + source_factor * 0.20
            + observation_factor * 0.20
        )

        if not parsed:
            confidence = 0.0

        confidence = round(
            max(
                0.0,
                min(
                    confidence,
                    1.0
                )
            ),
            3
        )

        bonus = 0.0

        # A recurrence bonus is valid only when observations
        # span multiple distinct dates. Supporting signals
        # cannot independently manufacture recurrence.
        if recurring:

            if date_count >= 2:
                bonus += 1.0

            if date_count >= 3:
                bonus += 0.75

            if month_count >= 2:
                bonus += 0.75

            if len(sources) >= 2:
                bonus += 0.50

            if persistence_days >= 30:
                bonus += 0.50

        bonus = round(
            min(
                bonus,
                3.0
            ),
            2
        )

        recurrence_map[
            indicator
        ] = {
            "indicator": indicator,
            "raw_observation_count": raw_count,
            "unique_observation_count": len(
                unique_observations
            ),
            "distinct_timestamp_count": len(
                timestamps
            ),
            "distinct_date_count": date_count,
            "distinct_month_count": month_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "persistence_days": round(
                persistence_days,
                2
            ),
            "source_count": len(
                sources
            ),
            "sources": sorted(
                sources,
                key=lambda value:
                value.lower()
            ),
            "recurrence_count": recurrence_count,
            "status": status,
            "recurring": recurring,
            "long_term_recurrence": persistent,
            "recurrence_confidence": confidence,
            "recurrence_bonus": bonus
        }

    indicators = sorted(
        recurrence_map.keys(),
        key=lambda value:
        value.lower()
    )

    recurring_items = [
        recurrence_map[
            indicator
        ]
        for indicator in indicators
        if recurrence_map[
            indicator
        ].get(
            "recurring"
        )
    ]

    persistent_items = [
        recurrence_map[
            indicator
        ]
        for indicator in indicators
        if recurrence_map[
            indicator
        ].get(
            "long_term_recurrence"
        )
    ]

    if recurring_items:

        overall_confidence = round(
            sum(
                float(
                    item.get(
                        "recurrence_confidence",
                        0
                    ) or 0
                )
                for item in recurring_items
            )
            /
            len(recurring_items),
            3
        )

    else:

        overall_confidence = 0.0

    total_bonus = round(
        min(
            sum(
                float(
                    item.get(
                        "recurrence_bonus",
                        0
                    ) or 0
                )
                for item in recurring_items
            ),
            6.0
        ),
        2
    )

    return {
        "detected": bool(
            recurring_items
        ),
        "indicator_count": len(
            recurrence_map
        ),
        "recurring_indicator_count": len(
            recurring_items
        ),
        "persistent_indicator_count": len(
            persistent_items
        ),
        "overall_confidence": (
            overall_confidence
        ),
        "total_recurrence_bonus": (
            total_bonus
        ),
        "indicators": [
            recurrence_map[
                indicator
            ]
            for indicator in indicators
        ]
    }



# =========================================================
# SOC 9.5 INFRASTRUCTURE REUSE INTELLIGENCE
# =========================================================

def _build_infrastructure_reuse_intelligence(
    correlation_map,
    matches,
    ip_intelligence
):
    """
    Build deterministic infrastructure-reuse intelligence.

    This is an additive enrichment layer. Existing campaign
    graph / correlation behavior remains intact.
    """

    if not isinstance(correlation_map, dict):
        correlation_map = {}

    if not isinstance(matches, dict):
        matches = {}

    if not isinstance(ip_intelligence, dict):
        ip_intelligence = {}

    # -----------------------------------------------------
    # Stable IOC universe.
    # -----------------------------------------------------

    indicators = set()

    for container in (
        correlation_map,
        matches,
        ip_intelligence
    ):
        if isinstance(container, dict):
            for key in container.keys():
                value = str(key).strip()
                if value:
                    indicators.add(value)

    indicators = sorted(
        indicators,
        key=lambda value: value.lower()
    )

    # -----------------------------------------------------
    # Canonical infrastructure attributes.
    # -----------------------------------------------------

    attribute_aliases = {
        "asn": {
            "asn",
            "asn_number",
            "autonomous_system",
            "autonomous_system_number",
            "asn_name"
        },
        "organization": {
            "organization",
            "organisation",
            "org",
            "isp",
            "company",
            "network",
            "owner"
        },
        "hosting": {
            "hosting",
            "is_hosting",
            "hosted",
            "hosting_provider",
            "hosting_company"
        },
        "nameserver": {
            "nameserver",
            "name_server",
            "name_servers",
            "ns",
            "dns_provider"
        }
    }

    def normalize_scalar(value):
        if value is None:
            return None

        if isinstance(value, bool):
            return str(value).lower()

        if isinstance(value, (int, float)):
            return str(value)

        value = str(value).strip()

        if not value:
            return None

        return value

    def collect_attributes(
        node,
        depth=0
    ):
        found = {
            key: set()
            for key in attribute_aliases
        }

        if depth > 5:
            return found

        if isinstance(node, dict):

            for raw_key, raw_value in node.items():

                key = str(
                    raw_key
                ).strip().lower()

                for canonical, aliases in attribute_aliases.items():

                    if key not in aliases:
                        continue

                    if isinstance(
                        raw_value,
                        (list, tuple, set)
                    ):
                        for item in raw_value:

                            normalized = normalize_scalar(
                                item
                            )

                            if normalized:
                                found[
                                    canonical
                                ].add(
                                    normalized
                                )

                    elif isinstance(
                        raw_value,
                        dict
                    ):
                        nested = collect_attributes(
                            raw_value,
                            depth + 1
                        )

                        for nested_canonical, values in nested.items():
                            found[
                                nested_canonical
                            ].update(
                                values
                            )

                    else:
                        normalized = normalize_scalar(
                            raw_value
                        )

                        if normalized:
                            found[
                                canonical
                            ].add(
                                normalized
                            )

                nested = collect_attributes(
                    raw_value,
                    depth + 1
                )

                for canonical, values in nested.items():
                    found[
                        canonical
                    ].update(
                        values
                    )

        elif isinstance(
            node,
            (list, tuple, set)
        ):

            for item in node:

                nested = collect_attributes(
                    item,
                    depth + 1
                )

                for canonical, values in nested.items():
                    found[
                        canonical
                    ].update(
                        values
                    )

        return found

    def gather_for_indicator(
        indicator
    ):

        payloads = []

        for container in (
            correlation_map,
            matches,
            ip_intelligence
        ):

            if not isinstance(
                container,
                dict
            ):
                continue

            candidates = (
                indicator,
                str(indicator).lower(),
                str(indicator).upper()
            )

            for candidate in candidates:

                if candidate in container:
                    payloads.append(
                        container.get(
                            candidate
                        )
                    )

        attributes = {
            key: set()
            for key in attribute_aliases
        }

        for payload in payloads:

            nested = collect_attributes(
                payload
            )

            for canonical, values in nested.items():

                attributes[
                    canonical
                ].update(
                    values
                )

        return attributes

    indicator_attributes = {}

    for indicator in indicators:

        attributes = gather_for_indicator(
            indicator
        )

        if any(
            attributes.get(
                key
            )
            for key in attribute_aliases
        ):
            indicator_attributes[
                indicator
            ] = attributes

    # -----------------------------------------------------
    # Build normalized reuse maps.
    # -----------------------------------------------------

    reuse_maps = {
        key: {}
        for key in attribute_aliases
    }

    for indicator, attributes in indicator_attributes.items():

        for attribute_type in attribute_aliases:

            values = attributes.get(
                attribute_type,
                set()
            )

            for value in sorted(
                values,
                key=lambda item: item.lower()
            ):

                normalized = str(
                    value
                ).strip().lower()

                if not normalized:
                    continue

                reuse_maps[
                    attribute_type
                ].setdefault(
                    normalized,
                    set()
                ).add(
                    indicator
                )

    attribute_weights = {
        "asn": 1.00,
        "organization": 0.92,
        "hosting": 0.55,
        "nameserver": 0.60
    }

    pair_evidence = {}

    # -----------------------------------------------------
    # Discover shared infrastructure.
    # -----------------------------------------------------

    for attribute_type in sorted(
        reuse_maps
    ):

        value_map = reuse_maps[
            attribute_type
        ]

        for shared_value, member_set in sorted(
            value_map.items()
        ):

            members = sorted(
                {
                    str(member)
                    for member in member_set
                },
                key=lambda value: value.lower()
            )

            if len(members) < 2:
                continue

            # Generic hosting=True across only two indicators
            # is insufficient to establish meaningful reuse.
            if (
                attribute_type == "hosting"
                and
                len(members) < 3
            ):
                continue

            weight = attribute_weights.get(
                attribute_type,
                0.50
            )

            for index, source in enumerate(
                members
            ):

                for target in members[
                    index + 1:
                ]:

                    pair = sorted(
                        (
                            source,
                            target
                        ),
                        key=lambda value: value.lower()
                    )

                    pair_key = (
                        pair[0].lower(),
                        pair[1].lower()
                    )

                    pair_evidence.setdefault(
                        pair_key,
                        []
                    ).append(
                        {
                            "attribute": attribute_type,
                            "value": shared_value,
                            "weight": weight
                        }
                    )

    # -----------------------------------------------------
    # Normalize relationship evidence.
    # -----------------------------------------------------

    relationships = []

    for pair_key in sorted(
        pair_evidence
    ):

        evidence = pair_evidence[
            pair_key
        ]

        unique = {}

        for item in evidence:

            fingerprint = (
                str(
                    item.get(
                        "attribute",
                        ""
                    )
                ),
                str(
                    item.get(
                        "value",
                        ""
                    )
                ).lower()
            )

            unique[
                fingerprint
            ] = item

        unique_items = sorted(
            unique.values(),
            key=lambda item: (
                str(
                    item.get(
                        "attribute",
                        ""
                    )
                ),
                str(
                    item.get(
                        "value",
                        ""
                    )
                ).lower()
            )
        )

        attributes = sorted(
            {
                str(
                    item.get(
                        "attribute",
                        ""
                    )
                )
                for item in unique_items
            }
        )

        weighted_sum = sum(
            float(
                item.get(
                    "weight",
                    0
                ) or 0
            )
            for item in unique_items
        )

        diversity_factor = min(
            1.0
            + (
                max(
                    0,
                    len(attributes) - 1
                )
                * 0.18
            ),
            1.45
        )

        raw_strength = min(
            weighted_sum
            * diversity_factor,
            2.50
        )

        confidence = min(
            1.0,
            0.45
            + (
                0.18
                * min(
                    len(unique_items),
                    3
                )
            )
            + (
                0.08
                if len(attributes) >= 2
                else 0.0
            )
        )

        strong_dimension_count = len(
            {
                attribute
                for attribute in attributes
                if attribute in {
                    "asn",
                    "organization"
                }
            }
        )

        if strong_dimension_count >= 2:
            strength = (
                "HIGH"
                if confidence >= 0.82
                else "MEDIUM"
            )

        elif any(
            attribute in {
                "asn",
                "organization"
            }
            for attribute in attributes
        ):
            strength = (
                "HIGH"
                if confidence >= 0.82
                else "MEDIUM"
            )

        else:
            strength = "LOW"

        relationships.append(
            {
                "source": pair_key[0],
                "target": pair_key[1],
                "relationship": (
                    "infrastructure_reuse"
                ),
                "strength": strength,
                "confidence": round(
                    confidence,
                    3
                ),
                "attributes": attributes,
                "evidence": [
                    {
                        "attribute": item.get(
                            "attribute"
                        ),
                        "shared_value": item.get(
                            "value"
                        )
                    }
                    for item in unique_items
                ],
                "evidence_count": len(
                    unique_items
                ),
                "raw_strength": round(
                    raw_strength,
                    3
                )
            }
        )

    # -----------------------------------------------------
    # Build connected reuse clusters.
    # -----------------------------------------------------

    adjacency = {}

    for relationship in relationships:

        source = relationship[
            "source"
        ]

        target = relationship[
            "target"
        ]

        adjacency.setdefault(
            source,
            set()
        ).add(
            target
        )

        adjacency.setdefault(
            target,
            set()
        ).add(
            source
        )

    visited = set()
    clusters = []

    for start in sorted(
        adjacency,
        key=lambda value: value.lower()
    ):

        if start in visited:
            continue

        stack = [start]
        component = []

        while stack:

            current = stack.pop()

            if current in visited:
                continue

            visited.add(
                current
            )

            component.append(
                current
            )

            neighbors = sorted(
                adjacency.get(
                    current,
                    set()
                ),
                key=lambda value: value.lower(),
                reverse=True
            )

            for neighbor in neighbors:

                if neighbor not in visited:
                    stack.append(
                        neighbor
                    )

        component = sorted(
            set(component),
            key=lambda value: value.lower()
        )

        component_relationships = [
            relationship
            for relationship in relationships
            if relationship.get(
                "source"
            ) in component
            and
            relationship.get(
                "target"
            ) in component
        ]

        if len(component) >= 2:

            clusters.append(
                {
                    "cluster_id": (
                        "INFRA-"
                        + str(
                            len(clusters) + 1
                        ).zfill(3)
                    ),
                    "members": component,
                    "size": len(
                        component
                    ),
                    "relationship_count": len(
                        component_relationships
                    ),
                    "relationship_types": sorted(
                        {
                            attribute
                            for relationship
                            in component_relationships
                            for attribute in relationship.get(
                                "attributes",
                                []
                            )
                        }
                    ),
                    "average_confidence": round(
                        sum(
                            float(
                                relationship.get(
                                    "confidence",
                                    0
                                ) or 0
                            )
                            for relationship
                            in component_relationships
                        )
                        / max(
                            1,
                            len(
                                component_relationships
                            )
                        ),
                        3
                    )
                }
            )

    # -----------------------------------------------------
    # Bounded reuse bonus.
    # -----------------------------------------------------

    total_bonus = 0.0

    for relationship in relationships:

        confidence = float(
            relationship.get(
                "confidence",
                0
            ) or 0
        )

        evidence_count = int(
            relationship.get(
                "evidence_count",
                0
            ) or 0
        )

        base = (
            0.75
            * confidence
        )

        if evidence_count >= 2:
            base += 0.35

        attributes = relationship.get(
            "attributes",
            []
        )

        if (
            "asn" in attributes
            and
            "organization" in attributes
        ):
            base += 0.45

        total_bonus += min(
            base,
            1.75
        )

    total_bonus = round(
        min(
            total_bonus,
            4.0
        ),
        2
    )

    reuse_confidence = 0.0

    if relationships:

        reuse_confidence = (
            sum(
                float(
                    relationship.get(
                        "confidence",
                        0
                    ) or 0
                )
                for relationship in relationships
            )
            /
            len(
                relationships
            )
        )

    detected = bool(
        relationships
    )

    return {
        "detected": detected,
        "indicator_count": len(
            indicators
        ),
        "reuse_relationship_count": len(
            relationships
        ),
        "reuse_cluster_count": len(
            clusters
        ),
        "reuse_confidence": round(
            min(
                max(
                    reuse_confidence,
                    0.0
                ),
                1.0
            ),
            3
        ),
        "reuse_bonus": total_bonus,
        "relationships": relationships,
        "clusters": clusters
    }



# =========================================================
# SOC 9.5 THREAT TIMELINE CORRELATION
# =========================================================

def _build_threat_timeline_correlation(
    correlation_map,
    matches
):
    """
    Build deterministic chronological threat-event intelligence.

    This is an additive layer:
    - existing temporal freshness remains authoritative
    - historical recurrence remains authoritative
    - duplicate observations are collapsed
    - missing timestamps stay conservative
    - timeline confidence/bonus are bounded
    """

    if not isinstance(
        correlation_map,
        dict
    ):
        correlation_map = {}

    if not isinstance(
        matches,
        dict
    ):
        matches = {}

    timestamp_fields = (
        "last_seen",
        "first_seen",
        "timestamp",
        "observed_at",
        "seen_at",
        "event_time",
        "event_timestamp",
        "date",
        "created_at",
        "updated_at"
    )

    def parse_timestamp(
        value
    ):
        if value is None:
            return None

        if isinstance(
            value,
            datetime
        ):
            parsed = value

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        if isinstance(
            value,
            (int, float)
        ):
            try:
                return datetime.fromtimestamp(
                    value,
                    tz=timezone.utc
                )
            except Exception:
                return None

        value = str(
            value
        ).strip()

        if not value:
            return None

        normalized = value

        if normalized.endswith(
            "Z"
        ):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        try:
            parsed = datetime.fromisoformat(
                normalized
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        except Exception:
            pass

        # Conservative fallback for date-only
        # values commonly found in threat feeds.
        for fmt in (
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S"
        ):

            try:
                parsed = datetime.strptime(
                    value,
                    fmt
                )

                return parsed.replace(
                    tzinfo=timezone.utc
                )

            except Exception:
                continue

        return None

    def safe_list(
        value
    ):
        if value is None:
            return []

        if isinstance(
            value,
            list
        ):
            return value

        if isinstance(
            value,
            tuple
        ):
            return list(value)

        if isinstance(
            value,
            set
        ):
            return list(value)

        return [value]

    # -----------------------------------------------------
    # Stable IOC universe.
    # -----------------------------------------------------

    indicators = set()

    for container in (
        correlation_map,
        matches
    ):

        for key in container.keys():

            value = str(
                key
            ).strip()

            if value:
                indicators.add(
                    value
                )

    indicators = sorted(
        indicators,
        key=lambda value: value.lower()
    )

    # -----------------------------------------------------
    # Event extraction.
    # -----------------------------------------------------

    all_events = []
    per_indicator = {}

    for indicator in indicators:

        records = []

        candidates = (
            correlation_map.get(
                indicator
            ),
            correlation_map.get(
                indicator.lower()
            ),
            correlation_map.get(
                indicator.upper()
            ),
            matches.get(
                indicator
            ),
            matches.get(
                indicator.lower()
            ),
            matches.get(
                indicator.upper()
            )
        )

        for candidate in candidates:
            records.extend(
                safe_list(
                    candidate
                )
            )

        unique_events = {}

        for record in records:

            if not isinstance(
                record,
                dict
            ):
                continue

            timestamp = None
            timestamp_source = None

            for field in timestamp_fields:

                parsed = parse_timestamp(
                    record.get(
                        field
                    )
                )

                if parsed is not None:
                    timestamp = parsed
                    timestamp_source = field
                    break

            # Missing timestamps do not become timeline events.
            # They are represented by uncertainty metadata later.
            if timestamp is None:
                continue

            source = str(
                record.get(
                    "source",
                    "unknown"
                )
            ).strip() or "unknown"

            reference = str(
                record.get(
                    "reference",
                    record.get(
                        "external_id",
                        ""
                    )
                )
            ).strip()

            threat_type = str(
                record.get(
                    "threat_type",
                    record.get(
                        "verdict",
                        ""
                    )
                )
            ).strip()

            malware = str(
                record.get(
                    "malware",
                    ""
                )
            ).strip()

            event_key = (
                indicator.lower(),
                timestamp.isoformat(),
                source.lower(),
                reference.lower(),
                threat_type.lower(),
                malware.lower()
            )

            unique_events.setdefault(
                event_key,
                {
                    "indicator": indicator,
                    "timestamp": timestamp,
                    "timestamp_source": timestamp_source,
                    "source": source,
                    "reference": reference,
                    "threat_type": threat_type,
                    "malware": malware
                }
            )

        parsed_events = list(
            unique_events.values()
        )

        parsed_events.sort(
            key=lambda item: (
                item.get(
                    "timestamp"
                ),
                str(
                    item.get(
                        "source",
                        ""
                    )
                ).lower(),
                str(
                    item.get(
                        "reference",
                        ""
                    )
                ).lower(),
                str(
                    item.get(
                        "threat_type",
                        ""
                    )
                ).lower()
            )
        )

        per_indicator[
            indicator
        ] = parsed_events

        all_events.extend(
            parsed_events
        )

    # -----------------------------------------------------
    # Global chronological event stream.
    # -----------------------------------------------------

    all_events.sort(
        key=lambda item: (
            item.get(
                "timestamp"
            ),
            str(
                item.get(
                    "indicator",
                    ""
                )
            ).lower(),
            str(
                item.get(
                    "source",
                    ""
                )
            ).lower(),
            str(
                item.get(
                    "reference",
                    ""
                )
            ).lower()
        )
    )

    # -----------------------------------------------------
    # Global sequence numbers.
    # -----------------------------------------------------

    global_timeline = []

    for index, event in enumerate(
        all_events,
        start=1
    ):

        global_timeline.append(
            {
                "sequence": index,
                "indicator": event.get(
                    "indicator"
                ),
                "timestamp": event.get(
                    "timestamp"
                ).isoformat(),
                "timestamp_source": event.get(
                    "timestamp_source"
                ),
                "source": event.get(
                    "source"
                ),
                "reference": event.get(
                    "reference"
                ),
                "threat_type": event.get(
                    "threat_type"
                ),
                "malware": event.get(
                    "malware"
                )
            }
        )

    # -----------------------------------------------------
    # Per-IOC timeline summaries.
    # -----------------------------------------------------

    indicator_timelines = []

    for indicator in indicators:

        events = per_indicator.get(
            indicator,
            []
        )

        serialized_events = [
            {
                "sequence": index,
                "timestamp": event.get(
                    "timestamp"
                ).isoformat(),
                "timestamp_source": event.get(
                    "timestamp_source"
                ),
                "source": event.get(
                    "source"
                ),
                "reference": event.get(
                    "reference"
                ),
                "threat_type": event.get(
                    "threat_type"
                ),
                "malware": event.get(
                    "malware"
                )
            }
            for index, event in enumerate(
                events,
                start=1
            )
        ]

        first_seen = None
        last_seen = None
        span_hours = 0.0
        gap_hours = []

        if events:

            first_seen = events[
                0
            ][
                "timestamp"
            ].isoformat()

            last_seen = events[
                -1
            ][
                "timestamp"
            ].isoformat()

            if len(events) >= 2:

                span_hours = max(
                    0.0,
                    (
                        events[-1][
                            "timestamp"
                        ]
                        -
                        events[0][
                            "timestamp"
                        ]
                    ).total_seconds()
                    / 3600.0
                )

                for left, right in zip(
                    events,
                    events[1:]
                ):

                    delta = max(
                        0.0,
                        (
                            right[
                                "timestamp"
                            ]
                            -
                            left[
                                "timestamp"
                            ]
                        ).total_seconds()
                        / 3600.0
                    )

                    gap_hours.append(
                        round(
                            delta,
                            2
                        )
                    )

        max_gap_hours = (
            max(
                gap_hours
            )
            if gap_hours
            else 0.0
        )

        burst_event_count = 0

        for event in events:

            nearby_count = 0

            for other in events:

                if event is other:
                    continue

                distance = abs(
                    (
                        other[
                            "timestamp"
                        ]
                        -
                        event[
                            "timestamp"
                        ]
                    ).total_seconds()
                    / 3600.0
                )

                if distance <= 24.0:
                    nearby_count += 1

            if nearby_count >= 1:
                burst_event_count += 1

        indicator_timelines.append(
            {
                "indicator": indicator,
                "event_count": len(
                    events
                ),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "span_hours": round(
                    span_hours,
                    2
                ),
                "gap_count": len(
                    gap_hours
                ),
                "max_gap_hours": round(
                    max_gap_hours,
                    2
                ),
                "burst_event_count": burst_event_count,
                "events": serialized_events
            }
        )

    # -----------------------------------------------------
    # Cross-IOC sequence analysis.
    #
    # Every adjacent pair is examined. Relationships are
    # informational and deliberately do not replace the
    # existing campaign graph.
    # -----------------------------------------------------

    sequence_relationships = []

    for left, right in zip(
        all_events,
        all_events[1:]
    ):

        left_indicator = str(
            left.get(
                "indicator",
                ""
            )
        )

        right_indicator = str(
            right.get(
                "indicator",
                ""
            )
        )

        if (
            not left_indicator
            or
            not right_indicator
            or
            left_indicator == right_indicator
        ):
            continue

        delta_hours = max(
            0.0,
            (
                right[
                    "timestamp"
                ]
                -
                left[
                    "timestamp"
                ]
            ).total_seconds()
            / 3600.0
        )

        if delta_hours <= 24.0:
            sequence_class = (
                "NEAR_REAL_TIME"
            )
        elif delta_hours <= 168.0:
            sequence_class = (
                "SHORT_TERM"
            )
        elif delta_hours <= 720.0:
            sequence_class = (
                "MEDIUM_TERM"
            )
        else:
            sequence_class = (
                "LONG_GAP"
            )

        sequence_confidence = 0.55

        if delta_hours <= 24.0:
            sequence_confidence += 0.15

        if (
            str(
                left.get(
                    "source",
                    ""
                )
            ).lower()
            ==
            str(
                right.get(
                    "source",
                    ""
                )
            ).lower()
        ):
            sequence_confidence -= 0.05

        if (
            left.get(
                "threat_type"
            )
            and
            right.get(
                "threat_type"
            )
            and
            str(
                left.get(
                    "threat_type"
                )
            ).lower()
            ==
            str(
                right.get(
                    "threat_type"
                )
            ).lower()
        ):
            sequence_confidence += 0.05

        sequence_confidence = min(
            1.0,
            max(
                0.0,
                sequence_confidence
            )
        )

        sequence_relationships.append(
            {
                "from_indicator": left_indicator,
                "to_indicator": right_indicator,
                "from_timestamp": left[
                    "timestamp"
                ].isoformat(),
                "to_timestamp": right[
                    "timestamp"
                ].isoformat(),
                "delta_hours": round(
                    delta_hours,
                    2
                ),
                "sequence_class": sequence_class,
                "confidence": round(
                    sequence_confidence,
                    3
                )
            }
        )

    # -----------------------------------------------------
    # Detect meaningful temporal patterns.
    # -----------------------------------------------------

    short_gap_count = sum(
        1
        for item in sequence_relationships
        if item.get(
            "delta_hours",
            0
        ) <= 24.0
    )

    long_gap_count = sum(
        1
        for item in sequence_relationships
        if item.get(
            "delta_hours",
            0
        ) > 720.0
    )

    sequence_indicator_set = set()

    for item in sequence_relationships:

        sequence_indicator_set.add(
            item.get(
                "from_indicator"
            )
        )

        sequence_indicator_set.add(
            item.get(
                "to_indicator"
            )
        )

    cross_ioc_sequence_detected = (
        len(sequence_relationships) >= 1
        and
        len(sequence_indicator_set) >= 2
    )

    # -----------------------------------------------------
    # Timeline confidence.
    # -----------------------------------------------------

    timestamped_indicator_count = sum(
        1
        for item in indicator_timelines
        if item.get(
            "event_count",
            0
        ) > 0
    )

    timestamp_coverage = (
        timestamped_indicator_count
        /
        max(
            1,
            len(indicators)
        )
    )

    sequence_confidences = [
        float(
            item.get(
                "confidence",
                0
            ) or 0
        )
        for item in sequence_relationships
    ]

    average_sequence_confidence = (
        sum(
            sequence_confidences
        )
        /
        len(
            sequence_confidences
        )
        if sequence_confidences
        else 0.0
    )

    timeline_confidence = (
        0.45
        * timestamp_coverage
        +
        0.35
        * average_sequence_confidence
        +
        0.20
        * min(
            1.0,
            (
                len(
                    global_timeline
                )
                / 3.0
            )
        )
    )

    timeline_confidence = min(
        1.0,
        max(
            0.0,
            timeline_confidence
        )
    )

    # -----------------------------------------------------
    # Bounded timeline bonus.
    #
    # Multiple indicators and near-real-time sequencing can
    # add support, but timeline alone cannot manufacture a
    # critical threat.
    # -----------------------------------------------------

    timeline_bonus = 0.0

    if cross_ioc_sequence_detected:
        timeline_bonus += 0.75

    if len(
        sequence_indicator_set
    ) >= 3:
        timeline_bonus += 0.75

    if short_gap_count >= 1:
        timeline_bonus += 0.50

    if short_gap_count >= 3:
        timeline_bonus += 0.50

    if (
        long_gap_count >= 1
        and
        short_gap_count >= 1
    ):
        timeline_bonus += 0.35

    timeline_bonus = round(
        min(
            timeline_bonus,
            3.0
        ),
        2
    )

    missing_timestamp_indicator_count = 0

    for indicator in indicators:

        raw_records = []

        for container in (
            correlation_map,
            matches
        ):

            for candidate in (
                indicator,
                indicator.lower(),
                indicator.upper()
            ):

                if candidate in container:
                    raw_records.extend(
                        safe_list(
                            container.get(
                                candidate
                            )
                        )
                    )

        has_timestamp = False

        for record in raw_records:

            if not isinstance(
                record,
                dict
            ):
                continue

            for field in timestamp_fields:

                if parse_timestamp(
                    record.get(
                        field
                    )
                ) is not None:

                    has_timestamp = True
                    break

            if has_timestamp:
                break

        if raw_records and not has_timestamp:
            missing_timestamp_indicator_count += 1

    detected = (
        len(
            global_timeline
        ) > 0
    )

    return {
        "detected": detected,
        "indicator_count": len(
            indicators
        ),
        "timestamped_indicator_count": (
            timestamped_indicator_count
        ),
        "missing_timestamp_indicator_count": (
            missing_timestamp_indicator_count
        ),
        "event_count": len(
            global_timeline
        ),
        "cross_ioc_sequence_detected": (
            cross_ioc_sequence_detected
        ),
        "sequence_relationship_count": len(
            sequence_relationships
        ),
        "short_gap_count": short_gap_count,
        "long_gap_count": long_gap_count,
        "timestamp_coverage": round(
            timestamp_coverage,
            3
        ),
        "average_sequence_confidence": round(
            average_sequence_confidence,
            3
        ),
        "timeline_confidence": round(
            timeline_confidence,
            3
        ),
        "timeline_bonus": timeline_bonus,
        "global_timeline": global_timeline,
        "indicator_timelines": indicator_timelines,
        "sequence_relationships": (
            sequence_relationships
        )
    }



# =========================================================
# SOC 9.5 MITRE ATT&CK ATTACK CHAIN INTELLIGENCE
# =========================================================

def _build_mitre_attack_chain_intelligence(
    correlation_map,
    matches
):
    """
    Convert already-enriched MITRE ATT&CK technique evidence
    into deterministic attack-chain intelligence.

    Existing MITRE extraction and campaign-graph logic remain
    authoritative. This helper is additive only.
    """

    if not isinstance(
        correlation_map,
        dict
    ):
        correlation_map = {}

    if not isinstance(
        matches,
        dict
    ):
        matches = {}

    # -----------------------------------------------------
    # Common ATT&CK Enterprise technique -> tactic mapping.
    #
    # This is intentionally limited to stable, high-value
    # techniques. Unknown techniques remain UNKNOWN and do not
    # manufacture an attack-chain stage.
    # -----------------------------------------------------

    technique_tactics = {
        "T1059": "Execution",
        "T1059.001": "Execution",
        "T1059.003": "Execution",
        "T1059.004": "Execution",
        "T1059.005": "Execution",
        "T1059.006": "Execution",
        "T1059.007": "Execution",

        "T1566": "Initial Access",
        "T1566.001": "Initial Access",
        "T1566.002": "Initial Access",
        "T1566.003": "Initial Access",

        "T1190": "Initial Access",
        "T1133": "Initial Access",

        "T1204": "Execution",
        "T1204.001": "Execution",
        "T1204.002": "Execution",

        "T1547": "Persistence",
        "T1547.001": "Persistence",
        "T1547.004": "Persistence",
        "T1547.009": "Persistence",

        "T1053": "Persistence",
        "T1053.005": "Persistence",

        "T1078": "Defense Evasion",
        "T1078.001": "Defense Evasion",
        "T1078.002": "Defense Evasion",
        "T1078.003": "Defense Evasion",
        "T1078.004": "Defense Evasion",

        "T1021": "Lateral Movement",
        "T1021.001": "Lateral Movement",
        "T1021.002": "Lateral Movement",
        "T1021.004": "Lateral Movement",
        "T1021.005": "Lateral Movement",

        "T1087": "Discovery",
        "T1087.001": "Discovery",
        "T1087.002": "Discovery",
        "T1082": "Discovery",
        "T1049": "Discovery",
        "T1016": "Discovery",

        "T1047": "Execution",
        "T1055": "Defense Evasion",

        "T1003": "Credential Access",
        "T1003.001": "Credential Access",
        "T1003.002": "Credential Access",
        "T1003.003": "Credential Access",
        "T1003.004": "Credential Access",
        "T1003.005": "Credential Access",
        "T1003.006": "Credential Access",

        "T1555": "Credential Access",
        "T1555.001": "Credential Access",
        "T1555.003": "Credential Access",

        "T1105": "Command and Control",
        "T1071": "Command and Control",
        "T1071.001": "Command and Control",
        "T1071.002": "Command and Control",
        "T1071.003": "Command and Control",
        "T1071.004": "Command and Control",

        "T1095": "Command and Control",
        "T1572": "Command and Control",

        "T1486": "Impact",
        "T1490": "Impact",
        "T1491": "Impact",

        "T1562": "Defense Evasion",
        "T1562.001": "Defense Evasion",

        "T1027": "Defense Evasion",
        "T1027.001": "Defense Evasion",
        "T1027.002": "Defense Evasion",

        "T1548": "Privilege Escalation",
        "T1548.002": "Privilege Escalation",
        "T1068": "Privilege Escalation",

        "T1083": "Discovery",
        "T1057": "Discovery",
        "T1018": "Discovery",

        "T1114": "Collection",
        "T1114.001": "Collection",
        "T1114.002": "Collection",
        "T1114.003": "Collection",

        "T1560": "Collection",
        "T1560.001": "Collection",
        "T1560.002": "Collection",

        "T1041": "Exfiltration",
        "T1020": "Exfiltration",
        "T1030": "Exfiltration",

        "T1531": "Impact"
    }

    tactic_order = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    ]

    tactic_rank = {
        tactic: index
        for index, tactic in enumerate(
            tactic_order
        )
    }

    # -----------------------------------------------------
    # Technique normalization.
    # -----------------------------------------------------

    def normalize_technique(
        value
    ):
        if value is None:
            return None

        if isinstance(
            value,
            dict
        ):
            candidates = (
                value.get("id"),
                value.get("technique_id"),
                value.get("technique"),
                value.get("name")
            )

            for candidate in candidates:

                if candidate:
                    normalized = str(
                        candidate
                    ).strip()

                    if normalized:
                        return normalized

            return None

        normalized = str(
            value
        ).strip()

        if not normalized:
            return None

        return normalized

    def safe_list(
        value
    ):
        if value is None:
            return []

        if isinstance(
            value,
            list
        ):
            return value

        if isinstance(
            value,
            tuple
        ):
            return list(value)

        if isinstance(
            value,
            set
        ):
            return list(value)

        return [value]

    def collect_mitre(
        node,
        depth=0
    ):
        techniques = set()

        if depth > 6:
            return techniques

        if isinstance(
            node,
            dict
        ):

            for key, value in node.items():

                normalized_key = str(
                    key
                ).strip().lower()

                if normalized_key in {
                    "mitre_attack",
                    "mitre_attck",
                    "mitre",
                    "attack_techniques",
                    "techniques",
                    "technique",
                    "technique_id",
                    "technique_ids"
                }:

                    for candidate in safe_list(
                        value
                    ):

                        technique = normalize_technique(
                            candidate
                        )

                        if technique:
                            techniques.add(
                                technique
                            )

                techniques.update(
                    collect_mitre(
                        value,
                        depth + 1
                    )
                )

        elif isinstance(
            node,
            (list, tuple, set)
        ):

            for item in node:

                techniques.update(
                    collect_mitre(
                        item,
                        depth + 1
                    )
                )

        return techniques

    # -----------------------------------------------------
    # Gather per-IOC technique evidence.
    # -----------------------------------------------------

    indicators = set()

    for container in (
        correlation_map,
        matches
    ):

        for key in container.keys():

            value = str(
                key
            ).strip()

            if value:
                indicators.add(
                    value
                )

    indicators = sorted(
        indicators,
        key=lambda value: value.lower()
    )

    per_indicator = {}
    all_techniques = set()

    for indicator in indicators:

        payloads = []

        for container in (
            correlation_map,
            matches
        ):

            for candidate in (
                indicator,
                indicator.lower(),
                indicator.upper()
            ):

                if candidate in container:

                    value = container.get(
                        candidate
                    )

                    payloads.extend(
                        safe_list(
                            value
                        )
                    )

        techniques = set()

        for payload in payloads:

            techniques.update(
                collect_mitre(
                    payload
                )
            )

        normalized_techniques = sorted(
            techniques,
            key=lambda value: value.lower()
        )

        per_indicator[
            indicator
        ] = normalized_techniques

        all_techniques.update(
            normalized_techniques
        )

    # -----------------------------------------------------
    # Build technique/tactic records.
    # -----------------------------------------------------

    technique_records = []

    for technique in sorted(
        all_techniques,
        key=lambda value: value.lower()
    ):

        normalized_id = str(
            technique
        ).strip()

        tactic = technique_tactics.get(
            normalized_id
        )

        if tactic is None:

            upper_id = normalized_id.upper()

            tactic = technique_tactics.get(
                upper_id
            )

        if tactic is None:

            # Parent technique fallback:
            # T1059.999 -> use T1059 when known.
            parent = normalized_id.split(
                ".",
                1
            )[0]

            tactic = technique_tactics.get(
                parent
            )

        technique_records.append(
            {
                "technique": normalized_id,
                "tactic": (
                    tactic
                    if tactic
                    else "UNKNOWN"
                ),
                "known": bool(
                    tactic
                )
            }
        )

    known_records = [
        item
        for item in technique_records
        if item.get(
            "known"
        )
    ]

    known_records.sort(
        key=lambda item: (
            tactic_rank.get(
                item.get(
                    "tactic"
                ),
                999
            ),
            str(
                item.get(
                    "technique",
                    ""
                )
            ).lower()
        )
    )

    # -----------------------------------------------------
    # Collapse repeated tactics while preserving the ordered
    # ATT&CK progression.
    # -----------------------------------------------------

    ordered_tactics = []

    for item in known_records:

        tactic = item.get(
            "tactic"
        )

        if (
            tactic
            and
            tactic not in ordered_tactics
        ):
            ordered_tactics.append(
                tactic
            )

    # -----------------------------------------------------
    # Expected transition analysis.
    # -----------------------------------------------------

    transitions = []

    valid_order = [
        tactic
        for tactic in tactic_order
        if tactic in ordered_tactics
    ]

    for index in range(
        len(valid_order) - 1
    ):

        current = valid_order[
            index
        ]

        next_tactic = valid_order[
            index + 1
        ]

        current_rank = tactic_rank.get(
            current,
            999
        )

        next_rank = tactic_rank.get(
            next_tactic,
            999
        )

        delta = (
            next_rank
            -
            current_rank
        )

        transitions.append(
            {
                "from_tactic": current,
                "to_tactic": next_tactic,
                "expected_progression": (
                    delta > 0
                ),
                "tactic_distance": delta
            }
        )

    forward_transitions = sum(
        1
        for transition in transitions
        if transition.get(
            "expected_progression"
        )
    )

    transition_count = len(
        transitions
    )

    # -----------------------------------------------------
    # Chain classification.
    # -----------------------------------------------------

    chain_stage_count = len(
        ordered_tactics
    )

    if chain_stage_count >= 5:
        chain_status = (
            "MULTI_STAGE_ATTACK_CHAIN"
        )

    elif chain_stage_count >= 3:
        chain_status = (
            "PARTIAL_ATTACK_CHAIN"
        )

    elif chain_stage_count == 2:
        chain_status = (
            "LIMITED_ATTACK_SEQUENCE"
        )

    elif chain_stage_count == 1:
        chain_status = (
            "SINGLE_TACTIC"
        )

    elif technique_records:
        chain_status = (
            "UNKNOWN_TECHNIQUE_SET"
        )

    else:
        chain_status = (
            "NO_MITRE_EVIDENCE"
        )

    # -----------------------------------------------------
    # Chain confidence.
    #
    # Unknown techniques contribute very little.
    # A single technique remains conservative.
    # -----------------------------------------------------

    if not technique_records:

        chain_confidence = 0.0

    else:

        known_ratio = (
            len(
                known_records
            )
            /
            max(
                1,
                len(
                    technique_records
                )
            )
        )

        stage_factor = min(
            1.0,
            chain_stage_count
            / 5.0
        )

        progression_factor = (
            forward_transitions
            /
            max(
                1,
                transition_count
            )
        )

        chain_confidence = (
            0.20
            * known_ratio
            +
            0.45
            * stage_factor
            +
            0.35
            * progression_factor
        )

        if chain_stage_count == 1:
            chain_confidence = min(
                chain_confidence,
                0.42
            )

        if (
            known_ratio == 0
        ):
            chain_confidence = 0.05

    chain_confidence = min(
        1.0,
        max(
            0.0,
            chain_confidence
        )
    )

    # -----------------------------------------------------
    # Bounded chain bonus.
    # -----------------------------------------------------

    chain_bonus = 0.0

    if chain_stage_count >= 2:
        chain_bonus += 0.50

    if chain_stage_count >= 3:
        chain_bonus += 0.75

    if chain_stage_count >= 5:
        chain_bonus += 0.75

    if forward_transitions >= 2:
        chain_bonus += 0.50

    if forward_transitions >= 4:
        chain_bonus += 0.50

    if (
        chain_stage_count >= 3
        and
        chain_confidence >= 0.70
    ):
        chain_bonus += 0.50

    if (
        chain_stage_count <= 1
    ):
        chain_bonus = 0.0

    if (
        not known_records
    ):
        chain_bonus = 0.0

    chain_bonus = round(
        min(
            max(
                chain_bonus,
                0.0
            ),
            3.0
        ),
        2
    )

    # -----------------------------------------------------
    # Attack path with deterministic technique ordering.
    # -----------------------------------------------------

    attack_path = []

    for tactic in ordered_tactics:

        techniques_for_tactic = sorted(
            [
                item.get(
                    "technique"
                )
                for item in known_records
                if item.get(
                    "tactic"
                ) == tactic
            ],
            key=lambda value: str(
                value
            ).lower()
        )

        attack_path.append(
            {
                "tactic": tactic,
                "techniques": techniques_for_tactic
            }
        )

    # -----------------------------------------------------
    # Per-IOC chain participation.
    # -----------------------------------------------------

    indicator_chain_profiles = []

    for indicator in indicators:

        techniques = per_indicator.get(
            indicator,
            []
        )

        known_indicator_techniques = [
            technique
            for technique in techniques
            if (
                technique in {
                    item.get(
                        "technique"
                    )
                    for item in known_records
                }
            )
        ]

        indicator_tactics = []

        for technique in known_indicator_techniques:

            tactic = next(
                (
                    item.get(
                        "tactic"
                    )
                    for item in known_records
                    if item.get(
                        "technique"
                    ) == technique
                ),
                None
            )

            if (
                tactic
                and
                tactic not in indicator_tactics
            ):
                indicator_tactics.append(
                    tactic
                )

        indicator_tactics.sort(
            key=lambda value: tactic_rank.get(
                value,
                999
            )
        )

        indicator_chain_profiles.append(
            {
                "indicator": indicator,
                "techniques": sorted(
                    techniques,
                    key=lambda value: value.lower()
                ),
                "known_technique_count": len(
                    known_indicator_techniques
                ),
                "tactics": indicator_tactics,
                "stage_count": len(
                    indicator_tactics
                )
            }
        )

    # -----------------------------------------------------
    # Detection semantics.
    # -----------------------------------------------------

    full_chain_recognized = (
        chain_stage_count >= 3
        and
        len(
            known_records
        ) >= 3
        and
        chain_confidence >= 0.55
    )

    single_technique_conservative = (
        chain_stage_count <= 1
        and
        chain_bonus == 0.0
        and
        chain_confidence <= 0.42
    )

    unknown_technique_conservative = (
        bool(
            technique_records
        )
        and
        not bool(
            known_records
        )
        and
        chain_bonus == 0.0
        and
        chain_confidence <= 0.05
    )

    no_mitre_conservative = (
        not technique_records
        and
        chain_confidence == 0.0
        and
        chain_bonus == 0.0
        and
        chain_status == "NO_MITRE_EVIDENCE"
    )

    return {
        "detected": bool(
            technique_records
        ),
        "full_chain_recognized": (
            full_chain_recognized
        ),
        "chain_status": chain_status,
        "technique_count": len(
            technique_records
        ),
        "known_technique_count": len(
            known_records
        ),
        "unknown_technique_count": (
            len(
                technique_records
            )
            -
            len(
                known_records
            )
        ),
        "tactic_count": len(
            ordered_tactics
        ),
        "tactics": ordered_tactics,
        "attack_path": attack_path,
        "transitions": transitions,
        "transition_count": transition_count,
        "forward_transition_count": (
            forward_transitions
        ),
        "chain_confidence": round(
            chain_confidence,
            3
        ),
        "chain_bonus": chain_bonus,
        "techniques": technique_records,
        "indicator_profiles": (
            indicator_chain_profiles
        ),
        "single_technique_conservative": (
            single_technique_conservative
        ),
        "unknown_technique_conservative": (
            unknown_technique_conservative
        ),
        "no_mitre_conservative": (
            no_mitre_conservative
        )
    }



# =========================================================
# SOC 9.5 CYBER KILL CHAIN INTELLIGENCE
# =========================================================

def _build_cyber_kill_chain_intelligence(
    correlation_map,
    matches
):
    """
    Build deterministic Lockheed-style Cyber Kill Chain
    intelligence from already-enriched threat evidence.

    Existing MITRE ATT&CK, campaign graph, timeline and
    recurrence intelligence remain authoritative and are
    not replaced by this layer.
    """

    if not isinstance(
        correlation_map,
        dict
    ):
        correlation_map = {}

    if not isinstance(
        matches,
        dict
    ):
        matches = {}

    # -----------------------------------------------------
    # Canonical Cyber Kill Chain stages.
    # -----------------------------------------------------

    stage_order = [
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "Command and Control",
        "Actions on Objectives"
    ]

    stage_rank = {
        stage: index
        for index, stage in enumerate(
            stage_order
        )
    }

    # -----------------------------------------------------
    # Flexible normalization for common provider labels.
    # -----------------------------------------------------

    stage_aliases = {
        "reconnaissance": "Reconnaissance",
        "recon": "Reconnaissance",
        "reconnaissance phase": "Reconnaissance",

        "weaponization": "Weaponization",
        "weaponisation": "Weaponization",
        "weaponize": "Weaponization",

        "delivery": "Delivery",
        "delivered": "Delivery",

        "exploitation": "Exploitation",
        "exploit": "Exploitation",
        "exploitation phase": "Exploitation",

        "installation": "Installation",
        "install": "Installation",
        "persistence": "Installation",

        "command and control": "Command and Control",
        "command & control": "Command and Control",
        "command-and-control": "Command and Control",
        "c2": "Command and Control",
        "c&c": "Command and Control",
        "command_control": "Command and Control",

        "actions on objectives": "Actions on Objectives",
        "actions-on-objectives": "Actions on Objectives",
        "actions": "Actions on Objectives",
        "objective": "Actions on Objectives"
    }

    # -----------------------------------------------------
    # Optional MITRE-tactic support.
    #
    # Existing MITRE evidence can provide supporting context
    # but does not itself silently manufacture every Kill Chain
    # stage.
    # -----------------------------------------------------

    mitre_to_kill_chain = {
        "Reconnaissance": "Reconnaissance",
        "Resource Development": "Weaponization",
        "Initial Access": "Delivery",
        "Execution": "Exploitation",
        "Persistence": "Installation",
        "Privilege Escalation": "Installation",
        "Defense Evasion": "Installation",
        "Credential Access": "Actions on Objectives",
        "Discovery": "Actions on Objectives",
        "Lateral Movement": "Actions on Objectives",
        "Collection": "Actions on Objectives",
        "Command and Control": "Command and Control",
        "Exfiltration": "Actions on Objectives",
        "Impact": "Actions on Objectives"
    }

    mitre_technique_tactic = {
        "T1566": "Initial Access",
        "T1566.001": "Initial Access",
        "T1566.002": "Initial Access",
        "T1566.003": "Initial Access",

        "T1059": "Execution",
        "T1059.001": "Execution",
        "T1059.003": "Execution",
        "T1059.004": "Execution",
        "T1059.005": "Execution",
        "T1059.006": "Execution",
        "T1059.007": "Execution",

        "T1204": "Execution",
        "T1204.001": "Execution",
        "T1204.002": "Execution",

        "T1547": "Persistence",
        "T1547.001": "Persistence",
        "T1547.004": "Persistence",
        "T1547.009": "Persistence",

        "T1053": "Persistence",
        "T1053.005": "Persistence",

        "T1105": "Command and Control",
        "T1071": "Command and Control",
        "T1071.001": "Command and Control",
        "T1071.002": "Command and Control",
        "T1071.003": "Command and Control",
        "T1071.004": "Command and Control",
        "T1095": "Command and Control",
        "T1572": "Command and Control",

        "T1486": "Impact",
        "T1490": "Impact",
        "T1491": "Impact"
    }

    def safe_list(
        value
    ):
        if value is None:
            return []

        if isinstance(
            value,
            list
        ):
            return value

        if isinstance(
            value,
            tuple
        ):
            return list(value)

        if isinstance(
            value,
            set
        ):
            return list(value)

        return [value]

    def normalize_stage(
        value
    ):
        if value is None:
            return None

        if isinstance(
            value,
            dict
        ):
            candidates = (
                value.get("stage"),
                value.get("kill_chain"),
                value.get("phase"),
                value.get("name")
            )

            for candidate in candidates:
                normalized = normalize_stage(
                    candidate
                )

                if normalized:
                    return normalized

            return None

        normalized = str(
            value
        ).strip()

        if not normalized:
            return None

        key = (
            normalized
            .lower()
            .replace("_", " ")
            .replace("-", " ")
        )

        key = " ".join(
            key.split()
        )

        return stage_aliases.get(
            key
        )

    def extract_mitre_techniques(
        node,
        depth=0
    ):
        techniques = set()

        if depth > 6:
            return techniques

        if isinstance(
            node,
            dict
        ):

            for key, value in node.items():

                normalized_key = str(
                    key
                ).strip().lower()

                if normalized_key in {
                    "mitre_attack",
                    "mitre_attck",
                    "mitre",
                    "technique",
                    "techniques",
                    "technique_id",
                    "technique_ids"
                }:

                    for candidate in safe_list(
                        value
                    ):

                        if isinstance(
                            candidate,
                            dict
                        ):
                            candidate = (
                                candidate.get(
                                    "id"
                                )
                                or
                                candidate.get(
                                    "technique_id"
                                )
                                or
                                candidate.get(
                                    "technique"
                                )
                            )

                        if candidate:
                            techniques.add(
                                str(
                                    candidate
                                ).strip()
                            )

                techniques.update(
                    extract_mitre_techniques(
                        value,
                        depth + 1
                    )
                )

        elif isinstance(
            node,
            (list, tuple, set)
        ):

            for item in node:
                techniques.update(
                    extract_mitre_techniques(
                        item,
                        depth + 1
                    )
                )

        return techniques

    # -----------------------------------------------------
    # Stable IOC universe.
    # -----------------------------------------------------

    indicators = set()

    for container in (
        correlation_map,
        matches
    ):

        for key in container.keys():

            value = str(
                key
            ).strip()

            if value:
                indicators.add(
                    value
                )

    indicators = sorted(
        indicators,
        key=lambda value: value.lower()
    )

    # -----------------------------------------------------
    # Extract explicit Kill Chain stage evidence first.
    # -----------------------------------------------------

    indicator_stages = {}
    explicit_stage_sources = {}

    for indicator in indicators:

        payloads = []

        for container in (
            correlation_map,
            matches
        ):

            for candidate in (
                indicator,
                indicator.lower(),
                indicator.upper()
            ):

                if candidate in container:

                    value = container.get(
                        candidate
                    )

                    payloads.extend(
                        safe_list(
                            value
                        )
                    )

        stages = set()
        sources = set()

        def walk_explicit(
            node,
            depth=0
        ):
            if depth > 6:
                return

            if isinstance(
                node,
                dict
            ):

                for key, value in node.items():

                    normalized_key = str(
                        key
                    ).strip().lower()

                    is_kill_chain_field = (
                        normalized_key
                        in {
                            "kill_chain",
                            "killchain",
                            "kill_chain_stage",
                            "killchain_stage",
                            "cyber_kill_chain",
                            "phase",
                            "attack_phase"
                        }
                    )

                    if is_kill_chain_field:

                        for candidate in safe_list(
                            value
                        ):

                            stage = normalize_stage(
                                candidate
                            )

                            if stage:
                                stages.add(
                                    stage
                                )

                    if normalized_key in {
                        "source",
                        "provider",
                        "feed"
                    }:

                        for candidate in safe_list(
                            value
                        ):

                            candidate = str(
                                candidate
                            ).strip()

                            if candidate:
                                sources.add(
                                    candidate
                                )

                    walk_explicit(
                        value,
                        depth + 1
                    )

            elif isinstance(
                node,
                (list, tuple, set)
            ):

                for item in node:
                    walk_explicit(
                        item,
                        depth + 1
                    )

        for payload in payloads:
            walk_explicit(
                payload
            )

        indicator_stages[
            indicator
        ] = sorted(
            stages,
            key=lambda stage: stage_rank.get(
                stage,
                999
            )
        )

        explicit_stage_sources[
            indicator
        ] = sorted(
            sources,
            key=lambda value: value.lower()
        )

    # -----------------------------------------------------
    # Build explicit stage set.
    # -----------------------------------------------------

    explicit_stages = set()

    for stages in indicator_stages.values():
        explicit_stages.update(
            stages
        )

    # -----------------------------------------------------
    # Optional supporting inference from MITRE ATT&CK.
    #
    # Only add inferred stages that are directly represented
    # by a known MITRE tactic. Unknown techniques remain
    # unknown and add no Kill Chain stage.
    # -----------------------------------------------------

    inferred_stages = set()
    inferred_stage_techniques = {}

    for indicator in indicators:

        payloads = []

        for container in (
            correlation_map,
            matches
        ):

            for candidate in (
                indicator,
                indicator.lower(),
                indicator.upper()
            ):

                if candidate in container:

                    payloads.extend(
                        safe_list(
                            container.get(
                                candidate
                            )
                        )
                    )

        techniques = set()

        for payload in payloads:

            techniques.update(
                extract_mitre_techniques(
                    payload
                )
            )

        for technique in sorted(
            techniques,
            key=lambda value: value.lower()
        ):

            normalized_technique = (
                technique.upper()
            )

            tactic = mitre_technique_tactic.get(
                normalized_technique
            )

            if tactic is None:

                parent = normalized_technique.split(
                    ".",
                    1
                )[0]

                tactic = mitre_technique_tactic.get(
                    parent
                )

            if tactic is None:
                continue

            stage = mitre_to_kill_chain.get(
                tactic
            )

            if not stage:
                continue

            # Avoid inventing Weaponization or Reconnaissance
            # from generic ATT&CK evidence.
            if stage in {
                "Weaponization",
                "Reconnaissance"
            }:
                continue

            inferred_stages.add(
                stage
            )

            inferred_stage_techniques.setdefault(
                stage,
                set()
            ).add(
                normalized_technique
            )

    # -----------------------------------------------------
    # Combined stage model.
    # Explicit evidence wins. MITRE-derived stages are marked
    # separately so analysts can distinguish evidence from
    # inference.
    # -----------------------------------------------------

    combined_stages = (
        explicit_stages
        |
        inferred_stages
    )

    ordered_stages = sorted(
        combined_stages,
        key=lambda stage: stage_rank.get(
            stage,
            999
        )
    )

    stage_records = []

    for stage in ordered_stages:

        explicit_indicators = sorted(
            {
                indicator
                for indicator, stages
                in indicator_stages.items()
                if stage in stages
            },
            key=lambda value: value.lower()
        )

        inferred_techniques = sorted(
            inferred_stage_techniques.get(
                stage,
                set()
            ),
            key=lambda value: value.lower()
        )

        evidence_mode = "EXPLICIT"

        if (
            stage not in explicit_stages
            and
            stage in inferred_stages
        ):
            evidence_mode = "MITRE_INFERRED"

        elif (
            stage in explicit_stages
            and
            stage in inferred_stages
        ):
            evidence_mode = "EXPLICIT_PLUS_MITRE"

        stage_records.append(
            {
                "stage": stage,
                "rank": stage_rank.get(
                    stage,
                    999
                ),
                "evidence_mode": evidence_mode,
                "indicator_count": len(
                    explicit_indicators
                ),
                "indicators": explicit_indicators,
                "mitre_techniques": inferred_techniques
            }
        )

    # -----------------------------------------------------
    # Progression analysis.
    # -----------------------------------------------------

    transitions = []

    for index in range(
        len(ordered_stages) - 1
    ):

        current = ordered_stages[
            index
        ]

        next_stage = ordered_stages[
            index + 1
        ]

        current_rank = stage_rank.get(
            current,
            999
        )

        next_rank = stage_rank.get(
            next_stage,
            999
        )

        distance = (
            next_rank
            -
            current_rank
        )

        transitions.append(
            {
                "from_stage": current,
                "to_stage": next_stage,
                "expected_progression": (
                    distance > 0
                ),
                "stage_distance": distance
            }
        )

    forward_transitions = sum(
        1
        for transition in transitions
        if transition.get(
            "expected_progression"
        )
    )

    # -----------------------------------------------------
    # Stage coverage.
    # -----------------------------------------------------

    stage_count = len(
        ordered_stages
    )

    coverage = (
        stage_count
        /
        len(stage_order)
    )

    # -----------------------------------------------------
    # Chain status.
    # -----------------------------------------------------

    if stage_count >= 6:
        chain_status = (
            "FULL_KILL_CHAIN"
        )

    elif stage_count >= 4:
        chain_status = (
            "MULTI_STAGE_KILL_CHAIN"
        )

    elif stage_count >= 2:
        chain_status = (
            "PARTIAL_KILL_CHAIN"
        )

    elif stage_count == 1:
        chain_status = (
            "SINGLE_STAGE"
        )

    else:
        chain_status = (
            "NO_KILL_CHAIN_EVIDENCE"
        )

    # -----------------------------------------------------
    # Confidence.
    #
    # Full explicit chains score highest.
    # Inferred-only chains are deliberately capped.
    # -----------------------------------------------------

    explicit_count = len(
        explicit_stages
    )

    inferred_only_count = len(
        {
            stage
            for stage in inferred_stages
            if stage not in explicit_stages
        }
    )

    explicit_ratio = (
        explicit_count
        /
        max(
            1,
            stage_count
        )
    )

    progression_ratio = (
        forward_transitions
        /
        max(
            1,
            len(transitions)
        )
    )

    confidence = (
        0.45
        * coverage
        +
        0.30
        * explicit_ratio
        +
        0.25
        * progression_ratio
    )

    if stage_count == 1:
        confidence = min(
            confidence,
            0.35
        )

    if (
        explicit_count == 0
        and
        inferred_only_count > 0
    ):
        confidence = min(
            confidence,
            0.55
        )

    confidence = min(
        1.0,
        max(
            0.0,
            confidence
        )
    )

    # -----------------------------------------------------
    # Bounded Kill Chain bonus.
    # -----------------------------------------------------

    chain_bonus = 0.0

    if stage_count >= 2:
        chain_bonus += 0.50

    if stage_count >= 4:
        chain_bonus += 0.75

    if stage_count >= 6:
        chain_bonus += 0.75

    if stage_count >= 7:
        chain_bonus += 0.50

    if forward_transitions >= 2:
        chain_bonus += 0.25

    if forward_transitions >= 4:
        chain_bonus += 0.25

    if explicit_count >= 3:
        chain_bonus += 0.50

    # Single-stage evidence never receives a chain bonus.
    if stage_count <= 1:
        chain_bonus = 0.0

    # Purely inferred ATT&CK mapping remains bounded.
    if explicit_count == 0:
        chain_bonus = min(
            chain_bonus,
            1.0
        )

    chain_bonus = round(
        min(
            max(
                chain_bonus,
                0.0
            ),
            3.0
        ),
        2
    )

    # -----------------------------------------------------
    # Conservative flags.
    # -----------------------------------------------------

    full_chain_recognized = (
        stage_count >= 5
        and
        explicit_count >= 3
        and
        confidence >= 0.55
    )

    single_stage_conservative = (
        stage_count <= 1
        and
        chain_bonus == 0.0
        and
        confidence <= 0.35
    )

    unknown_stage_conservative = (
        stage_count == 0
        and
        not explicit_stages
        and
        not inferred_stages
        and
        confidence == 0.0
        and
        chain_bonus == 0.0
    )

    no_kill_chain_conservative = (
        chain_status == "NO_KILL_CHAIN_EVIDENCE"
        and
        confidence == 0.0
        and
        chain_bonus == 0.0
    )

    # -----------------------------------------------------
    # Ordered analyst path.
    # -----------------------------------------------------

    attack_path = []

    for stage in ordered_stages:

        record = next(
            (
                item
                for item in stage_records
                if item.get(
                    "stage"
                ) == stage
            ),
            None
        )

        attack_path.append(
            {
                "stage": stage,
                "evidence_mode": (
                    record.get(
                        "evidence_mode"
                    )
                    if record
                    else "UNKNOWN"
                ),
                "indicators": (
                    record.get(
                        "indicators",
                        []
                    )
                    if record
                    else []
                ),
                "mitre_techniques": (
                    record.get(
                        "mitre_techniques",
                        []
                    )
                    if record
                    else []
                )
            }
        )

    return {
        "detected": bool(
            stage_count
        ),
        "chain_status": chain_status,
        "full_chain_recognized": (
            full_chain_recognized
        ),
        "stage_count": stage_count,
        "known_stage_count": stage_count,
        "stage_coverage": round(
            coverage,
            3
        ),
        "stages": ordered_stages,
        "stage_records": stage_records,
        "attack_path": attack_path,
        "transition_count": len(
            transitions
        ),
        "forward_transition_count": (
            forward_transitions
        ),
        "transitions": transitions,
        "explicit_stage_count": explicit_count,
        "mitre_inferred_stage_count": (
            inferred_only_count
        ),
        "chain_confidence": round(
            confidence,
            3
        ),
        "chain_bonus": chain_bonus,
        "indicator_stage_map": {
            indicator: stages
            for indicator, stages
            in sorted(
                indicator_stages.items(),
                key=lambda item: item[0].lower()
            )
        },
        "explicit_stage_sources": (
            explicit_stage_sources
        ),
        "single_stage_conservative": (
            single_stage_conservative
        ),
        "unknown_stage_conservative": (
            unknown_stage_conservative
        ),
        "no_kill_chain_conservative": (
            no_kill_chain_conservative
        )
    }



# =========================================================
# SOC 9.5 ALERT INTELLIGENCE / DETECTION CORRELATION
# =========================================================

def _build_alert_intelligence(
    correlation_map,
    matches
):
    # =====================================================
    # SOC 9.5 ALERT INTELLIGENCE ZERO-STATE INITIALIZATION
    # =====================================================
    conflict_count = 0
    multi_signal_bonus = 0.0
    high_strength_bonus = 0.0
    conflict_penalty = 0.0
    correlation_bonus = 0.0
    source_bonus = 0.0
    detection_count = 0
    signal_count = 0
    high_strength_count = 0
    max_risk_score = 0.0
    score_sum = 0.0
    confidence_sum = 0.0
    confidence_count = 0

    """
    Correlate existing IOC intelligence into deterministic,
    analyst-ready SOC alert intelligence.

    Additive only:
    - does not replace IOC threat scoring
    - does not replace campaign graph
    - does not replace MITRE attack chain
    - does not replace timeline / recurrence intelligence
    """

    if not isinstance(
        correlation_map,
        dict
    ):
        correlation_map = {}

    if not isinstance(
        matches,
        dict
    ):
        matches = {}

    # -----------------------------------------------------
    # Stable severity ranking.
    # -----------------------------------------------------

    severity_rank = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5
    }

    def normalize_severity(
        value
    ):
        value = str(
            value or "INFO"
        ).strip().upper()

        if value not in severity_rank:
            return "INFO"

        return value

    def clamp(
        value,
        low=0.0,
        high=1.0
    ):
        try:
            value = float(
                value
            )
        except Exception:
            value = 0.0

        return max(
            low,
            min(
                value,
                high
            )
        )

    def safe_float(
        value,
        default=0.0
    ):
        try:
            return float(
                value
            )
        except Exception:
            return default

    def safe_list(
        value
    ):
        if value is None:
            return []

        if isinstance(
            value,
            list
        ):
            return value

        if isinstance(
            value,
            tuple
        ):
            return list(value)

        if isinstance(
            value,
            set
        ):
            return list(value)

        return [value]

    # -----------------------------------------------------
    # Stable IOC universe.
    # -----------------------------------------------------

    indicators = set()

    for container in (
        correlation_map,
        matches
    ):

        for key in container.keys():

            value = str(
                key
            ).strip()

            if value:
                indicators.add(
                    value
                )

    indicators = sorted(
        indicators,
        key=lambda value: value.lower()
    )

    # -----------------------------------------------------
    # Per-IOC signal extraction.
    # -----------------------------------------------------

    detections = []

    for indicator in indicators:

        data = None

        for candidate in (
            indicator,
            indicator.lower(),
            indicator.upper()
        ):

            if candidate in correlation_map:
                data = correlation_map.get(
                    candidate
                )
                break

        if not isinstance(
            data,
            dict
        ):
            data = {}

        score = safe_float(
            data.get(
                "risk_score",
                data.get(
                    "threat_score",
                    0
                )
            )
        )

        severity = normalize_severity(
            data.get(
                "severity",
                "INFO"
            )
        )

        confidence = clamp(
            data.get(
                "confidence",
                0
            )
        )

        match_count = int(
            safe_float(
                data.get(
                    "match_count",
                    0
                )
            )
        )

        duplicate_count = int(
            safe_float(
                data.get(
                    "duplicate_evidence_count",
                    0
                )
            )
        )

        source_count = int(
            safe_float(
                data.get(
                    "independent_source_count",
                    data.get(
                        "source_count",
                        0
                    )
                )
            )
        )

        explicit_conflict = bool(
            data.get(
                "explicit_risk_conflict",
                data.get(
                    "conflict",
                    False
                )
            )
        )

        temporal_status = str(
            data.get(
                "temporal_status",
                "UNKNOWN"
            )
        ).strip().upper()

        mitre = safe_list(
            data.get(
                "mitre_attack"
            )
        )

        campaigns = safe_list(
            data.get(
                "campaigns",
                data.get(
                    "campaign",
                    []
                )
            )
        )

        signals = []

        if score >= 85:
            signals.append(
                "critical_risk"
            )
        elif score >= 65:
            signals.append(
                "high_risk"
            )
        elif score >= 40:
            signals.append(
                "medium_risk"
            )

        if match_count > 0:
            signals.append(
                "threat_intelligence_match"
            )

        if source_count >= 2:
            signals.append(
                "multi_source_confirmation"
            )

        if mitre:
            signals.append(
                "mitre_evidence"
            )

        if campaigns:
            signals.append(
                "campaign_evidence"
            )

        if temporal_status in {
            "FRESH",
            "RECENT"
        }:
            signals.append(
                "recent_temporal_evidence"
            )

        if explicit_conflict:
            signals.append(
                "evidence_conflict"
            )

        # Duplicate observations cannot increase alert
        # confidence merely by volume.
        effective_match_count = min(
            match_count,
            5
        )

        effective_source_count = min(
            source_count,
            5
        )

        detection_strength = (
            min(
                score / 100.0,
                1.0
            )
            * 0.50
            +
            clamp(
                confidence
            )
            * 0.25
            +
            min(
                effective_match_count / 5.0,
                1.0
            )
            * 0.10
            +
            min(
                effective_source_count / 3.0,
                1.0
            )
            * 0.15
        )

        detection_strength = clamp(
            detection_strength
        )

        detections.append(
            {
                "indicator": indicator,
                "score": round(
                    max(
                        0.0,
                        min(
                            score,
                            100.0
                        )
                    ),
                    2
                ),
                "severity": severity,
                "confidence": round(
                    confidence,
                    3
                ),
                "match_count": max(
                    0,
                    match_count
                ),
                "duplicate_evidence_count": max(
                    0,
                    duplicate_count
                ),
                "source_count": max(
                    0,
                    source_count
                ),
                "mitre_count": len(
                    mitre
                ),
                "campaign_count": len(
                    campaigns
                ),
                "temporal_status": temporal_status,
                "explicit_conflict": (
                    explicit_conflict
                ),
                "signals": sorted(
                    set(
                        signals
                    )
                ),
                "detection_strength": round(
                    detection_strength,
                    3
                )
            }
        )

    # -----------------------------------------------------
    # Global aggregation.
    # -----------------------------------------------------

    if not detections:

        alert_score = 0.0
        alert_confidence = 0.0
        alert_severity = "INFO"

    else:

        max_score = max(
            item["score"]
            for item in detections
        )

        strongest_severity = max(
            (
                item["severity"]
                for item in detections
            ),
            key=lambda value: severity_rank.get(
                value,
                1
            )
        )

        confidence_values = [
            item["confidence"]
            for item in detections
        ]

        weighted_confidence = (
            sum(
                confidence_values
            )
            /
            len(
                confidence_values
            )
        )

        # Independent high-strength signals receive bounded
        # correlation support.
        multi_signal_bonus = min(
            max(
                0,
                len(detections) - 1
            )
            * 4.0,
            12.0
        )

        high_strength_count = sum(
            1
            for item in detections
            if item.get(
                "detection_strength",
                0
            ) >= 0.70
        )

        correlation_bonus = min(
            high_strength_count
            * 2.0,
            8.0
        )

        conflict_count = sum(
            1
            for item in detections
            if item.get(
                "explicit_conflict"
            )
        )

        conflict_penalty = min(
            conflict_count
            * 4.0,
            8.0
        )

        alert_score = (
            max_score
            +
            multi_signal_bonus
            +
            correlation_bonus
            -
            conflict_penalty
        )

        alert_score = round(
            max(
                0.0,
                min(
                    alert_score,
                    100.0
                )
            ),
            2
        )

        alert_confidence = (
            weighted_confidence
            * 0.65
            +
            min(
                len(detections) / 4.0,
                1.0
            )
            * 0.20
            +
            (
                min(
                    high_strength_count / 3.0,
                    1.0
                )
                * 0.15
            )
        )

        if conflict_count:
            alert_confidence -= min(
                conflict_count
                * 0.05,
                0.15
            )

        alert_confidence = round(
            clamp(
                alert_confidence
            ),
            3
        )

        # Severity is based on aggregated score, but a clearly
        # critical IOC remains visible.
        if alert_score >= 85:
            alert_severity = "CRITICAL"
        elif alert_score >= 65:
            alert_severity = "HIGH"
        elif alert_score >= 40:
            alert_severity = "MEDIUM"
        elif (
            severity_rank.get(
                strongest_severity,
                1
            ) >= 2
            and
            alert_score >= 25
        ):
            alert_severity = strongest_severity
        else:
            alert_severity = "INFO"

    # -----------------------------------------------------
    # Deduplicated alert identity.
    #
    # Identity is based on the normalized set of indicators
    # and the core detection class, not raw evidence volume.
    # -----------------------------------------------------

    normalized_identity_parts = sorted(
        (
            str(
                item.get(
                    "indicator",
                    ""
                )
            ).strip().lower()
            for item in detections
            if str(
                item.get(
                    "indicator",
                    ""
                )
            ).strip()
        )
    )

    identity_seed = "|".join(
        normalized_identity_parts
    )

    alert_id = (
        "ALT-"
        +
        hashlib.sha256(
            identity_seed.encode(
                "utf-8"
            )
        ).hexdigest()[:12].upper()
    )

    # -----------------------------------------------------
    # Analyst reasons.
    # -----------------------------------------------------

    reasons = []

    high_count = sum(
        1
        for item in detections
        if item["severity"] in {
            "HIGH",
            "CRITICAL"
        }
    )

    confirmed_count = sum(
        1
        for item in detections
        if item["source_count"] >= 2
    )

    mitre_count = sum(
        item["mitre_count"]
        for item in detections
    )

    campaign_count = sum(
        item["campaign_count"]
        for item in detections
    )

    recent_count = sum(
        1
        for item in detections
        if item["temporal_status"] in {
            "FRESH",
            "RECENT"
        }
    )

    if high_count:
        reasons.append(
            (
                f"{high_count} indicator(s) "
                "have HIGH/CRITICAL severity."
            )
        )

    if confirmed_count:
        reasons.append(
            (
                f"{confirmed_count} indicator(s) "
                "have multi-source confirmation."
            )
        )

    if mitre_count:
        reasons.append(
            (
                f"{mitre_count} MITRE ATT&CK "
                "technique signal(s) are present."
            )
        )

    if campaign_count:
        reasons.append(
            (
                f"{campaign_count} campaign-related "
                "signal(s) are present."
            )
        )

    if recent_count:
        reasons.append(
            (
                f"{recent_count} indicator(s) carry "
                "fresh/recent temporal evidence."
            )
        )

    if conflict_count:
        reasons.append(
            (
                f"{conflict_count} indicator(s) contain "
                "explicit evidence conflict."
            )
        )

    if not reasons:
        reasons.append(
            "No strong correlated detection signal was identified."
        )

    # -----------------------------------------------------
    # Analyst headline.
    # -----------------------------------------------------

    if alert_severity == "CRITICAL":
        headline = (
            "Critical correlated threat activity detected"
        )
    elif alert_severity == "HIGH":
        headline = (
            "High-priority correlated threat activity detected"
        )
    elif alert_severity == "MEDIUM":
        headline = (
            "Correlated suspicious activity detected"
        )
    elif detections:
        headline = (
            "Low-confidence threat activity detected"
        )
    else:
        headline = (
            "No actionable threat alert generated"
        )

    # -----------------------------------------------------
    # Alert status semantics.
    # -----------------------------------------------------

    if not detections:
        status = "NO_ALERT"

    elif alert_severity in {
        "CRITICAL",
        "HIGH"
    }:
        status = "OPEN"

    elif alert_confidence >= 0.65:
        status = "OPEN"

    else:
        status = "REVIEW"

    # -----------------------------------------------------
    # Detection deduplication telemetry.
    # -----------------------------------------------------

    raw_detection_count = len(
        detections
    )

    normalized_detection_count = len(
        {
            item["indicator"].lower()
            for item in detections
        }
    )

    duplicate_detections_suppressed = max(
        0,
        raw_detection_count
        -
        normalized_detection_count
    )

    return {
        "alert_id": alert_id,
        "status": status,
        "headline": headline,
        "severity": alert_severity,
        "alert_score": alert_score,
        "confidence": alert_confidence,
        "indicator_count": normalized_detection_count,
        "raw_detection_count": raw_detection_count,
        "duplicate_detections_suppressed": (
            duplicate_detections_suppressed
        ),
        "high_priority_indicator_count": high_count,
        "multi_source_confirmed_count": confirmed_count,
        "mitre_signal_count": mitre_count,
        "campaign_signal_count": campaign_count,
        "recent_signal_count": recent_count,
        "conflict_indicator_count": conflict_count,
        "signals": sorted(
            {
                signal
                for item in detections
                for signal in item.get(
                    "signals",
                    []
                )
            }
        ),
        "detections": sorted(
            detections,
            key=lambda item: (
                -severity_rank.get(
                    item.get(
                        "severity",
                        "INFO"
                    ),
                    1
                ),
                -safe_float(
                    item.get(
                        "score",
                        0
                    )
                ),
                item.get(
                    "indicator",
                    ""
                ).lower()
            )
        ),
        "analyst_reasons": reasons,
        "correlation": {
            "multi_signal_bonus": round(
                min(
                    max(
                        multi_signal_bonus,
                        0
                    ),
                    12.0
                ),
                2
            ),
            "high_strength_bonus": round(
                min(
                    max(
                        correlation_bonus,
                        0
                    ),
                    8.0
                ),
                2
            ),
            "conflict_penalty": round(
                min(
                    max(
                        conflict_penalty,
                        0
                    ),
                    8.0
                ),
                2
            ),
            "bounded": True
        }
    }


def _soc95_analyze_threat_intelligence_v2_base(
    indicators,
    matches=None,
    ip_intelligence=None
):
    indicators = indicators or []
    matches = matches or {}
    ip_intelligence = ip_intelligence or {}

    indicator_types = Counter()
    severity_distribution = Counter()

    correlation_map = {}
    high_risk_indicators = []
    mitre_techniques = set()
    threat_sources = set()

    total_score = 0
    scored_indicators = 0

    for indicator in indicators:

        if not isinstance(indicator, dict):
            continue

        value = (
            indicator.get("value")
            or indicator.get("ioc")
            or indicator.get("indicator")
        )

        indicator_type = (
            indicator.get("type")
            or indicator.get("ioc_type")
            or "unknown"
        )

        indicator_type = str(
            indicator_type
        ).lower()

        indicator_types[indicator_type] += 1

        score = indicator.get(
            "threat_score",
            indicator.get(
                "risk_score",
                0
            )
        )

        try:
            score = float(score)
        except Exception:
            score = 0

        if score <= 0:
            score = 10

        matched_records = []

        if isinstance(matches, dict) and value:
            matched_records = matches.get(
                value,
                []
            )

        match_count = len(
            matched_records
        ) if isinstance(
            matched_records,
            list
        ) else 0

        evidence_quality_data = _evaluate_source_evidence(
            matched_records
        )

        unique_evidence_count = evidence_quality_data[
            "unique_evidence_count"
        ]

        duplicate_evidence_count = evidence_quality_data[
            "duplicate_evidence_count"
        ]

        source_names = set(
            evidence_quality_data[
                "source_names"
            ]
        )

        independent_source_count = evidence_quality_data[
            "independent_source_count"
        ]

        source_families = evidence_quality_data[
            "source_families"
        ]

        source_reliability = float(
            evidence_quality_data[
                "source_reliability"
            ]
        )

        source_reliability_grade = evidence_quality_data[
            "source_reliability_grade"
        ]

        evidence_diversity = float(
            evidence_quality_data[
                "evidence_diversity"
            ]
        )

        mitre_for_indicator = set()

        for record in _safe_list(
            matched_records
        ):

            if not isinstance(record, dict):
                continue

            source = record.get("source")

            if source:
                threat_sources.add(
                    str(source)
                )

            for technique in _safe_list(
                record.get(
                    "mitre_attack"
                )
            ):

                if technique:
                    mitre_for_indicator.add(
                        str(technique)
                    )
                    mitre_techniques.add(
                        str(technique)
                    )

        temporal_profiles = []

        for record in _safe_list(matched_records):
            if isinstance(record, dict):
                temporal_profiles.append(
                    _evidence_temporal_profile(record)
                )

        temporal_factors = [
            float(item.get("freshness_factor", 0.50))
            for item in temporal_profiles
            if item.get("freshness_factor") is not None
        ]

        temporal_factor = (
            sum(temporal_factors) / len(temporal_factors)
            if temporal_factors
            else 0.50
        )

        temporal_factor = max(
            0.40,
            min(
                temporal_factor,
                1.00
            )
        )

        temporal_bonus = round(
            (
                temporal_factor - 0.40
            ) * 4.0,
            2
        )

        # Authoritative temporal status for this indicator.
        # Never infer semantic status again from the averaged
        # freshness factor. The temporal profile helper owns
        # the status classification.
        valid_temporal_statuses = [
            str(
                item.get(
                    "temporal_status",
                    "UNKNOWN"
                )
            ).strip().upper()
            for item in temporal_profiles
            if item.get("age_hours") is not None
        ]

        temporal_status_priority = {
            "HISTORICAL": 0,
            "STALE": 1,
            "AGING": 2,
            "CURRENT": 3,
            "RECENT": 4,
            "FRESH": 5,
        }

        valid_temporal_statuses = [
            status
            for status in valid_temporal_statuses
            if status in temporal_status_priority
        ]

        temporal_status = (
            min(
                valid_temporal_statuses,
                key=lambda status:
                temporal_status_priority[status]
            )
            if valid_temporal_statuses
            else "UNKNOWN"
        )

        temporal_age_values = [
            float(
                item.get(
                    "age_hours"
                )
            )
            for item in temporal_profiles
            if item.get("age_hours") is not None
        ]

        temporal_age_hours = (
            round(
                sum(temporal_age_values)
                / len(temporal_age_values),
                2
            )
            if temporal_age_values
            else None
        )

        temporal_timestamp_sources = sorted({
            str(
                item.get(
                    "timestamp_source"
                )
            )
            for item in temporal_profiles
            if item.get("timestamp_source")
        })


        # SOC evidence weighting:
        # duplicate records are explicitly capped and do not count as
        # independent confirmation; source diversity and reliability have
        # bounded influence to prevent score inflation.

        effective_evidence_count = min(
            unique_evidence_count,
            5
        )

        evidence_bonus = min(
            effective_evidence_count * 4,
            16
        )

        independence_bonus = min(
            max(
                independent_source_count - 1,
                0
            ) * 5,
            10
        )

        reliability_bonus = round(
            max(
                0.0,
                min(
                    source_reliability,
                    1.0
                ) - 0.50
            ) * 8.0,
            2
        )

        diversity_bonus = round(
            max(
                0.0,
                min(
                    evidence_diversity,
                    1.0
                )
            ) * 3.0,
            2
        )

        duplicate_penalty = min(
            duplicate_evidence_count * 1.5,
            5
        )

        correlation_bonus = round(
            max(
                0.0,
                evidence_bonus +
                independence_bonus +
                reliability_bonus +
                diversity_bonus +
                temporal_bonus -
                duplicate_penalty
            ),
            2
        )

        source_bonus = round(
            min(
                source_reliability * 6.0,
                6.0
            ),
            2
        )

        # IOC type-aware risk weighting
        type_weight = IOC_TYPE_WEIGHTS.get(
            indicator_type,
            IOC_TYPE_WEIGHTS["unknown"]
        )

        weighted_score = score * type_weight

        # -----------------------------------------------------
        # SOC-GRADE RISK CALIBRATION
        # -----------------------------------------------------
        #
        # The raw threat score is the primary signal.
        # Evidence quality modifies it only within bounded
        # limits so no single subsystem can dominate.
        # -----------------------------------------------------

        base_risk_score = round(
            weighted_score +
            correlation_bonus +
            source_bonus,
            2
        )

        # Raw evidence available for explicit polarity checks.
        raw_records_for_risk = _safe_list(
            matched_records
        )

        verdict_profile = _evidence_verdict_profile(
            raw_records_for_risk
        )

        explicit_risk_conflict = bool(
            verdict_profile.get(
                "explicit_conflict",
                False
            )
        )

        malicious_evidence_count = int(
            verdict_profile.get(
                "known_positive",
                0
            ) or 0
        )

        benign_evidence_count = int(
            verdict_profile.get(
                "known_negative",
                0
            ) or 0
        )

        # Evidence strength is based on unique evidence rather
        # than raw duplicate count.
        evidence_quality_factor = (
            min(
                unique_evidence_count,
                5
            ) / 5.0
        )

        evidence_quality_modifier = round(
            (
                evidence_quality_factor - 0.40
            ) * 4.0,
            2
        )

        # Independent-source contribution is bounded.
        independence_modifier = round(
            min(
                max(
                    independent_source_count - 1,
                    0
                ) * 1.75,
                5.0
            ),
            2
        )

        # Higher source reliability provides only a modest
        # upward calibration.
        reliability_modifier = round(
            max(
                0.0,
                min(
                    source_reliability,
                    1.0
                ) - 0.70
            ) * 4.0,
            2
        )

        # Diversity rewards genuinely different source families.
        diversity_modifier = round(
            max(
                0.0,
                min(
                    evidence_diversity,
                    1.0
                )
            ) * 2.0,
            2
        )

        # Temporal freshness changes risk mildly; stale evidence
        # must never become stronger than fresh evidence.
        temporal_modifier = round(
            (
                temporal_factor - 0.70
            ) * 3.0,
            2
        )

        temporal_modifier = max(
            -0.90,
            min(
                temporal_modifier,
                0.90
            )
        )

        # Duplicate evidence can suppress confidence of the
        # calibration, but does not create additional risk.
        duplicate_modifier = -min(
            duplicate_evidence_count * 0.50,
            2.0
        )

        # Explicit malicious-vs-benign contradiction gets the
        # strongest risk-side uncertainty penalty.
        conflict_modifier = 0.0

        if explicit_risk_conflict:

            conflict_strength = min(
                (
                    min(
                        malicious_evidence_count,
                        3
                    ) * 1.25
                )
                + (
                    min(
                        benign_evidence_count,
                        3
                    ) * 1.25
                ),
                5.0
            )

            # Conflict must remain materially visible even when
            # the pre-calibration score is already above 100.
            # This prevents max-score saturation from erasing
            # contradictory-evidence uncertainty.
            conflict_modifier = -round(
                min(
                    12.0,
                    6.0 + conflict_strength
                ),
                2
            )

        # Aggregate only modest calibration deltas.
        evidence_calibration_modifier = round(
            evidence_quality_modifier
            + independence_modifier
            + reliability_modifier
            + diversity_modifier
            + temporal_modifier
            + duplicate_modifier
            + conflict_modifier,
            2
        )

        calibrated_score = round(
            base_risk_score
            + evidence_calibration_modifier,
            2
        )

        final_score = min(
            max(
                calibrated_score,
                0.0
            ),
            100.0
        )


        severity = _severity_from_score(
            final_score
        )

        severity_distribution[
            severity
        ] += 1

        total_score += final_score
        scored_indicators += 1

        # -------------------------------------
        # ADVANCED EVIDENCE CONFIDENCE MODEL
        # -------------------------------------

        confidence = 0.25

        # Evidence from correlation count
        if match_count:
            confidence += min(
                match_count * 0.06,
                0.25
            )

        # Independent threat-source diversity
        source_diversity = len(source_names)

        if source_diversity:
            confidence += min(
                source_diversity * 0.07,
                0.20
            )

        # MITRE ATT&CK evidence increases analytical confidence
        mitre_evidence_count = len(mitre_for_indicator)

        if mitre_evidence_count:
            confidence += min(
                mitre_evidence_count * 0.04,
                0.10
            )

        # IOC type reliability
        type_reliability = min(
            max(type_weight / 1.30, 0.50),
            1.00
        )

        confidence += (
            type_reliability * 0.10
        )

        # Stronger risk evidence increases confidence
        if final_score >= 85:
            confidence += 0.10
        elif final_score >= 65:
            confidence += 0.07
        elif final_score >= 40:
            confidence += 0.04

        # Penalize weak or isolated evidence
        if not match_count and not source_names:
            confidence -= 0.08

        confidence = min(
            max(
                round(confidence, 3),
                0.10
            ),
            0.99
        )

        correlation_map[


            str(value)


        ] = {


            "indicator": value,


            "type": indicator_type,


            "risk_score": final_score,


            "severity": severity,


            "confidence": confidence,


            "match_count": unique_evidence_count,


            "raw_match_count": match_count,


            "unique_evidence_count": unique_evidence_count,


            "duplicate_evidence_count": duplicate_evidence_count,


            "sources": sorted(source_names),


            "independent_source_count": independent_source_count,


            "source_families": source_families,


            "source_reliability": source_reliability,


            "source_reliability_grade": source_reliability_grade,


            "evidence_diversity": evidence_diversity,

            "risk_calibration": {
                "base_risk_score": base_risk_score,
                "evidence_quality_modifier": (
                    evidence_quality_modifier
                ),
                "independence_modifier": (
                    independence_modifier
                ),
                "reliability_modifier": (
                    reliability_modifier
                ),
                "diversity_modifier": (
                    diversity_modifier
                ),
                "temporal_modifier": (
                    temporal_modifier
                ),
                "duplicate_modifier": (
                    duplicate_modifier
                ),
                "conflict_modifier": (
                    conflict_modifier
                ),
                "calibration_modifier": (
                    evidence_calibration_modifier
                ),
                "calibrated_score": final_score,
                "explicit_conflict": (
                    explicit_risk_conflict
                )
            },

            "temporal_factor": temporal_factor,
            "temporal_bonus": temporal_bonus,
            "temporal_status": temporal_status,
            "temporal_age_hours": temporal_age_hours,
            "temporal_timestamp_sources": (
                temporal_timestamp_sources
            ),


            "mitre_attack": sorted(mitre_for_indicator)


        }

        if severity in (
            "CRITICAL",
            "HIGH"
        ):

            high_risk_indicators.append(
                correlation_map[
                    str(value)
                ]
            )

    # -------------------------------------
    # CROSS-INDICATOR CORRELATION ENGINE
    # -------------------------------------

    indicator_clusters = []
    correlation_relationships = []
    campaign_correlation_bonus = 0

    domain_indicators = []
    url_indicators = []
    ip_indicators = []
    hash_indicators = []

    for correlation_value, correlation_data in correlation_map.items():

        if not isinstance(correlation_data, dict):
            continue

        correlation_type = str(
            correlation_data.get(
                "type",
                "unknown"
            )
        ).lower()

        if correlation_type == "domain":
            domain_indicators.append(
                correlation_data
            )

        elif correlation_type == "url":
            url_indicators.append(
                correlation_data
            )

        elif correlation_type in (
            "ip",
            "ip:port"
        ):
            ip_indicators.append(
                correlation_data
            )

        elif correlation_type in (
            "hash",
            "sha256",
            "sha1",
            "md5"
        ):
            hash_indicators.append(
                correlation_data
            )

    # URL -> Domain infrastructure relationships
    for url_data in url_indicators:

        url_value = str(
            url_data.get(
                "indicator",
                ""
            )
        ).lower()

        related_domains = []

        for domain_data in domain_indicators:

            domain_value = str(
                domain_data.get(
                    "indicator",
                    ""
                )
            ).lower()

            if domain_value and domain_value in url_value:

                related_domains.append(
                    domain_data.get(
                        "indicator"
                    )
                )

                correlation_relationships.append({
                    "relationship": "url_domain",
                    "source": url_data.get(
                        "indicator"
                    ),
                    "related": domain_data.get(
                        "indicator"
                    ),
                    "strength": "HIGH"
                })

        if related_domains:

            indicator_clusters.append({
                "cluster_type": "infrastructure",
                "primary_indicator": url_data.get(
                    "indicator"
                ),
                "related_indicators": related_domains,
                "relationship_count": len(
                    related_domains
                ),
                "risk_level": "HIGH"
            })

    # Shared threat-source correlation
    source_indicator_map = {}

    for correlation_value, correlation_data in correlation_map.items():

        for source in correlation_data.get(
            "sources",
            []
        ):

            source_indicator_map.setdefault(
                source,
                []
            ).append(
                correlation_data.get(
                    "indicator"
                )
            )

    for source, related_indicators in (
        source_indicator_map.items()
    ):

        unique_related = sorted(
            set(
                item
                for item in related_indicators
                if item
            )
        )

        if len(unique_related) >= 2:

            correlation_relationships.append({
                "relationship": "shared_threat_source",
                "source": source,
                "related": unique_related,
                "strength": (
                    "HIGH"
                    if len(unique_related) >= 4
                    else "MEDIUM"
                )
            })

            indicator_clusters.append({
                "cluster_type": "source_correlation",
                "primary_indicator": source,
                "related_indicators": unique_related,
                "relationship_count": len(
                    unique_related
                ),
                "risk_level": (
                    "HIGH"
                    if len(unique_related) >= 4
                    else "MEDIUM"
                )
            })

    # -----------------------------------------------------
    # ADVANCED CAMPAIGN GRAPH / CLUSTER INTELLIGENCE
    # -----------------------------------------------------
    #
    # Existing relationship logic remains authoritative.
    # This adds deterministic graph-ready IOC-to-IOC
    # relationships and connected campaign clusters.
    # -----------------------------------------------------

    campaign_graph = _build_campaign_graph(
        correlation_map,
        matches
    )

    # -----------------------------------------------------
    # SOC 9.5 INFRASTRUCTURE REUSE INTELLIGENCE
    # -----------------------------------------------------

    infrastructure_reuse_intelligence = (
        _build_infrastructure_reuse_intelligence(
            correlation_map,
            matches,
            ip_intelligence
        )
    )


    relationship_graph = campaign_graph.get(
        "graph",
        {
            "nodes": [],
            "edges": [],
            "node_count": 0,
            "edge_count": 0,
            "cluster_count": 0
        }
    )

    campaign_clusters = campaign_graph.get(
        "campaign_clusters",
        []
    )

    campaign_graph_confidence = float(
        campaign_graph.get(
            "campaign_confidence",
            0
        ) or 0
    )

    strong_relationship_count = int(
        campaign_graph.get(
            "strong_relationship_count",
            0
        ) or 0
    )

    campaign_graph_bonus = float(
        campaign_graph.get(
            "campaign_graph_bonus",
            0
        ) or 0
    )

    # Do not allow graph enrichment to dominate the existing
    # bounded campaign score. It is intentionally capped.
    campaign_correlation_bonus = min(
        round(
            campaign_correlation_bonus
            + campaign_graph_bonus,
            2
        ),
        20
    )

    # -----------------------------------------------------
    # HISTORICAL THREAT RECURRENCE INTELLIGENCE
    # -----------------------------------------------------

    historical_recurrence = (
        _build_historical_recurrence_intelligence(
            correlation_map,
            matches
        )
    )

    # -----------------------------------------------------
    # SOC 9.5 MITRE ATT&CK ATTACK CHAIN INTELLIGENCE
    # -----------------------------------------------------

    mitre_attack_chain_intelligence = (
        _build_mitre_attack_chain_intelligence(
            correlation_map,
            matches
        )
    )

    # -----------------------------------------------------
    # SOC 9.5 CYBER KILL CHAIN INTELLIGENCE
    # -----------------------------------------------------

    cyber_kill_chain_intelligence = (
        _build_cyber_kill_chain_intelligence(
            correlation_map,
            matches
        )
    )



    # -----------------------------------------------------
    # SOC 9.5 THREAT TIMELINE CORRELATION
    # -----------------------------------------------------

    threat_timeline_correlation = (
        _build_threat_timeline_correlation(
            correlation_map,
            matches
        )
    )

    # -----------------------------------------------------
    # SOC 9.5 ALERT INTELLIGENCE / DETECTION CORRELATION
    # -----------------------------------------------------

    alert_intelligence = (
        _build_alert_intelligence(
            correlation_map,
            matches
        )
    )



    historical_recurrence_bonus = min(
        max(
            float(
                historical_recurrence.get(
                    "total_recurrence_bonus",
                    0
                ) or 0
            ),
            0.0
        ),
        6.0
    )

    # Historical recurrence is supporting evidence only.
    # Keep the existing campaign score bounded.
    campaign_correlation_bonus = min(
        round(
            campaign_correlation_bonus
            + (
                historical_recurrence_bonus
                * 0.50
            ),
            2
        ),
        20
    )

    # Multi-indicator campaign detection
    unique_indicator_count = len(
        correlation_map
    )

    high_risk_cluster_count = len([
        cluster
        for cluster in indicator_clusters
        if cluster.get(
            "risk_level"
        ) == "HIGH"
    ])

    if unique_indicator_count >= 3:

        campaign_correlation_bonus += min(
            unique_indicator_count * 2,
            10
        )

    if high_risk_cluster_count:

        campaign_correlation_bonus += min(
            high_risk_cluster_count * 3,
            10
        )

    campaign_correlation_bonus = min(
        campaign_correlation_bonus,
        20
    )

    # IP Intelligence correlation
    ip_risk_count = 0

    if isinstance(
        ip_intelligence,
        dict
    ):

        for ip, result in (
            ip_intelligence.items()
        ):

            if not isinstance(
                result,
                dict
            ):
                continue

            risk = str(
                result.get(
                    "risk",
                    "UNKNOWN"
                )
            ).upper()

            if risk in (
                "CRITICAL",
                "HIGH"
            ):

                ip_risk_count += 1

                high_risk_indicators.append({
                    "indicator": ip,
                    "type": "ip",
                    "risk_score": result.get(
                        "risk_score",
                        0
                    ),
                    "severity": risk,
                    "confidence": result.get(
                        "confidence",
                        0
                    ),
                    "match_count": 0,
                    "sources": [
                        "ip-intelligence-v2"
                    ],
                    "mitre_attack": []
                })

    average_score = 0

    if scored_indicators:

        average_score = round(
            total_score /
            scored_indicators,
            2
        )

    # -------------------------------------
    # ADVANCED EXPLAINABLE RISK MODEL
    # -------------------------------------

    # Every score contribution is stored separately.
    # This allows analysts and the frontend to understand
    # exactly why the final threat score was produced.

    base_intelligence_score = round(
        average_score,
        2
    )

    indicator_normalization_impact = 0
    correlation_impact = 0
    high_risk_impact = 0
    ip_intelligence_impact = 0

    # Primary intelligence evidence with calibrated
    # normalization to reduce score saturation.

    if scored_indicators:

        normalized_intelligence_score = (
            average_score * 0.88
        )

        indicator_normalization_impact = (
            min(
                scored_indicators,
                10
            ) * 0.8
        )

        overall_score = (
            normalized_intelligence_score +
            indicator_normalization_impact
        )

    else:

        normalized_intelligence_score = 0
        overall_score = 0

    # Campaign correlation enrichment.
    # Correlation strengthens confidence that multiple
    # indicators belong to the same malicious operation.

    if campaign_correlation_bonus:

        correlation_impact = min(
            campaign_correlation_bonus * 0.60,
            8
        )

        overall_score += correlation_impact

    # High-risk indicator enrichment with diminishing
    # returns to prevent artificial score inflation.

    high_risk_count = len([
        item
        for item in high_risk_indicators
        if item.get("severity") in (
            "CRITICAL",
            "HIGH"
        )
    ])

    if high_risk_count:

        high_risk_impact = min(
            2 +
            (
                max(
                    high_risk_count - 1,
                    0
                ) * 1.5
            ),
            8
        )

        overall_score += high_risk_impact

    # IP intelligence contributes supporting
    # infrastructure evidence.

    if ip_risk_count:

        ip_intelligence_impact = min(
            ip_risk_count * 2,
            5
        )

        overall_score += ip_intelligence_impact

    # Preserve the score before final ceiling protection.

    calculated_score = round(
        overall_score,
        2
    )

    # Prevent artificial inflation while preserving
    # genuinely critical evidence.

    overall_score = min(
        calculated_score,
        100
    )

    # -------------------------------------
    # RISK EXPLAINABILITY ENGINE
    # -------------------------------------

    primary_risk_drivers = []

    if base_intelligence_score >= 70:

        primary_risk_drivers.append({
            "driver": "strong_threat_intelligence",
            "impact": round(
                normalized_intelligence_score,
                2
            ),
            "description": (
                "Multiple indicators carry strong "
                "threat intelligence risk evidence."
            )
        })

    elif base_intelligence_score >= 40:

        primary_risk_drivers.append({
            "driver": "moderate_threat_intelligence",
            "impact": round(
                normalized_intelligence_score,
                2
            ),
            "description": (
                "Indicators contain moderate threat "
                "intelligence evidence."
            )
        })

    if indicator_normalization_impact:

        primary_risk_drivers.append({
            "driver": "multi_indicator_evidence",
            "impact": round(
                indicator_normalization_impact,
                2
            ),
            "description": (
                f"{scored_indicators} indicators contributed "
                "to the intelligence assessment."
            )
        })

    if correlation_impact:

        primary_risk_drivers.append({
            "driver": "campaign_correlation",
            "impact": round(
                correlation_impact,
                2
            ),
            "description": (
                "Indicators show correlation patterns "
                "consistent with coordinated infrastructure "
                "or campaign activity."
            )
        })

    if high_risk_impact:

        primary_risk_drivers.append({
            "driver": "high_risk_indicators",
            "impact": round(
                high_risk_impact,
                2
            ),
            "description": (
                f"{high_risk_count} high-risk or critical "
                "indicators were identified."
            )
        })

    if ip_intelligence_impact:

        primary_risk_drivers.append({
            "driver": "ip_infrastructure_risk",
            "impact": round(
                ip_intelligence_impact,
                2
            ),
            "description": (
                f"{ip_risk_count} high-risk infrastructure "
                "signals were detected."
            )
        })

    # Sort risk drivers by contribution.

    primary_risk_drivers.sort(
        key=lambda item:
        item.get(
            "impact",
            0
        ),
        reverse=True
    )

    # Generate an analyst-readable threat headline.

    if overall_score >= 85:

        analyst_headline = (
            "Critical multi-source threat evidence detected"
        )

    elif overall_score >= 65:

        analyst_headline = (
            "High-confidence malicious activity detected"
        )

    elif overall_score >= 40:

        analyst_headline = (
            "Suspicious activity requires further investigation"
        )

    else:

        analyst_headline = (
            "Limited threat evidence detected"
        )

    risk_explanation = {
        "base_intelligence_score": (
            base_intelligence_score
        ),
        "normalized_intelligence_score": round(
            normalized_intelligence_score,
            2
        ),
        "indicator_normalization_impact": round(
            indicator_normalization_impact,
            2
        ),
        "campaign_correlation_impact": round(
            correlation_impact,
            2
        ),
        "campaign_graph": {
            "node_count": relationship_graph.get(
                "node_count",
                0
            ),
            "edge_count": relationship_graph.get(
                "edge_count",
                0
            ),
            "cluster_count": len(
                campaign_clusters
            ),
            "campaign_confidence": round(
                campaign_graph_confidence,
                3
            ),
            "strong_relationship_count": (
                strong_relationship_count
            ),
            "graph_bonus": round(
                campaign_graph_bonus,
                2
            )
        },
        "high_risk_indicator_impact": round(
            high_risk_impact,
            2
        ),
        "ip_intelligence_impact": round(
            ip_intelligence_impact,
            2
        ),
        "calculated_score": calculated_score,
        "final_score": overall_score,
        "historical_recurrence": {
            "detected": historical_recurrence.get(
                "detected",
                False
            ),
            "indicator_count": historical_recurrence.get(
                "indicator_count",
                0
            ),
            "recurring_indicator_count": historical_recurrence.get(
                "recurring_indicator_count",
                0
            ),
            "persistent_indicator_count": historical_recurrence.get(
                "persistent_indicator_count",
                0
            ),
            "overall_confidence": historical_recurrence.get(
                "overall_confidence",
                0
            ),
            "total_recurrence_bonus": round(
                historical_recurrence_bonus,
                2
            )
        },
        "risk_calibration": {
            "calibrated_ioc_count": len(
                correlation_map
            ),
            "explicit_conflict_ioc_count": len([
                item
                for item in correlation_map.values()
                if isinstance(item, dict)
                and item.get(
                    "risk_calibration",
                    {}
                ).get(
                    "explicit_conflict",
                    False
                )
            ]),
            "total_calibration_modifier": round(
                sum(
                    float(
                        item.get(
                            "risk_calibration",
                            {}
                        ).get(
                            "calibration_modifier",
                            0
                        ) or 0
                    )
                    for item in correlation_map.values()
                    if isinstance(item, dict)
                ),
                2
            )
        },
        "primary_risk_drivers": (
            primary_risk_drivers
        )
    }

    analyst_summary = {
        "headline": analyst_headline,
        "severity": _severity_from_score(
            overall_score
        ),
        "indicator_count": scored_indicators,
        "high_risk_indicator_count": (
            high_risk_count
        ),
        "campaign_detected": bool(
            indicator_clusters or
            correlation_relationships
        ),
        "threat_source_count": len(
            threat_sources
        ),
        "mitre_technique_count": len(
            mitre_techniques
        )
    }

    overall_severity = (
        _severity_from_score(
            overall_score
        )
    )

    # -------------------------------------
    # CONFIDENCE & FALSE POSITIVE ENGINE
    # -------------------------------------

    confidence_score = 0.50
    confidence_reasons = []

    private_or_local_indicator_count = 0
    single_source_indicator_count = 0
    multi_source_indicator_count = 0
    conflicting_indicator_count = 0

    indicator_confidence_scores = []

    for confidence_value, confidence_data in (
        correlation_map.items()
    ):

        if not isinstance(
            confidence_data,
            dict
        ):
            continue

        indicator_value = str(
            confidence_data.get(
                "indicator",
                ""
            )
        ).lower()

        indicator_type = str(
            confidence_data.get(
                "type",
                ""
            )
        ).lower()

        indicator_sources = confidence_data.get(
            "sources",
            []
        )

        indicator_risk = float(
            confidence_data.get(
                "risk_score",
                0
            ) or 0
        )

        indicator_confidence = float(
            confidence_data.get(
                "confidence",
                0
            ) or 0
        )

        indicator_confidence_scores.append(
            indicator_confidence
        )

        # Detect common non-public infrastructure.
        is_private_or_local = False

        if indicator_value in (
            "localhost",
            "127.0.0.1",
            "::1"
        ):

            is_private_or_local = True

        elif indicator_type in (
            "ip",
            "ip:port"
        ):

            ip_value = indicator_value.split(
                ":"
            )[0]

            if (
                ip_value.startswith("10.") or
                ip_value.startswith("192.168.") or
                ip_value.startswith("172.16.") or
                ip_value.startswith("172.17.") or
                ip_value.startswith("172.18.") or
                ip_value.startswith("172.19.") or
                ip_value.startswith("172.20.") or
                ip_value.startswith("172.21.") or
                ip_value.startswith("172.22.") or
                ip_value.startswith("172.23.") or
                ip_value.startswith("172.24.") or
                ip_value.startswith("172.25.") or
                ip_value.startswith("172.26.") or
                ip_value.startswith("172.27.") or
                ip_value.startswith("172.28.") or
                ip_value.startswith("172.29.") or
                ip_value.startswith("172.30.") or
                ip_value.startswith("172.31.") or
                ip_value.startswith("127.")
            ):

                is_private_or_local = True

        if is_private_or_local:

            private_or_local_indicator_count += 1

        source_count = len(
            set(
                source
                for source in indicator_sources
                if source
            )
        )

        if source_count <= 1:

            single_source_indicator_count += 1

        elif source_count >= 2:

            multi_source_indicator_count += 1

        # Detect conflicting evidence patterns.
        if (
            indicator_risk >= 70 and
            indicator_confidence < 0.45
        ):

            conflicting_indicator_count += 1

    # Evidence confidence aggregation.

    if scored_indicators:

        confidence_score += min(
            scored_indicators * 0.03,
            0.15
        )

    if multi_source_indicator_count:

        multi_source_boost = min(
            multi_source_indicator_count * 0.06,
            0.18
        )

        confidence_score += multi_source_boost

        confidence_reasons.append(
            "multi_source_consensus"
        )

    if high_risk_count:

        confidence_score += min(
            high_risk_count * 0.025,
            0.10
        )

        confidence_reasons.append(
            "high_risk_evidence"
        )

    if campaign_correlation_bonus:

        confidence_score += min(
            campaign_correlation_bonus * 0.01,
            0.08
        )

        confidence_reasons.append(
            "campaign_correlation"
        )

    # Weak evidence reduces confidence.

    if single_source_indicator_count:

        single_source_penalty = min(
            single_source_indicator_count * 0.02,
            0.08
        )

        confidence_score -= single_source_penalty

    # Private/local infrastructure is more likely
    # to require environmental context.

    if private_or_local_indicator_count:

        private_indicator_penalty = min(
            private_or_local_indicator_count * 0.04,
            0.12
        )

        confidence_score -= private_indicator_penalty

        confidence_reasons.append(
            "private_or_local_context_required"
        )

    # Conflicting evidence reduces certainty.

    if conflicting_indicator_count:

        conflict_penalty = min(
            conflicting_indicator_count * 0.05,
            0.15
        )

        confidence_score -= conflict_penalty

        confidence_reasons.append(
            "conflicting_evidence_detected"
        )

    # Average per-indicator confidence contributes
    # to final intelligence confidence.

    average_indicator_confidence = 0

    if indicator_confidence_scores:

        average_indicator_confidence = sum(
            indicator_confidence_scores
        ) / len(
            indicator_confidence_scores
        )

        confidence_score = (
            confidence_score * 0.75
        ) + (
            average_indicator_confidence * 0.25
        )

    # ---------------------------------------------------------
    # SOC TEMPORAL CONFIDENCE HARDENING
    # ---------------------------------------------------------
    temporal_factors_for_confidence = []
    temporal_status_counts = {
        "FRESH": 0,
        "RECENT": 0,
        "CURRENT": 0,
        "AGING": 0,
        "STALE": 0,
        "HISTORICAL": 0,
        "UNKNOWN": 0,
    }

    for temporal_item in correlation_map.values():
        if not isinstance(
            temporal_item,
            dict
        ):
            continue

        try:
            factor = temporal_item.get(
                "temporal_factor"
            )

            if factor is not None:
                temporal_factors_for_confidence.append(
                    max(
                        0.40,
                        min(
                            float(factor),
                            1.00
                        )
                    )
                )
        except Exception:
            pass

        temporal_status = str(
            temporal_item.get(
                "temporal_status",
                "UNKNOWN"
            )
        ).strip().upper()

        if temporal_status in temporal_status_counts:
            temporal_status_counts[
                temporal_status
            ] += 1
        else:
            temporal_status_counts[
                "UNKNOWN"
            ] += 1

    average_temporal_factor = (
        sum(temporal_factors_for_confidence)
        / len(temporal_factors_for_confidence)
        if temporal_factors_for_confidence
        else 0.50
    )

    average_temporal_factor = max(
        0.40,
        min(
            average_temporal_factor,
            1.00
        )
    )
    temporal_unknown_count = (
        temporal_status_counts.get(
            "UNKNOWN",
            0
        )
    )

    # 0.70 is neutral. The adjustment is intentionally bounded.
    temporal_confidence_adjustment = round(
        (
            average_temporal_factor - 0.70
        ) * 0.15,
        3
    )

    confidence_score += (
        temporal_confidence_adjustment
    )

    if average_temporal_factor >= 0.85:
        confidence_reasons.append(
            "fresh_temporal_evidence"
        )
    elif average_temporal_factor < 0.55:
        confidence_reasons.append(
            "stale_temporal_evidence"
        )
    elif not temporal_factors_for_confidence:
        confidence_reasons.append(
            "temporal_evidence_unknown"
        )


    confidence_score = round(
        min(
            max(
                confidence_score,
                0.05
            ),
            0.99
        ),
        3
    )

    # Evidence quality classification.

    if confidence_score >= 0.85:

        evidence_quality = "VERY_HIGH"

    elif confidence_score >= 0.70:

        evidence_quality = "HIGH"

    elif confidence_score >= 0.50:

        evidence_quality = "MODERATE"

    else:

        evidence_quality = "LOW"

    # Source consensus classification.

    if multi_source_indicator_count >= 3:

        source_consensus = "STRONG"

    elif multi_source_indicator_count >= 1:

        source_consensus = "MODERATE"

    elif single_source_indicator_count:

        source_consensus = "LIMITED"

    else:

        source_consensus = "UNKNOWN"

    # False positive probability estimation.

    false_positive_probability = 0.50

    false_positive_probability -= (
        confidence_score * 0.45
    )

    if multi_source_indicator_count:

        false_positive_probability -= min(
            multi_source_indicator_count * 0.03,
            0.10
        )

    if campaign_correlation_bonus:

        false_positive_probability -= 0.05

    if private_or_local_indicator_count:

        false_positive_probability += min(
            private_or_local_indicator_count * 0.06,
            0.20
        )

    if conflicting_indicator_count:

        false_positive_probability += min(
            conflicting_indicator_count * 0.08,
            0.25
        )


    # Temporal freshness changes uncertainty within a narrow bound.
    if average_temporal_factor >= 0.70:
        temporal_fp_adjustment = -min(
            (
                average_temporal_factor - 0.70
            ) * 0.05,
            0.015
        )
    else:
        temporal_fp_adjustment = min(
            (
                0.70 - average_temporal_factor
            ) * 0.10,
            0.03
        )

    false_positive_probability += (
        temporal_fp_adjustment
    )

    false_positive_probability = round(
        min(
            max(
                false_positive_probability,
                0.01
            ),
            0.95
        ),
        3
    )

    confidence_intelligence = {
        "confidence_score": confidence_score,
        "evidence_quality": evidence_quality,
        "source_consensus": source_consensus,
        "average_temporal_factor": round(
            average_temporal_factor,
            3
        ),
        "temporal_confidence_adjustment": (
            temporal_confidence_adjustment
        ),
        "temporal_status_counts": (
            temporal_status_counts
        ),
        "temporal_unknown_count": (
            temporal_unknown_count
        ),
        "temporal_fp_adjustment": (
            temporal_fp_adjustment
        ),
        "false_positive_probability": (
            false_positive_probability
        ),
        "conflicting_evidence": bool(
            conflicting_indicator_count
        ),
        "private_or_local_indicators": (
            private_or_local_indicator_count
        ),
        "single_source_indicators": (
            single_source_indicator_count
        ),
        "multi_source_indicators": (
            multi_source_indicator_count
        ),
        "confidence_reasons": (
            confidence_reasons
        )
    }

    # ================================================================
    # SOC-GRADE EVIDENCE CONSENSUS & CONFLICT RESOLUTION ENGINE
    # ================================================================

    evidence_consensus = []

    consensus_strong_count = 0
    consensus_moderate_count = 0
    consensus_weak_count = 0
    consensus_conflict_count = 0
    consensus_insufficient_count = 0

    explicit_conflict_count = 0
    independent_consensus_count = 0

    consensus_weight_total = 0.0
    consensus_strength_total = 0.0

    # Explicit verdict polarity is intentionally conservative.
    # Unknown/undetected results do not become benign evidence.
    malicious_verdicts = {
        "malicious",
        "malware",
        "phishing",
        "blacklisted",
        "blocked",
        "hostile",
        "compromised",
        "bad",
        "badware",
        "threat",
        "malicious_ip",
        "malicious_url",
        "malicious_domain",
    }

    benign_verdicts = {
        "benign",
        "clean",
        "safe",
        "harmless",
        "legitimate",
        "trusted",
        "good",
        "no_threat",
        "not_malicious",
    }

    suspicious_verdicts = {
        "suspicious",
        "questionable",
        "likely_malicious",
        "potentially_malicious",
        "gray",
        "grey",
    }

    def _normalize_consensus_verdict(record):
        if not isinstance(record, dict):
            return "UNKNOWN"

        raw_values = (
            record.get("verdict"),
            record.get("result"),
            record.get("classification"),
            record.get("status"),
            record.get("detection"),
            record.get("threat_type"),
        )

        for raw in raw_values:
            if raw is None:
                continue

            value = str(raw).strip().lower()
            if not value:
                continue

            normalized = value.replace("-", "_").replace(" ", "_")

            if normalized in malicious_verdicts:
                return "MALICIOUS"

            if normalized in benign_verdicts:
                return "BENIGN"

            if normalized in suspicious_verdicts:
                return "SUSPICIOUS"

        return "UNKNOWN"

    def _consensus_source_key(value):
        return str(value or "unknown").strip().lower()

    for item in correlation_map.values():

        if not isinstance(item, dict):
            continue

        indicator_value = item.get("indicator")
        indicator_type = item.get("type", "unknown")

        indicator_sources = [
            str(source).strip()
            for source in (item.get("sources") or [])
            if str(source).strip()
        ]

        unique_source_names = sorted(
            set(indicator_sources)
        )

        independent_source_count = int(
            item.get(
                "independent_source_count",
                0
            ) or 0
        )

        source_families = sorted(
            {
                str(family).strip().lower()
                for family in (
                    item.get("source_families") or []
                )
                if str(family).strip()
            }
        )

        source_reliability = float(
            item.get(
                "source_reliability",
                0.55
            ) or 0.55
        )

        evidence_diversity = float(
            item.get(
                "evidence_diversity",
                0.0
            ) or 0.0
        )

        unique_evidence_count = int(
            item.get(
                "unique_evidence_count",
                item.get("match_count", 0)
            ) or 0
        )

        duplicate_evidence_count = int(
            item.get(
                "duplicate_evidence_count",
                0
            ) or 0
        )

        temporal_factor = float(
            item.get(
                "temporal_factor",
                0.50
            ) or 0.50
        )

        temporal_factor = max(
            0.40,
            min(
                temporal_factor,
                1.00
            )
        )

        indicator_risk = float(
            item.get(
                "risk_score",
                0
            ) or 0
        )

        indicator_confidence = float(
            item.get(
                "confidence",
                0
            ) or 0
        )

        # Re-read raw evidence for this IOC so explicit verdict
        # polarity can be evaluated rather than inferred from score.
        raw_records = _safe_list(
            matches.get(str(indicator_value), [])
        )

        # Some callers may normalize keys differently.
        if not raw_records and indicator_value is not None:
            raw_records = _safe_list(
                matches.get(
                    indicator_value,
                    []
                )
            )

        verdict_counts = {
            "MALICIOUS": 0,
            "BENIGN": 0,
            "SUSPICIOUS": 0,
            "UNKNOWN": 0,
        }

        verdict_sources = {
            "MALICIOUS": set(),
            "BENIGN": set(),
            "SUSPICIOUS": set(),
            "UNKNOWN": set(),
        }

        verdict_families = {
            "MALICIOUS": set(),
            "BENIGN": set(),
            "SUSPICIOUS": set(),
            "UNKNOWN": set(),
        }

        seen_consensus_fingerprints = set()

        for record in raw_records:

            if not isinstance(record, dict):
                continue

            source = (
                record.get("source")
                or record.get("feed")
                or "unknown"
            )

            source_profile = _source_profile(source)

            source_name = (
                str(
                    source_profile.get(
                        "source",
                        source
                    )
                ).strip().lower()
            )

            source_family = (
                str(
                    source_profile.get(
                        "family",
                        "unknown"
                    )
                ).strip().lower()
            )

            verdict = _normalize_consensus_verdict(
                record
            )

            fingerprint = (
                source_name,
                verdict,
                str(
                    record.get("threat_type") or ""
                ).strip().lower(),
                str(
                    record.get("malware") or ""
                ).strip().lower(),
                str(
                    record.get("reference") or ""
                ).strip().lower(),
            )

            if fingerprint in seen_consensus_fingerprints:
                continue

            seen_consensus_fingerprints.add(
                fingerprint
            )

            verdict_counts[verdict] += 1
            verdict_sources[verdict].add(
                source_name
            )
            verdict_families[verdict].add(
                source_family
            )

        malicious_count = verdict_counts[
            "MALICIOUS"
        ]

        benign_count = verdict_counts[
            "BENIGN"
        ]

        suspicious_count = verdict_counts[
            "SUSPICIOUS"
        ]

        unknown_count = verdict_counts[
            "UNKNOWN"
        ]

        # Explicit contradiction requires materially opposed
        # verdict polarity. Suspicious/unknown alone is not a
        # malicious-vs-benign conflict.
        conflict_detected = (
            malicious_count > 0
            and benign_count > 0
        )

        malicious_independent_families = len(
            {
                family
                for family in verdict_families[
                    "MALICIOUS"
                ]
                if family != "unknown"
            }
        )

        benign_independent_families = len(
            {
                family
                for family in verdict_families[
                    "BENIGN"
                ]
                if family != "unknown"
            }
        )

        conflict_independent_families = len(
            {
                family
                for family in (
                    verdict_families["MALICIOUS"]
                    | verdict_families["BENIGN"]
                )
                if family != "unknown"
            }
        )

        # Independent-family telemetry must never exceed the
        # independent-source count already established upstream.
        effective_independent_sources = min(
            independent_source_count,
            max(
                len(
                    {
                        family
                        for family in source_families
                        if family != "unknown"
                    }
                ),
                0
            )
        )

        independent_consensus_count += (
            1
            if effective_independent_sources >= 2
            and unique_evidence_count > 0
            else 0
        )

        # Consensus quality components.
        evidence_component = min(
            unique_evidence_count,
            5
        ) / 5.0

        independence_component = min(
            effective_independent_sources,
            3
        ) / 3.0

        reliability_component = max(
            0.0,
            min(
                source_reliability,
                1.0
            )
        )

        diversity_component = max(
            0.0,
            min(
                evidence_diversity,
                1.0
            )
        )

        temporal_component = max(
            0.0,
            min(
                temporal_factor,
                1.0
            )
        )

        # Positive evidence polarity component.
        # Unknown evidence contributes no positive consensus.
        positive_known_count = (
            malicious_count
            + suspicious_count
        )

        polarity_component = (
            positive_known_count
            / max(
                malicious_count
                + benign_count
                + suspicious_count
                + unknown_count,
                1
            )
        )

        # Base quality is deliberately bounded.
        consensus_quality = (
            (evidence_component * 0.20)
            + (independence_component * 0.25)
            + (reliability_component * 0.20)
            + (diversity_component * 0.15)
            + (temporal_component * 0.10)
            + (polarity_component * 0.10)
        )

        consensus_quality = max(
            0.0,
            min(
                consensus_quality,
                1.0
            )
        )

        # Classify consensus based on independent evidence first,
        # then use quality as the deciding strength modifier.
        if conflict_detected:

            consensus_state = "CONFLICTING"
            consensus_strength = max(
                0.20,
                min(
                    0.40,
                    consensus_quality * 0.50
                )
            )

            consensus_conflict_count += 1
            explicit_conflict_count += 1

        elif effective_independent_sources >= 3:

            consensus_state = "CONSENSUS_STRONG"
            consensus_strength = max(
                0.75,
                min(
                    0.98,
                    0.70 + (
                        consensus_quality * 0.28
                    )
                )
            )

            consensus_strong_count += 1

        elif effective_independent_sources == 2:

            consensus_state = "CONSENSUS_MODERATE"
            consensus_strength = max(
                0.60,
                min(
                    0.88,
                    0.55 + (
                        consensus_quality * 0.28
                    )
                )
            )

            consensus_moderate_count += 1

        elif effective_independent_sources == 1:

            consensus_state = "CONSENSUS_WEAK"
            consensus_strength = max(
                0.35,
                min(
                    0.65,
                    0.30 + (
                        consensus_quality * 0.35
                    )
                )
            )

            consensus_weak_count += 1

        elif unique_evidence_count > 0:

            consensus_state = "CONSENSUS_WEAK"
            consensus_strength = max(
                0.25,
                min(
                    0.50,
                    0.20 + (
                        consensus_quality * 0.30
                    )
                )
            )

            consensus_weak_count += 1

        else:

            consensus_state = "INSUFFICIENT"
            consensus_strength = 0.20

            consensus_insufficient_count += 1

        # Conflict with strong independent opposition is a harder
        # uncertainty signal than duplicated evidence.
        conflict_severity = 0.0

        if conflict_detected:

            conflict_severity = min(
                1.0,
                (
                    min(
                        malicious_independent_families,
                        3
                    ) * 0.30
                )
                + (
                    min(
                        benign_independent_families,
                        3
                    ) * 0.30
                )
                + (
                    min(
                        effective_independent_sources,
                        3
                    ) * 0.10
                )
                + (
                    0.10
                    if conflict_independent_families >= 2
                    else 0.0
                )
            )

        consensus_weight = (
            max(
                effective_independent_sources,
                1
            )
            * max(
                reliability_component,
                0.55
            )
            * max(
                temporal_component,
                0.40
            )
        )

        consensus_weight_total += consensus_weight
        consensus_strength_total += (
            consensus_strength
            * consensus_weight
        )

        evidence_consensus.append({
            "indicator": indicator_value,
            "type": indicator_type,
            "sources": unique_source_names,
            "source_count": len(
                unique_source_names
            ),
            "independent_source_count": (
                effective_independent_sources
            ),
            "source_families": source_families,
            "unique_evidence_count": (
                unique_evidence_count
            ),
            "duplicate_evidence_count": (
                duplicate_evidence_count
            ),
            "source_reliability": round(
                source_reliability,
                3
            ),
            "evidence_diversity": round(
                evidence_diversity,
                3
            ),
            "temporal_factor": round(
                temporal_factor,
                3
            ),
            "risk_score": round(
                indicator_risk,
                2
            ),
            "indicator_confidence": round(
                indicator_confidence,
                3
            ),
            "verdict_counts": verdict_counts,
            "malicious_independent_families": (
                malicious_independent_families
            ),
            "benign_independent_families": (
                benign_independent_families
            ),
            "conflict_independent_families": (
                conflict_independent_families
            ),
            "consensus_quality": round(
                consensus_quality,
                3
            ),
            "consensus": consensus_state,
            "consensus_strength": round(
                consensus_strength,
                3
            ),
            "conflict_detected": (
                conflict_detected
            ),
            "conflict_severity": round(
                conflict_severity,
                3
            ),
        })

    total_consensus_indicators = len(
        evidence_consensus
    )

    if total_consensus_indicators:

        weighted_consensus_ratio = (
            consensus_strength_total
            / max(
                consensus_weight_total,
                1e-9
            )
        )

    else:

        weighted_consensus_ratio = 0.0

    weighted_consensus_ratio = max(
        0.0,
        min(
            weighted_consensus_ratio,
            1.0
        )
    )

    conflict_ratio = (
        consensus_conflict_count
        / max(
            total_consensus_indicators,
            1
        )
    )

    strong_ratio = (
        consensus_strong_count
        / max(
            total_consensus_indicators,
            1
        )
    )

    moderate_ratio = (
        consensus_moderate_count
        / max(
            total_consensus_indicators,
            1
        )
    )

    if explicit_conflict_count > 0:

        overall_consensus = "CONFLICTING"

    elif (
        strong_ratio >= 0.50
        and weighted_consensus_ratio >= 0.70
    ):

        overall_consensus = "CONSENSUS_STRONG"

    elif (
        (
            strong_ratio > 0
            or moderate_ratio >= 0.50
        )
        and weighted_consensus_ratio >= 0.50
    ):

        overall_consensus = "CONSENSUS_MODERATE"

    elif consensus_weak_count > 0:

        overall_consensus = "CONSENSUS_WEAK"

    else:

        overall_consensus = "INSUFFICIENT"

    # Consensus hardening affects confidence only within a bounded
    # range so evidence quality cannot dominate the entire engine.
    consensus_confidence_adjustment = 0.0

    if explicit_conflict_count:

        consensus_confidence_adjustment = -min(
            0.12,
            (
                0.04
                * explicit_conflict_count
            )
            + (
                0.04
                * min(
                    conflict_ratio,
                    1.0
                )
            )
        )

    elif independent_consensus_count:

        consensus_confidence_adjustment = min(
            0.04,
            0.015
            * min(
                independent_consensus_count,
                3
            )
        )

    confidence_score += (
        consensus_confidence_adjustment
    )

    confidence_score = round(
        min(
            max(
                confidence_score,
                0.05
            ),
            0.99
        ),
        3
    )

    # Apply the bounded consensus adjustment to false-positive
    # probability after the explicit conflict assessment.
    false_positive_probability -= (
        consensus_confidence_adjustment
        * 0.70
    )

    false_positive_probability = round(
        min(
            max(
                false_positive_probability,
                0.01
            ),
            0.95
        ),
        3
    )

    if explicit_conflict_count:

        confidence_reasons.append(
            "explicit_verdict_conflict"
        )

    elif independent_consensus_count:

        confidence_reasons.append(
            "independent_source_consensus"
        )

    source_consensus = (
        "CONFLICTING"
        if overall_consensus == "CONFLICTING"
        else "STRONG"
        if overall_consensus == "CONSENSUS_STRONG"
        else "MODERATE"
        if overall_consensus == "CONSENSUS_MODERATE"
        else "LIMITED"
    )

    confidence_intelligence.update({
        "confidence_score": confidence_score,
        "source_consensus": source_consensus,
        "consensus_confidence_adjustment": (
            consensus_confidence_adjustment
        ),
        "explicit_conflict_count": (
            explicit_conflict_count
        ),
        "independent_consensus_count": (
            independent_consensus_count
        ),
        "consensus_weighted_ratio": round(
            weighted_consensus_ratio,
            3
        ),
        "consensus_conflict_ratio": round(
            conflict_ratio,
            3
        ),
        "false_positive_probability": (
            false_positive_probability
        ),
        "conflicting_evidence": bool(
            explicit_conflict_count
        ),
        "confidence_reasons": (
            confidence_reasons
        ),
    })

    evidence_consensus_summary = {
        "overall_consensus": (
            overall_consensus
        ),
        "consensus_ratio": round(
            weighted_consensus_ratio,
            3
        ),
        "weighted_consensus_ratio": round(
            weighted_consensus_ratio,
            3
        ),
        "strong": consensus_strong_count,
        "moderate": consensus_moderate_count,
        "weak": consensus_weak_count,
        "conflicting": consensus_conflict_count,
        "insufficient": consensus_insufficient_count,
        "explicit_conflict_count": (
            explicit_conflict_count
        ),
        "independent_consensus_count": (
            independent_consensus_count
        ),
        "conflict_ratio": round(
            conflict_ratio,
            3
        ),
        "indicators": evidence_consensus,
    }

    high_risk_indicators.sort(
        key=lambda item:
        item.get(
            "risk_score",
            0
        ),
        reverse=True
    )

    # -------------------------------------------------
    # SOC 9.5 Detection Correlation Engine
    # -------------------------------------------------
    alert_detections = []

    if isinstance(alert_intelligence, dict):

        _candidate_detections = alert_intelligence.get(
            "detections",
            []
        )

        if isinstance(_candidate_detections, list):

            alert_detections = [
                dict(item)
                for item in _candidate_detections
                if isinstance(item, dict)
            ]

    detection_correlation = correlate_detections(
        alert_detections
    )

    return {
        "engine": "threat-intelligence-v2",
        "version": "advanced-v1",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "overall": {
            "risk_score": overall_score,
            "severity": overall_severity,
            "confidence": round(confidence_score, 3)
        },

        "summary": {
            "total_indicators": len(
                indicators
            ),
            "scored_indicators": scored_indicators,
            "high_risk_count": len([
                item
                for item
                in high_risk_indicators
                if item.get(
                    "severity"
                ) in (
                    "CRITICAL",
                    "HIGH"
                )
            ]),
            "ip_high_risk_count": (
                ip_risk_count
            ),
            "unique_sources": len(
                threat_sources
            ),
            "mitre_techniques": len(
                mitre_techniques
            )
        },

        "indicator_types": dict(
            indicator_types
        ),

        "severity_distribution": dict(
            severity_distribution
        ),

        "high_risk_indicators": (
            high_risk_indicators[:50]
        ),

        "correlation_map": (
            correlation_map
        ),

        "infrastructure_reuse_intelligence": (
            infrastructure_reuse_intelligence
        ),

        "campaign_intelligence": {
            "detected": bool(
                indicator_clusters or
                correlation_relationships
            ),
            "correlation_bonus": (
                campaign_correlation_bonus
            ),
            "cluster_count": len(
                indicator_clusters
            ),
            "relationship_count": len(
                correlation_relationships
            ),
            "clusters": indicator_clusters,
            "relationships": correlation_relationships,
            "graph": relationship_graph,
            "campaign_clusters": campaign_clusters,
            "campaign_cluster_count": len(
                campaign_clusters
            ),
            "campaign_confidence": round(
                campaign_graph_confidence,
                3
            ),
            "strong_relationship_count": (
                strong_relationship_count
            ),
            "graph_bonus": round(
                campaign_graph_bonus,
                2
            )
        },

        "risk_explanation": (
            risk_explanation
        ),

        "analyst_summary": (
            analyst_summary
        ),

        "confidence_intelligence": (
            confidence_intelligence
        ),

        "evidence_consensus": (
            evidence_consensus_summary
        ),

        "alert_intelligence": (
            alert_intelligence
        ),

        "threat_timeline_correlation": (
            threat_timeline_correlation
        ),

        "mitre_attack_chain_intelligence": (
            mitre_attack_chain_intelligence
        ),

        "cyber_kill_chain_intelligence": (
            cyber_kill_chain_intelligence
        ),

        "historical_recurrence": (
            historical_recurrence
        ),

        "mitre_attack": sorted(
            mitre_techniques
        ),

        "threat_sources": sorted(
            threat_sources
        ),
            "detection_correlation": detection_correlation,
}


_soc95_v2_incident_public_wrapper = True


def analyze_threat_intelligence_v2(
    *args,
    **kwargs,
):
    result = _soc95_analyze_threat_intelligence_v2_base(
        *args,
        **kwargs,
    )

    if not isinstance(result, dict):
        raise RuntimeError(
            "Threat Intelligence V2 returned a non-dict result"
        )

    detection_correlation = result.get(
        "detection_correlation",
        {},
    )

    alert_intelligence = result.get(
        "alert_intelligence",
        {},
    )

    incident_management = manage_incidents(
        detection_correlation=detection_correlation,
        alert_intelligence=alert_intelligence,
    )

    result["incident_management"] = (
        incident_management
    )

    # SOC95 Investigation Management integration
    investigation_management = investigate_incidents(
        incident_management=incident_management,
        detection_correlation=detection_correlation,
    )

    result["investigation_management"] = (
        investigation_management
    )

    return result
