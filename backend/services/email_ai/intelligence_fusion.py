from __future__ import annotations

"""
MailTrace-AI SOC Production Intelligence Fusion Engine.

Backward compatible with the existing analyze_email_intelligence() interface.
All existing top-level response keys are preserved; SOC-focused fields are additive.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from services.domain_alignment import compare_domains, normalized_host


ENGINE_NAME = "mailtrace-ai-intelligence-fusion"
ENGINE_VERSION = "3.0.0"
DETECTION_POLICY_VERSION = "soc-fusion-policy-3.0"
SCHEMA_VERSION = "3.0"


@dataclass(frozen=True)
class Signal:
    category: str
    name: str
    score: float
    confidence: float
    evidence: str
    critical: bool = False
    source: str = "MailTrace-AI"
    detection_id: str = ""
    correlation_group: str = ""
    mitre_techniques: Tuple[str, ...] = ()
    reliability: float = 0.75


CATEGORY_WEIGHTS: Dict[str, float] = {
    "ml": 1.45,
    "threat_intelligence": 1.45,
    "header_forensics": 1.35,
    "identity": 1.35,
    "malware_delivery": 1.30,
    "credential_theft": 1.25,
    "fraud": 1.25,
    "impersonation": 1.20,
    "forensics": 1.20,
    "infrastructure": 1.15,
    "url": 1.05,
    "social_engineering": 1.00,
    "attachment": 0.80,
}

CATEGORY_CORRELATION_GROUPS = {
    "ml": "model",
    "threat_intelligence": "external_intelligence",
    "header_forensics": "email_authentication",
    "identity": "sender_identity",
    "malware_delivery": "delivery_artifact",
    "credential_theft": "content_intent",
    "fraud": "content_intent",
    "impersonation": "content_intent",
    "forensics": "forensic_engine",
    "infrastructure": "network_infrastructure",
    "url": "delivery_artifact",
    "social_engineering": "content_intent",
    "attachment": "delivery_artifact",
}

MITRE_BY_CATEGORY = {
    "credential_theft": ("T1566.002", "T1056"),
    "fraud": ("T1566",),
    "identity": ("T1566.002",),
    "impersonation": ("T1656",),
    "malware_delivery": ("T1566.001",),
    "url": ("T1566.002",),
    "social_engineering": ("T1566",),
    "attachment": ("T1566.001",),
    "header_forensics": ("T1566",),
}


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(default) if value is None else float(value)
    except (TypeError, ValueError):
        return float(default)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _domain_from_email(value: str) -> str:
    return normalized_host(value) or ""


def _has_any(text: str, terms: Iterable[str]) -> bool:
    normalized = _lower(text)
    return any(term in normalized for term in terms)


def _matched_terms(text: str, terms: Iterable[str]) -> List[str]:
    normalized = _lower(text)
    return sorted({term for term in terms if term in normalized})


def _contextual_clauses(text: str) -> List[str]:
    """Return unquoted clauses that are not explicitly negated."""
    unquoted = re.sub(
        r"""“[^”]*”|"[^"]*"|‘[^’]*’|(?<!\w)'[^'\n]*'(?!\w)""",
        " ",
        _lower(text),
    )
    clauses = re.split(r"[.!?;\n]+", unquoted)
    negation = ("never ask", "do not", "don't", "does not", "will not", "won't",
                "not required", "no need to", "not asking", "without asking")
    return [clause.strip() for clause in clauses
            if clause.strip() and not _has_any(clause, negation)]


def _detection_id(category: str, name: str) -> str:
    return f"MT-FUS-{category.upper().replace('_', '-')}-{name.upper().replace('_', '-')}"


def _make_signal(
    category: str, name: str, score: float, confidence: float,
    evidence: str, critical: bool = False, source: str = "MailTrace-AI",
    reliability: float = 0.75,
) -> Signal:
    return Signal(
        category=category,
        name=name,
        score=_clamp(score),
        confidence=_clamp01(confidence),
        evidence=evidence,
        critical=critical,
        source=source,
        detection_id=_detection_id(category, name),
        correlation_group=CATEGORY_CORRELATION_GROUPS.get(category, category),
        mitre_techniques=MITRE_BY_CATEGORY.get(category, ()),
        reliability=_clamp01(reliability),
    )


def _probability_from_ai(ai_result: Mapping[str, Any]) -> float:
    raw = ai_result.get("calibrated_probability")
    if raw is None:
        raw = ai_result.get("model_probability")
    if raw is None:
        raw = ai_result.get("probability")
    return _clamp01(_safe_float(raw))


def _model_available(ai_result: Any) -> bool:
    if not isinstance(ai_result, Mapping):
        return False
    status = _upper(ai_result.get("status"))
    if status in {"MODEL_NOT_READY", "UNAVAILABLE", "ERROR", "SKIPPED"}:
        return False
    return (any(ai_result.get(key) is not None for key in ("calibrated_probability", "model_probability", "probability"))
            or bool(_upper(ai_result.get("classification"))))


def _ai_signal(ai_result: Mapping[str, Any]) -> Signal | None:
    if _upper(ai_result.get("status")) in {"MODEL_NOT_READY", "UNAVAILABLE", "ERROR", "SKIPPED"}:
        return None
    probability = _probability_from_ai(ai_result)
    classification = _upper(ai_result.get("classification"))
    if probability <= 0.0 and not classification:
        return None
    score = probability * 100.0
    if classification in {"PHISHING","BEC","CREDENTIAL_THEFT","INVOICE_FRAUD","PAYMENT_DIVERSION","EXECUTIVE_IMPERSONATION","MALWARE_DELIVERY"}:
        score = max(score, 82.0)
    return _make_signal("ml", "calibrated_ml_probability", score,
                        max(0.50, min(0.99, probability)),
                        f"AI classification={classification or 'UNKNOWN'}; calibrated_probability={probability:.4f}",
                        score >= 85.0, "email_ai", 0.70)


def _content_signals(email: Mapping[str, Any]) -> List[Signal]:
    raw_combined = f"{_text(email.get('subject'))}\n{_text(email.get('body'))}"
    clauses = _contextual_clauses(raw_combined)
    combined = " ".join(clauses)
    signals: List[Signal] = []
    groups = [
        ("credential_theft", "credential_harvesting_language", 90, .88,
         ("enter your password", "send your password", "submit your password", "provide your password",
          "share your password", "password and one-time code", "one-time code", "login credentials",
          "account credentials", "enter your credentials", "submit your credentials",
          "provide your credentials", "share your credentials", "verify your account",
          "verify your identity", "sign in", "log in"),
         "Credential/login verification language detected.", True),
        ("fraud", "financial_fraud_language", 88, .87,
         ("payment","invoice","wire transfer","bank transfer","transfer funds","beneficiary","account details","refund","payment verification"),
         "Payment/invoice/transfer language detected.", True),
        ("impersonation", "authority_impersonation_language", 76, .74,
         ("ceo","cfo","director","administrator","security team","finance team","management"),
         "Authority/executive language detected.", False),
    ]
    for cat, name, score, conf, terms, evidence, critical in groups:
        matched = _matched_terms(combined, terms)
        if matched:
            signals.append(_make_signal(cat, name, score, conf,
                f"{evidence} Matched terms: {', '.join(matched)}.", critical, "email_content", .80))
    urgency = ("urgent","immediately","right away","suspended","deadline","act now","within 24")
    social = ("verify your account","verify your identity","enter your password","sign in","avoid closure","account will be closed","click here to verify")
    headers = email.get("headers") if isinstance(email.get("headers"), Mapping) else {}
    promotional_context = bool(email.get("promotional") or email.get("unsubscribe_url")
        or _has_any(" ".join(f"{k} {v}" for k, v in headers.items()).lower(), ("list-unsubscribe", "bulk", "marketing"))
        or _has_any(combined, ("discount", "sale", "offer", "shop now", "unsubscribe", "terms and conditions")))
    has_actionable_pressure = any(
        _has_any(" ".join(clauses[max(0, index - 1):index + 2]), urgency)
        and _has_any(" ".join(clauses[max(0, index - 1):index + 2]), social)
        for index in range(len(clauses))
    )
    if has_actionable_pressure and not promotional_context:
        matched = sorted({term for clause in clauses for term in (*urgency, *social) if term in clause})
        signals.append(_make_signal("social_engineering","urgency_pressure_pattern",82,.84,
                                    f"Urgency and pressure-to-act pattern detected. Matched terms: {', '.join(matched)}.",True,"email_content",.82))
    return signals


def _identity_signals(email: Mapping[str, Any]) -> List[Signal]:
    sender, reply_to = _text(email.get("sender")), _text(email.get("reply_to"))
    sender_domain = normalized_host(email.get("sender_domain")) or _domain_from_email(sender)
    reply_domain = _domain_from_email(reply_to)
    out: List[Signal] = []
    comparison = compare_domains(sender_domain, reply_domain)
    if sender and reply_to and comparison == "MISMATCH":
        out.append(_make_signal("identity","sender_reply_to_mismatch",92,.94,
                                f"Sender={sender}; Reply-To={reply_to}; organizational-domain comparison={comparison}.",
                                True,"identity_analysis",.95))
    return out


def _header_signals(email: Mapping[str, Any]) -> List[Signal]:
    validation = email.get("authentication_validation") or {}
    if not isinstance(validation, Mapping):
        return []
    if validation.get("independent_validation") is not True:
        return []
    statuses = {
        key: _upper((validation.get(key) or {}).get("status"))
        for key in ("spf", "dkim", "dmarc")
        if isinstance(validation.get(key), Mapping)
    }
    failures = sum(
        statuses.get(key) in {"FAIL", "SOFTFAIL", "PERMERROR"}
        for key in ("spf", "dkim", "dmarc")
    )
    out: List[Signal] = []
    if failures:
        out.append(_make_signal("header_forensics","authentication_failure",
                                min(100,70+failures*10),min(.99,.76+failures*.07),
                                f"{failures} cryptographically or contextually validated mail authentication check(s) failed.",
                                failures >= 2,"header_forensics",.90))
    return out


def _url_signals(email: Mapping[str, Any]) -> List[Signal]:
    url_intel = email.get("advanced_url_intelligence") or email.get("url_intelligence")
    if not isinstance(url_intel, Mapping):
        return []
    risk = _safe_float(url_intel.get("risk_score", url_intel.get("score", 0)))
    verdict = _upper(url_intel.get("verdict"))
    if risk < 50 and verdict not in {"SUSPICIOUS", "DECEPTIVE_OR_SUSPICIOUS", "HIGH_CONFIDENCE_DECEPTIVE", "HIGH_RISK"}:
        return []
    score = _clamp(max(68, risk))
    conf = min(.93,.72+score/500)
    return [_make_signal("url","url_delivery_signal",score,conf,
                         f"URL intelligence verdict={verdict or 'UNKNOWN'}; risk score={risk:.2f}.",
                         True,"url_intelligence",.88)]


def _attachment_signals(email: Mapping[str, Any]) -> List[Signal]:
    attachments = _as_list(email.get("attachments"))
    if not attachments:
        return []
    dangerous_ext = {".exe",".scr",".js",".vbs",".bat",".cmd",".ps1",".msi",".dll",".hta",".lnk",".iso"}
    dangerous = 0
    masqueraded = 0
    unscanned = 0
    scan_unverified = 0
    confirmed_malware = 0
    for item in attachments:
        if not isinstance(item, Mapping):
            name = _lower(item)
            file_type = {}
        else:
            name = _lower(item.get("filename"))
            scan = item.get("malware_scan")
            if not isinstance(scan, Mapping):
                scan = {}
            scan_status = _upper(scan.get("status"))
            confirmed_malware += int(scan_status in {"INFECTED", "MALICIOUS"})
            scan_unverified += int(scan_status not in {"CLEAN", "INFECTED", "MALICIOUS"})
            file_type = item.get("file_type_intelligence")
            if not isinstance(file_type, Mapping):
                file_type = {}
            if item.get("analysis_status") != "STATIC_ANALYSIS_COMPLETE":
                unscanned += 1
        detected_category = _upper(file_type.get("detected_category"))
        detected_type = _upper(file_type.get("detected_type"))
        executable_detected = bool(
            file_type.get("metadata", {}).get("executable_detected")
            if isinstance(file_type.get("metadata"), Mapping)
            else False
        ) or detected_category == "EXECUTABLE"
        risky_extension = any(name.endswith(ext) for ext in dangerous_ext)
        dangerous += int(risky_extension or executable_detected)
        masqueraded += int(
            executable_detected
            and name.rsplit(".", 1)[-1] not in {"exe", "scr", "dll", "sys", "ocx", "cpl"}
        )
    if confirmed_malware:
        return [_make_signal("malware_delivery", "attachment_malware_confirmed", 100, .99,
                             f"ClamAV reported malware in {confirmed_malware} attachment(s). Treat the reported file(s) as malicious and preserve the scanner signature as evidence.",
                             True, "clamav_malware_scan", .99)]
    if dangerous:
        return [_make_signal("malware_delivery","attachment_delivery_risk",
                             min(96,78+dangerous*5+masqueraded*5),min(.82,.68+dangerous*.04),
                             f"{len(attachments)} attachment(s); {dangerous} executable-format or script-capable attachment(s), {masqueraded} with a potentially misleading extension. Executable format alone does not confirm malware.",
                             True,"attachment_intelligence",.82)]
    if any(
        isinstance(item, Mapping)
        and isinstance(item.get("file_type_intelligence"), Mapping)
        and item["file_type_intelligence"].get("metadata", {}).get("semantic_extension_consistent") is False
        for item in attachments
    ):
        return [_make_signal("malware_delivery","attachment_type_mismatch",68,.72,
                             f"{len(attachments)} attachment(s); file content and filename extension do not consistently match.",
                             True,"attachment_intelligence",.70)]
    if unscanned:
        return [_make_signal("attachment","attachment_scan_coverage_limited",52,.50,
                             f"{len(attachments)} attachment(s); static analysis is incomplete for {unscanned}. Malware scanning or detonation may be unavailable or over its processing limit.",
                             False,"attachment_intelligence",.45)]
    if scan_unverified:
        return [_make_signal("attachment","attachment_malware_scan_unverified",52,.50,
                             f"{len(attachments)} attachment(s); malware scan did not return a clean or infected verdict for {scan_unverified}. Do not treat this as a clean scan.",
                             False,"attachment_intelligence",.45)]
    return [_make_signal("attachment","attachment_presence",48,.58,
                         f"{len(attachments)} attachment(s) present.",False,"attachment_intelligence",.55)]


def _forensic_signals(forensic: Mapping[str, Any] | None) -> List[Signal]:
    if not isinstance(forensic, Mapping):
        return []
    findings = forensic.get("findings")
    if not isinstance(findings, list):
        return []
    severe = [item for item in findings if isinstance(item, Mapping)
              and _upper(item.get("severity")) in {"HIGH", "CRITICAL"}
              and "return-path" not in _lower(item.get("title"))
              and "return-path" not in _lower(item.get("category"))]
    if not severe:
        return []
    score = min(90.0, 68.0 + 8.0 * len(severe))
    return [_make_signal("forensics", "email_forensic_findings", score, .70,
                         f"{len(severe)} independent high/critical forensic finding(s).", len(severe) >= 2,
                         "email_forensics_findings", .75)]


def _ti_signals(threat_intelligence: Mapping[str, Any] | None) -> List[Signal]:
    if not isinstance(threat_intelligence, Mapping):
        return []
    matches = threat_intelligence.get("matches")
    items = list(matches.values()) if isinstance(matches, Mapping) else _as_list(matches)
    valid = [x for x in items if isinstance(x, Mapping)]
    malicious = sum(_lower(x.get("verdict") or x.get("result") or x.get("classification"))
                    in {"malicious","bad","phishing","fraud","threat"} for x in valid)
    if not valid:
        return []
    if malicious:
        return [_make_signal("threat_intelligence","threat_intelligence_match",
                             min(100,88+malicious*7),min(.99,.86+malicious*.04),
                             f"Threat intelligence returned {len(valid)} match(es), {malicious} malicious.",
                             True,"threat_intelligence_v2",.93)]
    return [_make_signal("threat_intelligence","threat_intelligence_nonmalicious_or_unknown",52,.62,
                         f"Threat intelligence returned {len(valid)} non-malicious/unknown match(es).",
                         False,"threat_intelligence_v2",.60)]


def _infrastructure_signals(ip_intelligence: Mapping[str, Any] | None) -> List[Signal]:
    if not isinstance(ip_intelligence, Mapping):
        return []
    scores = []
    for value in ip_intelligence.values():
        if isinstance(value, Mapping):
            s = _safe_float(value.get("risk_score", value.get("score", 0)))
            if s > 0: scores.append(_clamp(s))
    if not scores:
        return []
    maximum, mean = max(scores), sum(scores)/len(scores)
    score = min(100,.72*maximum+.28*mean)
    return [_make_signal("infrastructure","ip_infrastructure_risk",score,min(.96,.62+score/300),
                         f"{len(scores)} IP intelligence result(s); max risk={maximum:.2f}; mean risk={mean:.2f}.",
                         score>=80,"ip_intelligence_v2",.80)]


def _build_signals(email, ai_result, forensic, threat_intelligence, ip_intelligence) -> List[Signal]:
    signals: List[Signal] = []
    if isinstance(ai_result, Mapping):
        ai = _ai_signal(ai_result)
        if ai: signals.append(ai)
    signals += _content_signals(email)
    signals += _identity_signals(email)
    signals += _header_signals(email)
    signals += _url_signals(email)
    signals += _attachment_signals(email)
    signals += _forensic_signals(forensic)
    signals += _ti_signals(threat_intelligence)
    signals += _infrastructure_signals(ip_intelligence)
    return _deduplicate_signals(signals)


def _deduplicate_signals(signals: Sequence[Signal]) -> List[Signal]:
    seen, out = set(), []
    for s in signals:
        key = (s.category, s.name, s.evidence)
        if key not in seen:
            seen.add(key); out.append(s)
    return out


def _aggregate_categories(signals: Sequence[Signal]) -> Dict[str, Dict[str, float]]:
    grouped: Dict[str,List[Signal]] = {}
    for s in signals: grouped.setdefault(s.category,[]).append(s)
    output = {}
    for cat, items in grouped.items():
        weight = CATEGORY_WEIGHTS.get(cat,1.0)
        local_weights = [weight*(.70+.30*_clamp01(x.confidence))* (.75+.25*_clamp01(x.reliability)) for x in items]
        total = sum(local_weights)
        score = sum(x.score*w for x,w in zip(items,local_weights))/total if total else max(x.score for x in items)
        output[cat] = {"score":round(_clamp(score),6),
                       "confidence":round(max(x.confidence for x in items),6),
                       "support_count":float(len(items))}
    return output


def _calculate_convergence(category_scores: Mapping[str,Mapping[str,float]]) -> Dict[str,Any]:
    independent = {c for c,v in category_scores.items() if not v.get("model_only") and _safe_float(v.get("score"))>=55}
    corroborated = {c for c,v in category_scores.items() if _safe_float(v.get("score"))>=65}
    severe = {c for c,v in category_scores.items() if _safe_float(v.get("score"))>=80}
    return {"independent_categories":sorted(independent),"corroborated_categories":sorted(corroborated),
            "severe_categories":sorted(severe),"independent_count":len(independent),
            "corroborated_count":len(corroborated),"severe_count":len(severe),
            "convergence_bonus":round(min(15,max(0,(len(independent)-1)*3)),6)}


_EVIDENCE_STOPWORDS = {
    "detected", "language", "pattern", "matched", "terms", "found", "signal",
    "evidence", "reported", "result", "results", "score", "risk", "unknown",
    "and", "the", "for", "with", "from", "into", "that", "this", "are",
}


def _effective_group_scores(categories: Mapping[str, Mapping[str, float]],
                            signals: Sequence[Signal]) -> Dict[str, Dict[str, Any]]:
    """Merge category scores only when same-family signals share >=2 evidence terms."""
    category_terms: Dict[str, set[str]] = {}
    category_parent: Dict[str, str] = {}
    for signal in signals:
        category_parent[signal.category] = CATEGORY_CORRELATION_GROUPS.get(signal.category, signal.category)
        tokens = {token for token in re.findall(r"[a-z0-9]+", _lower(signal.evidence))
                  if len(token) >= 4 and token not in _EVIDENCE_STOPWORDS}
        category_terms.setdefault(signal.category, set()).update(tokens)

    parents: Dict[str, List[str]] = {}
    for category in categories:
        parents.setdefault(category_parent.get(category, category), []).append(category)

    grouped: Dict[str, Dict[str, Any]] = {}
    for parent, members in parents.items():
        roots = {category: category for category in members}
        overlap_by_category: Dict[str, set[str]] = {category: set() for category in members}

        def find(category):
            while roots[category] != category:
                roots[category] = roots[roots[category]]
                category = roots[category]
            return category

        for index, left in enumerate(members):
            for right in members[index + 1:]:
                shared = category_terms.get(left, set()) & category_terms.get(right, set())
                if len(shared) >= 2:
                    overlap_by_category[left].update(shared)
                    overlap_by_category[right].update(shared)
                    roots[find(right)] = find(left)
        clusters: Dict[str, List[str]] = {}
        for category in members:
            clusters.setdefault(find(category), []).append(category)
        for cluster in clusters.values():
            cluster = sorted(cluster)
            ranked = sorted((_safe_float(categories[c].get("score")) for c in cluster), reverse=True)
            uplift = min(8.0, sum(ranked[1:]) * .08) if len(ranked) > 1 else 0.0
            score = _clamp(ranked[0] + uplift) if ranked else 0.0
            name = f"{parent}[{','.join(cluster)}]"
            grouped[name] = {
                "score": round(score, 6),
                "confidence": round(max(_safe_float(categories[c].get("confidence")) for c in cluster), 6),
                "weight": max(CATEGORY_WEIGHTS.get(c, 1.0) for c in cluster),
                "categories": cluster,
                "model_only": cluster == ["ml"],
                "correlation_uplift": round(uplift, 6),
                "evidence_overlap_terms": sorted(set().union(*(overlap_by_category[c] for c in cluster))) if len(cluster) > 1 else [],
            }
    return grouped


def _calculate_data_quality(email, ai_result, forensic, ti, ip) -> Dict[str,Any]:
    expected = {"subject":email.get("subject"),"body":email.get("body"),
                "sender":email.get("sender"),"headers":email.get("headers"),
                "urls":email.get("urls")}
    present = [k for k,v in expected.items() if v not in (None,"",{},[])]
    missing = [k for k in expected if k not in present]
    enrichment = {"ai_result":_model_available(ai_result),"forensic":bool(isinstance(forensic,Mapping) and forensic),
                  "threat_intelligence":_intelligence_availability(ti)["status"] not in {"NOT_PROVIDED", "UNAVAILABLE", "ERROR", "UNKNOWN"},
                  "ip_intelligence":bool(isinstance(ip,Mapping) and ip)}
    enrichment_count = sum(enrichment.values())
    completeness = _clamp01(.70*(len(present)/len(expected))+.30*(enrichment_count/4))
    return {"completeness":round(completeness,6),"present_components":present,
            "missing_components":missing,"enrichment_available":enrichment,
            "enrichment_count":enrichment_count}


def _authentication_contract(email: Mapping[str, Any], forensic: Any) -> Dict[str, Any]:
    email_validation = email.get("authentication_validation")
    auth_analysis = forensic.get("authentication_analysis") if isinstance(forensic, Mapping) else None
    validation = email_validation if isinstance(email_validation, Mapping) else (
        auth_analysis.get("validation") if isinstance(auth_analysis, Mapping) else None
    )
    reported = auth_analysis.get("reported_results", {}) if isinstance(auth_analysis, Mapping) else {}
    reported = reported if isinstance(reported, Mapping) else {}
    checks = {}
    for method in ("spf", "dkim", "dmarc"):
        value = validation.get(method) if isinstance(validation, Mapping) else None
        status = _upper(value.get("status")) if isinstance(value, Mapping) else "NOT_PROVIDED"
        checks[method] = {
            "reported_status": _upper(reported.get(method)) or "NOT_REPORTED",
            "reported_results_trusted": bool(auth_analysis.get("authentication_results_trusted", False)) if isinstance(auth_analysis, Mapping) else False,
            "validated_status": status,
        }
    independent = bool(isinstance(validation, Mapping) and validation.get("independent_validation") is True)
    validated_domain = normalized_host(validation.get("validated_domain")) if isinstance(validation, Mapping) else None
    terminal = {"PASS", "FAIL", "SOFTFAIL", "PERMERROR", "NO_POLICY", "POLICY_FOUND", "NOT_PRESENT", "NO_VALID_FROM_DOMAIN"}
    statuses = [item["validated_status"] for item in checks.values()]
    completion = "NOT_PROVIDED" if not isinstance(validation, Mapping) else (
        "COMPLETE" if independent and all(status in terminal for status in statuses) else "INCOMPLETE"
    )
    return {
        "reported_results_trusted": bool(auth_analysis.get("authentication_results_trusted", False)) if isinstance(auth_analysis, Mapping) else False,
        "independent_validation": independent,
        "validation_completion": completion,
        "validated_domain": validated_domain,
        "checks": checks,
    }


def _intelligence_availability(ti: Any) -> Dict[str, Any]:
    if not isinstance(ti, Mapping):
        return {"status": "NOT_PROVIDED", "coverage_status": "UNKNOWN", "ioc_count": None, "matched_count": None}
    raw_status = _lower(ti.get("status"))
    provenance = ti.get("source_provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    coverage = _upper(ti.get("coverage_status") or provenance.get("coverage_status"))
    iocs = ti.get("iocs")
    ioc_summary = ti.get("ioc_summary")
    ioc_count = len(iocs) if isinstance(iocs, (list, tuple)) else (
        _safe_float(ioc_summary.get("total")) if isinstance(ioc_summary, Mapping) else None
    )
    matched_count = _safe_float(ti.get("matched_count")) if ti.get("matched_count") is not None else None
    if raw_status == "error": state = "ERROR"
    elif raw_status == "coverage_limited" or (raw_status == "no_matches" and coverage not in {"FRESH", "COMPLETE", "FULL"}): state = "PARTIAL_COVERAGE"
    elif raw_status == "no_iocs": state = "NO_INDICATORS"
    elif raw_status == "no_matches": state = "CHECKED_NO_MATCHES"
    elif raw_status == "matched": state = "MATCHES_FOUND"
    elif raw_status in {"unavailable", "not_configured", "disabled"}: state = "UNAVAILABLE"
    else: state = "UNKNOWN"
    return {"status": state, "source_status": raw_status.upper() or "NOT_PROVIDED",
            "coverage_status": coverage or "UNKNOWN", "ioc_count": ioc_count,
            "matched_count": matched_count, "meaning": "Lookup/coverage state is separate from message risk."}


def _fuse(signals: Sequence[Signal]) -> Tuple[float,float,Dict[str,Any]]:
    cats = _aggregate_categories(signals)
    groups = _effective_group_scores(cats, signals)
    if not groups:
        groups = {}
    weighted_sum = total_weight = 0.0
    for value in groups.values():
        quality = .70 + .30 * _clamp01(_safe_float(value.get("confidence")))
        weight = _safe_float(value.get("weight"), 1.0)
        weighted_sum += _safe_float(value.get("score")) * weight * quality
        total_weight += weight * quality
    base = weighted_sum / total_weight if total_weight else 0.0
    conv = _calculate_convergence(groups)
    strong = sorted([_safe_float(v.get("score")) for v in groups.values() if _safe_float(v.get("score")) >= 65], reverse=True)
    severe = sorted([_safe_float(v.get("score")) for v in groups.values() if _safe_float(v.get("score")) >= 80], reverse=True)
    corroboration_strength = sum(strong[:4]) / max(1, len(strong[:4]))
    severe_strength = sum(severe[:4]) / max(1, len(severe[:4])) if severe else 0
    severity_bonus = 5 if conv["severe_count"] >= 4 else 2.5 if conv["severe_count"] >= 2 else 0
    corroboration_bonus = 2 if conv["corroborated_count"] >= 4 else 1 if conv["corroborated_count"] >= 2 else 0
    base_component = .62 * base
    corroboration_component = .38 * corroboration_strength
    breadth_bonus = 2.5 if conv["independent_count"] >= 5 else 0.0
    final = _clamp(base_component + corroboration_component + conv["convergence_bonus"]
                   + severity_bonus + corroboration_bonus + breadth_bonus)
    confs = [_clamp01(_safe_float(v.get("confidence"))) for v in groups.values()]
    strong_confs = [_clamp01(_safe_float(v.get("confidence"))) for v in groups.values() if _safe_float(v.get("score")) >= 65]
    severe_confs = [_clamp01(_safe_float(v.get("confidence"))) for v in groups.values() if _safe_float(v.get("score")) >= 80]
    mean = sum(confs) / len(confs) if confs else 0
    strong_mean = sum(strong_confs) / len(strong_confs) if strong_confs else mean
    severe_mean = sum(severe_confs) / len(severe_confs) if severe_confs else strong_mean
    breadth = min(1, conv["independent_count"] / 6)
    corroboration = min(1, conv["corroborated_count"] / 5)
    severe_support = min(1, conv["severe_count"] / 4)
    evidence_conf = _clamp01(.16*mean + .30*strong_mean + .28*severe_mean + .14*breadth
                             + .12*max(corroboration, severe_support))
    meta = {
        "category_scores": cats, "fusion_groups": groups, "convergence": conv,
        "base_score": round(base, 6), "corroboration_strength": round(corroboration_strength, 6),
        "severe_strength": round(severe_strength, 6), "severity_bonus": round(severity_bonus, 6),
        "corroboration_bonus": round(corroboration_bonus, 6), "evidence_confidence": round(evidence_conf, 6),
        "correlation_groups": {key: value["score"] for key, value in groups.items()},
        "score_breakdown": [
            {"component":"weighted_evidence", "points":round(base_component,6), "source":"62% of evidence-group weighted score"},
            {"component":"corroboration", "points":round(corroboration_component,6), "source":"38% of strongest independent evidence groups"},
            {"component":"convergence_bonus", "points":round(conv["convergence_bonus"],6), "source":"independent evidence-group convergence"},
            {"component":"severity_bonus", "points":round(severity_bonus,6), "source":"multiple severe evidence groups"},
            {"component":"corroboration_bonus", "points":round(corroboration_bonus,6), "source":"corroborated evidence groups"},
            {"component":"evidence_breadth_bonus", "points":round(breadth_bonus,6), "source":"five or more independent evidence groups"},
        ],
    }
    return round(final,6), round(evidence_conf,6), meta


def _analyze_signal_contradictions(classification,model_probability,category_scores,evidence_confidence,overall_confidence):
    contradictions=[]
    ml_score=next((_safe_float(v.get("score")) for v in category_scores.values() if v.get("model_only")), model_probability*100)
    independent={c:_safe_float(v.get("score")) for c,v in category_scores.items() if not v.get("model_only")}
    strong={c:s for c,s in independent.items() if s>=75}; severe={c:s for c,s in independent.items() if s>=85}
    mean=sum(independent.values())/len(independent) if independent else 0
    if ml_score<40 and len(strong)>=2:
        contradictions.append({"type":"MODEL_EVIDENCE_CONFLICT","severity":"HIGH","description":"ML probability is low while multiple independent security evidence categories indicate elevated risk.","model_score":round(ml_score,6),"independent_categories":sorted(strong)})
    if ml_score>=80 and mean<45 and not strong:
        contradictions.append({"type":"MODEL_DOMINANT_RISK","severity":"MEDIUM","description":"ML indicates high risk but independent security evidence does not sufficiently corroborate the prediction.","model_score":round(ml_score,6),"independent_mean":round(mean,6)})
    if overall_confidence>=.82 and evidence_confidence<.50:
        contradictions.append({"type":"CONFIDENCE_EVIDENCE_MISMATCH","severity":"HIGH","description":"Overall confidence is high despite limited independent evidence confidence.","overall_confidence":round(overall_confidence,6),"evidence_confidence":round(evidence_confidence,6)})
    if ml_score<50 and severe:
        contradictions.append({"type":"CRITICAL_EVIDENCE_MODEL_DISAGREEMENT","severity":"CRITICAL","description":"Independent evidence reports severe risk while the ML model remains below the threat threshold.","model_score":round(ml_score,6),"severe_categories":sorted(severe)})
    ranks={"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    highest=max((x["severity"] for x in contradictions),key=lambda x:ranks.get(x,0),default="NONE")
    penalties={"LOW":.02,"MEDIUM":.04,"HIGH":.08,"CRITICAL":.12}
    penalty=min(.25,sum(penalties.get(x["severity"],0) for x in contradictions))
    return {"contradiction_count":len(contradictions),"highest_severity":highest,"confidence_penalty":round(penalty,6),
            "independent_evidence_mean":round(mean,6),"strong_independent_categories":sorted(strong),
            "severe_independent_categories":sorted(severe),"contradictions":contradictions}


def _derive_attack_intent(signals):
    cats={s.category for s in signals}; intents=[]
    mapping={"credential_theft":"CREDENTIAL_THEFT","fraud":"FINANCIAL_FRAUD","malware_delivery":"MALWARE_DELIVERY",
             "url":"LINK_BASED_DELIVERY","social_engineering":"SOCIAL_ENGINEERING"}
    for cat,label in mapping.items():
        if cat in cats: intents.append(label)
    if "identity" in cats or "impersonation" in cats: intents.append("IMPERSONATION")
    return intents


def _is_protective_security_notice(email):
    """Recognize narrow, non-actionable security-awareness disclaimers."""
    if not isinstance(email, Mapping):
        return False
    subject = _text(email.get("subject"))
    body = _text(email.get("body"))
    text = f"{subject}\n{body}".lower()
    protective_phrases = (
        "will never ask you to send a password",
        "will never ask you to send a password or one-time code",
        "do not use links in unexpected messages",
        "never ask you to share your password",
    )
    if not any(phrase in text for phrase in protective_phrases):
        return False
    if email.get("urls") or email.get("url_evidence"):
        return False
    if re.search(r"https?://|\bwww\.", text):
        return False
    actionable_phrases = (
        "click here", "open this", "enter your password", "submit your password",
        "provide your password", "send your password", "verify your account",
    )
    return not any(phrase in text for phrase in actionable_phrases)


ML_ONLY_HIGH_RISK_MIN_PROBABILITY = 0.60
PROTECTIVE_NOTICE_MAX_PROBABILITY = 0.70


def _decision(classification,risk_score,overall_confidence,evidence_confidence,signal_count):
    threat=classification in {"PHISHING","BEC","CREDENTIAL_THEFT","INVOICE_FRAUD","PAYMENT_DIVERSION","EXECUTIVE_IMPERSONATION","MALWARE_DELIVERY"}
    legitimate=classification in {"LEGITIMATE","BENIGN","SAFE","HAM"}
    if threat and risk_score>=90 and overall_confidence>=.80 and evidence_confidence>=.70 and signal_count>=5: return "HIGH_CONFIDENCE_THREAT"
    if threat and risk_score>=78 and overall_confidence>=.70 and signal_count>=3 and evidence_confidence>=.45: return "CORROBORATED_THREAT"
    if legitimate and risk_score<30 and overall_confidence>=.60: return "LIKELY_LEGITIMATE"
    if threat or risk_score>=60: return "SUSPICIOUS_REVIEW_REQUIRED"
    if risk_score<30 and overall_confidence>=.55: return "LIKELY_LEGITIMATE"
    return "INSUFFICIENT_EVIDENCE"


def _soc_severity(score, critical_count, confidence):
    if score>=90 and critical_count>=2 and confidence>=.65: return "CRITICAL"
    if score>=75: return "HIGH"
    if score>=50: return "MEDIUM"
    if score>=25: return "LOW"
    return "INFO"


def _recommended_disposition(decision, severity):
    if decision=="HIGH_CONFIDENCE_THREAT": return "ESCALATE_INCIDENT"
    if decision=="CORROBORATED_THREAT": return "QUEUE_FOR_SOC_TRIAGE"
    if severity in {"HIGH","CRITICAL"}: return "PRIORITY_ANALYST_REVIEW"
    if decision=="LIKELY_LEGITIMATE": return "CLOSE_AS_BENIGN_PENDING_POLICY"
    return "ANALYST_REVIEW_REQUIRED"


def _evidence_record(signal: Signal) -> Dict[str,Any]:
    evidence_ref = "EVD-" + sha256(
        f"{signal.detection_id}|{signal.source}|{signal.evidence}".encode("utf-8")
    ).hexdigest()[:16]
    return {"category":signal.category,"name":signal.name,"score":round(signal.score,6),
            "confidence":round(signal.confidence,6),"evidence":signal.evidence,"source":signal.source,
            "detection_id":signal.detection_id,"reason_code":signal.detection_id,
            "evidence_ref":evidence_ref,"correlation_group":signal.correlation_group,
            "mitre_techniques":list(signal.mitre_techniques),"source_reliability":round(signal.reliability,6)}


def _score_ledger(signals: Sequence[Signal], groups: Mapping[str, Mapping[str, Any]],
                  score_breakdown: Sequence[Mapping[str, Any]], final_score: float,
                  authentication: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    """Attribute the correlation-aware fusion equation to evidence groups and policy rows."""
    rows: List[Dict[str, Any]] = []
    for signal in signals:
        record = _evidence_record(signal)
        rows.append({
            "reason_code": record["reason_code"], "evidence_ref": record["evidence_ref"],
            "detector_source": signal.source, "category": signal.category,
            "correlation_group": signal.correlation_group, "evidence": signal.evidence,
            "raw_signal_score": round(signal.score, 6), "contribution": 0.0,
            "explanation": "Evidence input to the correlation-aware group contribution below; not added independently.",
        })

    weighted_total = sum(_safe_float(value.get("weight"), 1.0)
                         * (.70 + .30 * _clamp01(_safe_float(value.get("confidence"))))
                         for value in groups.values())
    qualifying = sorted([(name, _safe_float(value.get("score"))) for name, value in groups.items()
                         if _safe_float(value.get("score")) >= 65], key=lambda pair: pair[1], reverse=True)[:4]
    corroboration_share = {name: .38 * score / max(1, len(qualifying)) for name, score in qualifying}
    refs_by_category: Dict[str, List[str]] = {}
    for row in rows:
        refs_by_category.setdefault(row["category"], []).append(row["evidence_ref"])
    group_support_refs: List[str] = []
    for name, value in groups.items():
        members = list(value.get("categories", []))
        refs = [ref for category in members for ref in refs_by_category.get(category, [])]
        group_support_refs.extend(refs)
        score = _safe_float(value.get("score"))
        weight = _safe_float(value.get("weight"), 1.0)
        quality = .70 + .30 * _clamp01(_safe_float(value.get("confidence")))
        base_points = .62 * score * weight * quality / weighted_total if weighted_total else 0.0
        corr_points = corroboration_share.get(name, 0.0)
        slug = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
        rows.append({
            "reason_code": f"MT-FUS-GROUP-{slug}", "evidence_ref": refs[0] if len(refs) == 1 else None,
            "evidence_refs": refs, "detector_source": "intelligence_fusion_policy",
            "category": "evidence_group", "correlation_group": name,
            "evidence": f"Evidence group score {score:.6f}; overlap terms={','.join(value.get('evidence_overlap_terms', [])) or 'none'}.",
            "group_score": round(score, 6), "category_weight": round(weight, 6),
            "member_categories": members,
            "signal_confidence": round(_safe_float(value.get("confidence")), 6),
            "correlation_uplift": round(_safe_float(value.get("correlation_uplift")), 6),
            "base_contribution": round(base_points, 6), "corroboration_contribution": round(corr_points, 6),
            "contribution": round(base_points + corr_points, 6),
            "explanation": "One weighted evidence-group contribution; correlated categories do not receive separate category/convergence bonuses.",
        })
    for component in score_breakdown:
        name = _text(component.get("component"))
        if name in {"weighted_evidence", "corroboration"}:
            continue
        if _safe_float(component.get("points")) == 0:
            continue
        refs = list(group_support_refs)
        detector_source = "intelligence_fusion_policy"
        if name == "evidence_limited_cap":
            auth = authentication if isinstance(authentication, Mapping) else {}
            checks = auth.get("checks") if isinstance(auth.get("checks"), Mapping) else {}
            refs = []
            for method in ("spf", "dkim", "dmarc"):
                status = (checks.get(method) or {}).get("validated_status", "NOT_PROVIDED")
                material = f"{method}|{status}|{auth.get('validated_domain') or ''}"
                refs.append("EVD-AUTH-" + sha256(material.encode("utf-8")).hexdigest()[:16])
            detector_source = "authentication_validation_policy"
        rows.append({
            "reason_code": "MT-FUS-POLICY-" + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_"),
            "evidence_ref": refs[0] if len(refs) == 1 else None,
            "evidence_refs": refs,
            "detector_source": detector_source,
            "category": "fusion_policy", "evidence": component.get("source", ""),
            "contribution": round(_safe_float(component.get("points")), 6),
            "explanation": "Policy adjustment in the canonical fusion score; support references identify contributing evidence.",
        })
    delta = round(final_score - sum(_safe_float(row.get("contribution")) for row in rows), 6)
    if delta:
        rows.append({"reason_code": "MT-FUS-POLICY-ROUNDING_OR_CAP_RECONCILIATION",
                     "evidence_ref": None, "evidence_refs": [], "detector_source": "intelligence_fusion_policy",
                     "category": "fusion_policy", "evidence": "Final score reconciliation adjustment.",
                     "contribution": delta, "explanation": "Makes displayed ledger contributions sum to the canonical score."})
    return rows


def analyze_email_intelligence(email=None,ai_result=None,forensic=None,threat_intelligence=None,ip_intelligence=None) -> Dict[str,Any]:
    email=email if isinstance(email,Mapping) else {}
    signals=_build_signals(email,ai_result,forensic,threat_intelligence,ip_intelligence)
    unified,evidence_conf,fusion_meta=_fuse(signals)
    model_probability=_probability_from_ai(ai_result) if isinstance(ai_result,Mapping) else 0.0
    model_available = _model_available(ai_result)
    model_support=max(.50,min(.99,.50+abs(model_probability-.50)*.98)) if model_available else .50
    confidence_components={"model_support":round(model_support,6),"evidence_confidence":round(evidence_conf,6),
        "model_available":model_available,
        "evidence_breadth":round(min(1,fusion_meta["convergence"]["independent_count"]/6),6),
        "severe_evidence_support":round(min(1,fusion_meta["convergence"]["severe_count"]/4),6)}
    overall=_clamp01(.55*model_support+.45*evidence_conf)
    classification=_upper(ai_result.get("classification")) if isinstance(ai_result,Mapping) else "UNKNOWN"
    classification=classification or "UNKNOWN"
    contradiction=_analyze_signal_contradictions(classification,model_probability,fusion_meta["fusion_groups"],evidence_conf,overall)
    raw_conf=overall; overall=_clamp01(overall-contradiction["confidence_penalty"])
    independent=fusion_meta["convergence"]["independent_count"]
    before_evidence_cap = unified
    if independent==0 and unified>75: unified=75
    elif independent==1 and unified>85: unified=85
    if unified != before_evidence_cap:
        fusion_meta.setdefault("score_breakdown", []).append({
            "component":"independent_evidence_cap", "points":round(unified-before_evidence_cap, 6),
            "source":f"score capped for {independent} independent evidence groups"})
    validation=email.get("authentication_validation") or {}
    auth_summary = _authentication_contract(email, forensic)
    auth_all_pass=(auth_summary["independent_validation"] and bool(auth_summary["validated_domain"])
                   and all(auth_summary["checks"][key]["validated_status"] == "PASS"
                           for key in ("spf", "dkim", "dmarc")))
    protected={"credential_theft", "fraud", "malware_delivery", "identity", "threat_intelligence", "url"}
    if auth_all_pass and not any(s.category in protected for s in signals):
        uncapped=unified
        unified=min(unified, 15.0)
        if unified < uncapped:
            fusion_meta.setdefault("score_breakdown", []).append({
                "component":"evidence_limited_cap", "points":round(unified-uncapped, 6),
                "source":"authentication passed and no specific threat evidence was present"})
    # ML-only evidence must not trigger the API's >=50 HIGH RISK mapping
    # without sufficient probability or independent corroboration. A narrow
    # security-awareness disclaimer exception protects benign training notices.
    threat_classes = {"PHISHING", "BEC", "CREDENTIAL_THEFT", "INVOICE_FRAUD", "PAYMENT_DIVERSION", "EXECUTIVE_IMPERSONATION", "MALWARE_DELIVERY"}
    ml_only_low_confidence = (
        independent == 0 and model_available and classification in threat_classes
        and model_probability < ML_ONLY_HIGH_RISK_MIN_PROBABILITY
    )
    protective_notice = (
        independent == 0 and model_available and classification in threat_classes
        and model_probability < PROTECTIVE_NOTICE_MAX_PROBABILITY and _is_protective_security_notice(email)
    )
    if (ml_only_low_confidence or protective_notice) and unified >= 50.0:
        prior_score = unified
        unified = 49.0
        fusion_meta.setdefault("score_breakdown", []).append({
            "component": "uncorroborated_ml_risk_cap",
            "points": round(unified - prior_score, 6),
            "source": "uncorroborated ML-only verdict capped below the HIGH RISK API threshold",
        })
    breakdown=fusion_meta.get("score_breakdown", [])
    if breakdown:
        # Round-off is absorbed into the final line so displayed points sum to
        # the exact score emitted by fusion.
        delta=round(unified-sum(_safe_float(item.get("points")) for item in breakdown), 6)
        if delta:
            breakdown[-1]["points"]=round(_safe_float(breakdown[-1].get("points"))+delta, 6)
    evidence=[_evidence_record(s) for s in signals]
    score_ledger=_score_ledger(signals, fusion_meta["fusion_groups"], breakdown, unified, auth_summary)
    critical=[_evidence_record(s) for s in signals if (s.critical or s.score>=80) and independent>=2]
    risk_drivers=sorted([{"category":c,"score":round(_safe_float(v.get("score")),6),"confidence":round(_safe_float(v.get("confidence")),6)}
                         for c,v in fusion_meta["category_scores"].items()],key=lambda x:x["score"],reverse=True)
    decision=_decision(classification,unified,overall,evidence_conf,len(signals))
    risk_tier="CRITICAL" if unified>=90 else "HIGH" if unified>=75 else "MEDIUM" if unified>=50 else "LOW"
    data_quality=_calculate_data_quality(email,ai_result,forensic,threat_intelligence,ip_intelligence)
    soc_severity=_soc_severity(unified,len(critical),overall)
    mitre=sorted({t for s in signals for t in s.mitre_techniques})
    now=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    fingerprint_input="|".join(sorted(f"{s.detection_id}:{s.evidence}" for s in signals))
    analysis_fingerprint=sha256(fingerprint_input.encode()).hexdigest() if fingerprint_input else None
    return {
        "status":"ANALYZED","engine":ENGINE_NAME,"version":ENGINE_VERSION,
        "classification":classification,"model_probability":round(model_probability,6),
        "evidence_confidence":round(evidence_conf,6),"confidence":round(overall,6),
        "raw_confidence":round(raw_conf,6),"adjusted_confidence":round(overall,6),
        "confidence_penalty":contradiction["confidence_penalty"],"confidence_components":confidence_components,
        "contradiction_analysis":contradiction,"unified_risk_score":round(unified,6),
        "risk_tier":risk_tier,"decision":decision,"attack_intent":_derive_attack_intent(signals),
        "signal_count":len(signals),"evidence_count":len(evidence),"critical_signals":critical,
        "critical_signal_count":len(critical),"risk_drivers":risk_drivers,
        "explainability":{"reason":"Risk is derived from evidence groups, confidence/reliability weights, convergence and corroboration. Categories are merged only when same-family evidence text shares at least two meaningful terms. The score is not an ML probability.",
            "top_risk_drivers":risk_drivers[:6],"independent_evidence_components":fusion_meta["convergence"]["independent_categories"],
            "convergence":"MULTI_SIGNAL_CORROBORATION" if independent>=2 else "LIMITED_CORROBORATION"},
        "score_breakdown":fusion_meta.get("score_breakdown",[]),
        "score_ledger":score_ledger,
        "fusion_metrics":{"base_weighted_score":fusion_meta["base_score"],"corroboration_strength":fusion_meta["corroboration_strength"],
            "severe_strength":fusion_meta["severe_strength"],"convergence_bonus":fusion_meta["convergence"]["convergence_bonus"],
            "severity_bonus":fusion_meta["severity_bonus"],"corroboration_bonus":fusion_meta["corroboration_bonus"],
            "independent_category_count":independent,"corroborated_category_count":fusion_meta["convergence"]["corroborated_count"],
            "severe_category_count":fusion_meta["convergence"]["severe_count"],
            "correlation_group_count":len(fusion_meta["correlation_groups"]),
            "independent_evidence_group_count":independent},
        "fusion_group_details":fusion_meta["fusion_groups"],
        "evidence":evidence,
        "model_available":model_available,
        "authentication":auth_summary,
        "intelligence_availability":_intelligence_availability(threat_intelligence),
        "soc":{"schema_version":SCHEMA_VERSION,"policy_version":DETECTION_POLICY_VERSION,"analysis_timestamp":now,
            "analysis_fingerprint":analysis_fingerprint,"severity":soc_severity,
            "recommended_disposition":_recommended_disposition(decision,soc_severity),
            "analyst_disposition":"UNRESOLVED","mitre_attack_techniques":mitre,
            "data_quality":data_quality,"detection_count":len({s.detection_id for s in signals}),
            "correlation_groups":fusion_meta["correlation_groups"]},
        "governance":{"read_only":True,"persistence":False,"execution_side_effect":False,
            "autonomous_destructive_action":False,"model_probability_is_separate_from_confidence":True,
            "score_is_not_a_probability":True,"human_review_required_for_destructive_response":True,
            "policy_version":DETECTION_POLICY_VERSION},
    }


__all__=["ENGINE_NAME","ENGINE_VERSION","Signal","analyze_email_intelligence"]
