from __future__ import annotations

"""
MailTrace-AI SOC Production Intelligence Fusion Engine.

Backward compatible with the existing analyze_email_intelligence() interface.
All existing top-level response keys are preserved; SOC-focused fields are additive.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


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
    value = _text(value)
    return value.rsplit("@", 1)[-1].strip().lower() if "@" in value else ""


def _has_any(text: str, terms: Iterable[str]) -> bool:
    normalized = _lower(text)
    return any(term in normalized for term in terms)


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


def _ai_signal(ai_result: Mapping[str, Any]) -> Signal | None:
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
    combined = f"{_text(email.get('subject'))}\n{_text(email.get('body'))}"
    signals: List[Signal] = []
    groups = [
        ("credential_theft", "credential_harvesting_language", 90, .88,
         ("password","verify your account","verify your identity","login","sign in","credential","authentication","security verification"),
         "Credential/login verification language detected.", True),
        ("fraud", "financial_fraud_language", 88, .87,
         ("payment","invoice","wire transfer","bank transfer","transfer funds","beneficiary","account details","refund","payment verification"),
         "Payment/invoice/transfer language detected.", True),
        ("impersonation", "authority_impersonation_language", 76, .74,
         ("ceo","cfo","director","administrator","security team","finance team","management"),
         "Authority/executive language detected.", False),
    ]
    for cat, name, score, conf, terms, evidence, critical in groups:
        if _has_any(combined, terms):
            signals.append(_make_signal(cat, name, score, conf, evidence, critical, "email_content", .80))
    urgency = ("urgent","immediately","right away","suspended","deadline","act now","within 24")
    social = ("suspended","verify","urgent","confidential","immediately","act now","avoid closure")
    if _has_any(combined, urgency) and _has_any(combined, social):
        signals.append(_make_signal("social_engineering","urgency_pressure_pattern",82,.84,
                                    "Urgency and pressure-to-act pattern detected.",True,"email_content",.82))
    return signals


def _identity_signals(email: Mapping[str, Any]) -> List[Signal]:
    sender, reply_to = _text(email.get("sender")), _text(email.get("reply_to"))
    sender_domain = _lower(email.get("sender_domain")) or _domain_from_email(sender)
    reply_domain = _domain_from_email(reply_to)
    out: List[Signal] = []
    if sender and reply_to and sender.lower() != reply_to.lower():
        out.append(_make_signal("identity","sender_reply_to_mismatch",92,.94,
                                f"Sender={sender}; Reply-To={reply_to}.",True,"identity_analysis",.95))
    if sender_domain and reply_domain and sender_domain != reply_domain:
        out.append(_make_signal("identity","sender_reply_domain_mismatch",94,.95,
                                f"Sender domain={sender_domain}; Reply-To domain={reply_domain}.",True,"identity_analysis",.97))
    return out


def _header_signals(email: Mapping[str, Any]) -> List[Signal]:
    validation = email.get("authentication_validation") or {}
    if not isinstance(validation, Mapping):
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
    urls = _as_list(email.get("urls"))
    if not urls:
        return []
    markers = ("login","verify","secure","account","signin","password","update","confirm")
    suspicious = sum(_has_any(_lower(url), markers) for url in urls)
    score = min(94,68+suspicious*8) if suspicious else 58
    conf = min(.93,.72+suspicious*.05) if suspicious else .65
    return [_make_signal("url","url_delivery_signal",score,conf,
                         f"{len(urls)} URL(s) present; {suspicious} contain suspicious delivery markers.",
                         suspicious >= 1,"url_intelligence",.72)]


def _attachment_signals(email: Mapping[str, Any]) -> List[Signal]:
    attachments = _as_list(email.get("attachments"))
    if not attachments:
        return []
    dangerous_ext = {".exe",".scr",".js",".vbs",".bat",".cmd",".ps1",".msi",".dll",".hta",".lnk",".iso"}
    dangerous = 0
    for item in attachments:
        name = _lower(item.get("filename") if isinstance(item, Mapping) else item)
        dangerous += any(name.endswith(ext) for ext in dangerous_ext)
    if dangerous:
        return [_make_signal("malware_delivery","attachment_delivery_risk",
                             min(100,86+dangerous*6),min(.98,.84+dangerous*.05),
                             f"{len(attachments)} attachment(s); {dangerous} dangerous executable/script attachment(s).",
                             True,"attachment_intelligence",.88)]
    return [_make_signal("attachment","attachment_presence",48,.58,
                         f"{len(attachments)} attachment(s) present.",False,"attachment_intelligence",.55)]


def _forensic_signals(forensic: Mapping[str, Any] | None) -> List[Signal]:
    if not isinstance(forensic, Mapping):
        return []
    score = _safe_float(forensic.get("risk_score", forensic.get("score", 0)))
    if score <= 0:
        return []
    score = _clamp(score)
    return [_make_signal("forensics","email_forensic_risk",score,min(.96,.60+score/250),
                         f"Forensic analysis risk_score={score:.2f}.",score>=80,"email_forensics",.82)]


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
    independent = {c for c,v in category_scores.items() if c!="ml" and _safe_float(v.get("score"))>=55}
    corroborated = {c for c,v in category_scores.items() if _safe_float(v.get("score"))>=65}
    severe = {c for c,v in category_scores.items() if _safe_float(v.get("score"))>=80}
    return {"independent_categories":sorted(independent),"corroborated_categories":sorted(corroborated),
            "severe_categories":sorted(severe),"independent_count":len(independent),
            "corroborated_count":len(corroborated),"severe_count":len(severe),
            "convergence_bonus":round(min(15,max(0,(len(independent)-1)*3)),6)}


def _calculate_data_quality(email, ai_result, forensic, ti, ip) -> Dict[str,Any]:
    expected = {"subject":email.get("subject"),"body":email.get("body"),
                "sender":email.get("sender"),"headers":email.get("headers"),
                "urls":email.get("urls")}
    present = [k for k,v in expected.items() if v not in (None,"",{},[])]
    missing = [k for k in expected if k not in present]
    enrichment = {"ai_result":isinstance(ai_result,Mapping),"forensic":isinstance(forensic,Mapping),
                  "threat_intelligence":isinstance(ti,Mapping),"ip_intelligence":isinstance(ip,Mapping)}
    enrichment_count = sum(enrichment.values())
    completeness = _clamp01(.70*(len(present)/len(expected))+.30*(enrichment_count/4))
    return {"completeness":round(completeness,6),"present_components":present,
            "missing_components":missing,"enrichment_available":enrichment,
            "enrichment_count":enrichment_count}


def _fuse(signals: Sequence[Signal]) -> Tuple[float,float,Dict[str,Any]]:
    if not signals:
        meta={"category_scores":{},"convergence":_calculate_convergence({}),"base_score":0.0,
              "evidence_confidence":0.0,"correlation_groups":[]}
        return 0.0,0.0,meta
    cats = _aggregate_categories(signals)
    grouped_scores: Dict[str,List[float]] = {}
    for cat,v in cats.items():
        group = CATEGORY_CORRELATION_GROUPS.get(cat,cat)
        grouped_scores.setdefault(group,[]).append(_safe_float(v.get("score")))
    # Correlated categories contribute as one group using strongest evidence plus limited secondary uplift.
    correlation_group_scores = {}
    for group, scores in grouped_scores.items():
        ordered = sorted(scores, reverse=True)
        correlation_group_scores[group] = ordered[0] + min(8.0, sum(ordered[1:])*.08)
    weighted_sum=total_weight=0.0
    for cat,v in cats.items():
        score,conf=_safe_float(v.get("score")),_safe_float(v.get("confidence"))
        w=CATEGORY_WEIGHTS.get(cat,1.0); quality=.70+.30*_clamp01(conf)
        weighted_sum += score*w*quality; total_weight += w*quality
    base=weighted_sum/total_weight if total_weight else 0
    conv=_calculate_convergence(cats)
    strong=sorted([_safe_float(v.get("score")) for v in cats.values() if _safe_float(v.get("score"))>=65],reverse=True)
    severe=sorted([_safe_float(v.get("score")) for v in cats.values() if _safe_float(v.get("score"))>=80],reverse=True)
    corroboration_strength=sum(strong[:4])/max(1,len(strong[:4]))
    severe_strength=sum(severe[:4])/max(1,len(severe[:4])) if severe else 0
    severity_bonus=5 if conv["severe_count"]>=4 else 2.5 if conv["severe_count"]>=2 else 0
    corroboration_bonus=2 if conv["corroborated_count"]>=4 else 1 if conv["corroborated_count"]>=2 else 0
    final=.62*base+.38*corroboration_strength+conv["convergence_bonus"]+severity_bonus+corroboration_bonus
    if conv["independent_count"]>=5: final+=2.5
    final=_clamp(final)
    confs=[_clamp01(_safe_float(v.get("confidence"))) for v in cats.values()]
    strong_confs=[_clamp01(_safe_float(v.get("confidence"))) for v in cats.values() if _safe_float(v.get("score"))>=65]
    severe_confs=[_clamp01(_safe_float(v.get("confidence"))) for v in cats.values() if _safe_float(v.get("score"))>=80]
    mean=sum(confs)/len(confs) if confs else 0
    strong_mean=sum(strong_confs)/len(strong_confs) if strong_confs else mean
    severe_mean=sum(severe_confs)/len(severe_confs) if severe_confs else strong_mean
    breadth=min(1,conv["independent_count"]/6); corroboration=min(1,conv["corroborated_count"]/5); severe_support=min(1,conv["severe_count"]/4)
    evidence_conf=_clamp01(.16*mean+.30*strong_mean+.28*severe_mean+.14*breadth+.12*max(corroboration,severe_support))
    meta={"category_scores":cats,"convergence":conv,"base_score":round(base,6),
          "corroboration_strength":round(corroboration_strength,6),"severe_strength":round(severe_strength,6),
          "severity_bonus":round(severity_bonus,6),"corroboration_bonus":round(corroboration_bonus,6),
          "evidence_confidence":round(evidence_conf,6),"correlation_groups":correlation_group_scores}
    return round(final,6),round(evidence_conf,6),meta


def _analyze_signal_contradictions(classification,model_probability,category_scores,evidence_confidence,overall_confidence):
    contradictions=[]
    ml_score=_safe_float(category_scores.get("ml",{}).get("score"),model_probability*100)
    independent={c:_safe_float(v.get("score")) for c,v in category_scores.items() if c!="ml"}
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
    return {"category":signal.category,"name":signal.name,"score":round(signal.score,6),
            "confidence":round(signal.confidence,6),"evidence":signal.evidence,"source":signal.source,
            "detection_id":signal.detection_id,"correlation_group":signal.correlation_group,
            "mitre_techniques":list(signal.mitre_techniques),"source_reliability":round(signal.reliability,6)}


def analyze_email_intelligence(email=None,ai_result=None,forensic=None,threat_intelligence=None,ip_intelligence=None) -> Dict[str,Any]:
    email=email if isinstance(email,Mapping) else {}
    signals=_build_signals(email,ai_result,forensic,threat_intelligence,ip_intelligence)
    unified,evidence_conf,fusion_meta=_fuse(signals)
    model_probability=_probability_from_ai(ai_result) if isinstance(ai_result,Mapping) else 0.0
    model_support=max(.50,min(.99,.50+abs(model_probability-.50)*.98))
    confidence_components={"model_support":round(model_support,6),"evidence_confidence":round(evidence_conf,6),
        "evidence_breadth":round(min(1,fusion_meta["convergence"]["independent_count"]/6),6),
        "severe_evidence_support":round(min(1,fusion_meta["convergence"]["severe_count"]/4),6)}
    overall=_clamp01(.55*model_support+.45*evidence_conf)
    classification=_upper(ai_result.get("classification")) if isinstance(ai_result,Mapping) else "UNKNOWN"
    classification=classification or "UNKNOWN"
    contradiction=_analyze_signal_contradictions(classification,model_probability,fusion_meta["category_scores"],evidence_conf,overall)
    raw_conf=overall; overall=_clamp01(overall-contradiction["confidence_penalty"])
    independent=fusion_meta["convergence"]["independent_count"]
    if independent==0 and unified>75: unified=75
    elif independent==1 and unified>85: unified=85
    evidence=[_evidence_record(s) for s in signals]
    critical=[_evidence_record(s) for s in signals if s.critical or s.score>=80]
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
        "explainability":{"reason":"Risk is derived from grouped evidence with convergence, correlation controls and corroboration; the score is not an ML probability.",
            "top_risk_drivers":risk_drivers[:6],"independent_evidence_components":fusion_meta["convergence"]["independent_categories"],
            "convergence":"MULTI_SIGNAL_CORROBORATION" if independent>=2 else "LIMITED_CORROBORATION"},
        "fusion_metrics":{"base_weighted_score":fusion_meta["base_score"],"corroboration_strength":fusion_meta["corroboration_strength"],
            "severe_strength":fusion_meta["severe_strength"],"convergence_bonus":fusion_meta["convergence"]["convergence_bonus"],
            "severity_bonus":fusion_meta["severity_bonus"],"corroboration_bonus":fusion_meta["corroboration_bonus"],
            "independent_category_count":independent,"corroborated_category_count":fusion_meta["convergence"]["corroborated_count"],
            "severe_category_count":fusion_meta["convergence"]["severe_count"],
            "correlation_group_count":len(fusion_meta["correlation_groups"])},
        "evidence":evidence,
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
