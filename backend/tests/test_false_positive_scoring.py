from email.message import Message

from services.domain_alignment import domains_differ, organizational_domain
from services.email_ai.intelligence_fusion import analyze_email_intelligence
from services.email_parser import analyze_threat


def _passed_auth():
    return {key: {"status": "PASS"} for key in ("spf", "dkim", "dmarc")}


def _parser_threat_result(subject, body):
    message = Message()
    message["From"] = "updates@example.test"
    message["Subject"] = subject
    return analyze_threat(message, body, [], {"validation": {}}, [])


def test_organizational_domains_follow_public_suffix_boundaries():
    assert organizational_domain("updates@myntra.com") == "myntra.com"
    assert organizational_domain("myntramailers.myntra.com") == "myntra.com"
    assert not domains_differ("myntra.com", "myntramailers.myntra.com")
    assert not domains_differ("bounce.shop.example.co.uk", "mail.example.co.uk")
    assert domains_differ("example.co.uk", "other.co.uk")
    assert domains_differ("myntra.com", "myntra.com.evil.net")


def test_promotional_mail_with_passed_auth_does_not_escalate_on_generic_copy():
    result = analyze_email_intelligence(
        email={
            "sender": "updates@myntra.com",
            "subject": "It's LIVE! 3X Discounts",
            "body": "Offers may be revoked or suspended. Shop now. Unsubscribe.",
            "headers": {"List-Unsubscribe": "<https://track.myntra.com/unsubscribe>"},
            "urls": ["https://track.myntra.com/click"],
            "attachments": [],
            "authentication_validation": _passed_auth(),
        },
        ai_result={"status": "MODEL_NOT_READY", "classification": "UNKNOWN"},
        forensic={"risk_score": 82, "findings": [
            {"severity": "MEDIUM", "title": "From and Return-Path domains differ"}
        ]},
        threat_intelligence={"matches": [], "matched_count": 0},
    )
    assert result["unified_risk_score"] <= 15
    assert result["critical_signal_count"] == 0
    assert "urgency_pressure_pattern" not in {item["name"] for item in result["evidence"]}
    assert "calibrated_ml_probability" not in {item["name"] for item in result["evidence"]}
    assert round(sum(item["points"] for item in result["score_breakdown"]), 6) == result["unified_risk_score"]


def test_phishing_sample_remains_high_risk_despite_authentication_passes():
    result = analyze_email_intelligence(
        email={
            "sender": "security@fakebank.example",
            "subject": "Urgent: verify your account",
            "body": "Your account will be suspended. Verify your account and enter your password immediately.",
            "urls": ["https://fakebank-login.example.test/secure"],
            "advanced_url_intelligence": {"risk_score": 76, "verdict": "HIGH_CONFIDENCE_DECEPTIVE"},
            "attachments": [],
            "authentication_validation": _passed_auth(),
        },
        ai_result={"status": "MODEL_NOT_READY"},
        threat_intelligence={"matches": []},
    )
    assert result["unified_risk_score"] >= 75
    assert {item["category"] for item in result["evidence"]} & {"credential_theft", "url"}
    assert round(sum(item["points"] for item in result["score_breakdown"]), 6) == result["unified_risk_score"]


def test_single_generic_signal_is_not_reported_as_corroborated_critical():
    result = analyze_email_intelligence(
        email={"body": "Act now before the deadline."},
        ai_result={"status": "MODEL_NOT_READY"},
    )
    assert result["critical_signal_count"] == 0


def test_disclaimer_urgency_words_do_not_add_parser_social_engineering_points():
    result = _parser_threat_result(
        "Offer details",
        "Offers may be revoked or suspended under the terms and conditions.",
    )

    assert result["score"] == 0
    assert not any(i["type"] == "social_engineering" for i in result["indicators"])


def test_quoted_or_negated_urgency_does_not_add_parser_social_engineering_points():
    for body in (
        'The message said, "Your account is suspended immediately," as an example.',
        "We will never ask you to verify your account immediately by email.",
    ):
        result = _parser_threat_result("Account security guidance", body)
        assert result["score"] == 0
        assert not any(i["type"] == "social_engineering" for i in result["indicators"])


def test_fusion_ignores_quoted_or_negated_credential_pressure_phrases():
    for body in (
        'The sample said, "Your account will be suspended immediately. Verify your account."',
        "We will never ask you to verify your account immediately or enter your password.",
        "Our fraud-prevention training discusses password safety and identity verification.",
    ):
        result = analyze_email_intelligence(
            email={"subject": "Security guidance", "body": body},
            ai_result={"status": "MODEL_NOT_READY"},
        )
        assert not {item["name"] for item in result["evidence"]} & {
            "credential_harvesting_language",
            "urgency_pressure_pattern",
        }


def test_actionable_suspension_phishing_keeps_parser_and_fusion_evidence():
    subject = "Urgent: verify your account"
    body = "Your account will be suspended immediately. Verify your account and enter your password."
    parsed = _parser_threat_result(subject, body)
    fused = analyze_email_intelligence(
        email={"subject": subject, "body": body},
        ai_result={"status": "MODEL_NOT_READY"},
    )

    assert any(i["type"] == "social_engineering" for i in parsed["indicators"])
    assert {item["name"] for item in fused["evidence"]} >= {
        "credential_harvesting_language",
        "urgency_pressure_pattern",
    }
