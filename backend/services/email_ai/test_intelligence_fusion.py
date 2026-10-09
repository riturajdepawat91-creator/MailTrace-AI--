from __future__ import annotations

from services.email_ai.intelligence_fusion import (
    ENGINE_NAME,
    ENGINE_VERSION,
    analyze_email_intelligence,
)


def main():
    email = {
        "sender": "finance@example-bank.com",
        "reply_to": "attacker@evil-example.test",
        "sender_domain": "example-bank.com",
        "subject": "URGENT payment verification required",
        "body": (
            "Your account will be suspended immediately. "
            "Verify your password and complete the payment "
            "using the secure login link."
        ),
        "urls": [
            "https://secure-login.example.test/verify",
        ],
        "attachments": [
            "payment_update.zip",
            "invoice.exe",
        ],
        "headers": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "authentication_results": (
                "spf=fail dkim=fail dmarc=fail"
            ),
        },
    }

    ai_result = {
        "classification": "PHISHING",
        "calibrated_probability": 0.97,
        "model_probability": 0.97,
    }

    forensic = {
        "risk_score": 88,
    }

    threat_intelligence = {
        "matches": [
            {
                "ioc": "evil-example.test",
                "verdict": "malicious",
            }
        ]
    }

    ip_intelligence = {
        "203.0.113.10": {
            "risk_score": 91,
        }
    }

    result = analyze_email_intelligence(
        email=email,
        ai_result=ai_result,
        forensic=forensic,
        threat_intelligence=threat_intelligence,
        ip_intelligence=ip_intelligence,
    )

    assert result["status"] == "ANALYZED"
    assert result["engine"] == ENGINE_NAME
    assert result["version"] == ENGINE_VERSION
    assert ENGINE_VERSION == "3.0.0"

    assert result["classification"] == "PHISHING"

    assert 90.0 <= result["unified_risk_score"] <= 100.0

    assert result["model_probability"] == 0.97

    assert 0.80 <= result["confidence"] <= 1.0
    assert 0.70 <= result["evidence_confidence"] <= 1.0

    assert result["decision"] in {
        "HIGH_CONFIDENCE_THREAT",
        "CORROBORATED_THREAT",
    }

    assert "CREDENTIAL_THEFT" in result["attack_intent"]
    assert "FINANCIAL_FRAUD" in result["attack_intent"]
    assert "MALWARE_DELIVERY" in result["attack_intent"]

    assert result["evidence_count"] >= 6
    assert result["critical_signal_count"] >= 2

    assert (
        result["fusion_metrics"][
            "independent_category_count"
        ] >= 5
    )

    assert (
        result["confidence_components"][
            "model_support"
        ] >= 0.90
    )

    assert (
        result["governance"]["read_only"]
        is True
    )

    assert (
        result["governance"]["persistence"]
        is False
    )

    assert (
        result["governance"][
            "execution_side_effect"
        ]
        is False
    )

    assert (
        result["governance"][
            "score_is_not_a_probability"
        ]
        is True
    )

    assert (
        result["governance"][
            "model_probability_is_separate_from_confidence"
        ]
        is True
    )

    print("AI_FUSION_ENGINE: PASS")
    print("ENGINE:", ENGINE_NAME)
    print("VERSION:", ENGINE_VERSION)
    print(
        "UNIFIED_RISK_SCORE:",
        result["unified_risk_score"],
    )
    print(
        "MODEL_PROBABILITY:",
        result["model_probability"],
    )
    print(
        "EVIDENCE_CONFIDENCE:",
        result["evidence_confidence"],
    )
    print(
        "OVERALL_CONFIDENCE:",
        result["confidence"],
    )
    print(
        "CONFIDENCE_COMPONENTS:",
        result["confidence_components"],
    )
    print(
        "RISK_TIER:",
        result["risk_tier"],
    )
    print(
        "DECISION:",
        result["decision"],
    )
    print(
        "ATTACK_INTENT:",
        result["attack_intent"],
    )
    print(
        "EVIDENCE_COUNT:",
        result["evidence_count"],
    )
    print(
        "CRITICAL_SIGNAL_COUNT:",
        result["critical_signal_count"],
    )
    print(
        "INDEPENDENT_CATEGORY_COUNT:",
        result["fusion_metrics"][
            "independent_category_count"
        ],
    )
    print(
        "PERSISTENCE:",
        result["governance"]["persistence"],
    )
    print(
        "EXECUTION_SIDE_EFFECT:",
        result["governance"][
            "execution_side_effect"
        ],
    )


if __name__ == "__main__":
    main()
