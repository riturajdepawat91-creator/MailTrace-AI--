import json
import unittest

from services.campaign_correlation import correlate_campaigns


def investigation(identifier, *, matched=None, score=0, subject="Notice"):
    matched = matched or {}
    iocs = [{"ioc": value, "ioc_type": kind} for value, kind in matched.items()]
    return {
        "investigation_id": identifier,
        "subject": subject,
        "sender": "same@example.test",
        "recipient": "analyst@example.test",
        "threat_score": score,
        "threat_verdict": "HIGH" if score >= 70 else "LOW",
        "analysis_json": json.dumps({
            "threat_intelligence": {
                "iocs": iocs,
                "matches": {value: [{"source": "fixture-feed"}] for value in matched},
            }
        }),
    }


class CampaignCorrelationTests(unittest.TestCase):
    def test_same_subject_and_sender_do_not_create_campaign(self):
        campaigns = correlate_campaigns([
            investigation("INV-1"), investigation("INV-2")
        ])
        self.assertEqual(campaigns, [])

    def test_shared_matched_indicator_creates_explainable_stable_campaign(self):
        items = [
            investigation("INV-1", matched={"bad.example": "domain"}, score=72),
            investigation("INV-2", matched={"bad.example": "domain"}, score=45),
        ]
        first = correlate_campaigns(items)
        second = correlate_campaigns(list(reversed(items)))
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["campaign_id"], second[0]["campaign_id"])
        self.assertEqual(first[0]["email_count"], 2)
        self.assertEqual(first[0]["indicator_count"], 1)
        self.assertEqual(first[0]["severity"], "HIGH")
        self.assertIn("threat-intelligence", first[0]["description"])
        self.assertEqual(len(first[0]["investigations"]), 2)

    def test_unmatched_ioc_does_not_create_campaign(self):
        records = [
            investigation("INV-1", matched={"shared.example": "domain"}),
            investigation("INV-2", matched={"shared.example": "domain"}),
        ]
        for record in records:
            analysis = json.loads(record["analysis_json"])
            analysis["threat_intelligence"]["matches"] = {}
            record["analysis_json"] = json.dumps(analysis)
        self.assertEqual(correlate_campaigns(records), [])

    def test_common_provider_domain_is_not_campaign_evidence(self):
        campaigns = correlate_campaigns([
            investigation("INV-1", matched={"mail.google.com": "domain"}),
            investigation("INV-2", matched={"mail.google.com": "domain"}),
        ])
        self.assertEqual(campaigns, [])

    def test_explicit_feed_campaign_label_links_different_iocs(self):
        records = [
            investigation("INV-1", matched={"alpha.example": "domain"}),
            investigation("INV-2", matched={"beta.example": "domain"}),
        ]
        for record in records:
            analysis = json.loads(record["analysis_json"])
            match_key = next(iter(analysis["threat_intelligence"]["matches"]))
            analysis["threat_intelligence"]["matches"][match_key][0]["campaign"] = "Operation Test"
            record["analysis_json"] = json.dumps(analysis)
        campaigns = correlate_campaigns(records)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["indicator_count"], 0)
        self.assertIn("Operation Test", campaigns[0]["name"])


if __name__ == "__main__":
    unittest.main()
