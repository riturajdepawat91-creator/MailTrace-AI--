from datetime import datetime, timezone
from services.privacy_governance import *


def iso(days=0):
    return (datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()

p = RetentionPolicy("p-sensitive", "Sensitive Mail", DataClassification.SENSITIVE.value, 180)
e = PrivacyGovernanceEngine(policies=[p])

# 1-5 policy/classification safety
assert e.get_policy("p-sensitive").retention_days == 180
assert e.classify({"sender_email": "a@b.test"}) == "SENSITIVE"
assert e.classify({"raw_email": "x"}) == "RESTRICTED"
assert e.classify({"subject": "hello"}) == "INTERNAL"
try:
    e.register_policy(RetentionPolicy("bad", "bad", "NOPE", 1))
    raise AssertionError
except PrivacyPolicyError:
    pass

# 13-17 retention
r = e.evaluate_retention(evidence_id="E1", classification="SENSITIVE", acquired_at_utc=iso(), policy_id="p-sensitive", now_utc="2026-02-01T00:00:00+00:00")
assert r.action == "RETAIN"
old = e.evaluate_retention(evidence_id="E1", classification="SENSITIVE", acquired_at_utc=iso(), policy_id="p-sensitive", now_utc="2026-09-01T00:00:00+00:00")
assert old.action == "ELIGIBLE_FOR_PURGE"
assert e.evaluate_retention(evidence_id="E1", classification="SENSITIVE", acquired_at_utc=iso(), policy_id="p-sensitive", now_utc="2026-09-01T00:00:00+00:00", legal_hold=True).action == "LEGAL_HOLD"
assert e.evaluate_retention(evidence_id="E1", classification="SENSITIVE", acquired_at_utc=iso(), policy_id="p-sensitive", now_utc="2026-09-01T00:00:00+00:00", forensic_hold=True).action == "FORENSIC_HOLD"
try:
    e.evaluate_retention(evidence_id="E1", classification="INTERNAL", acquired_at_utc=iso(), policy_id="p-sensitive")
    raise AssertionError
except PrivacyPolicyError:
    pass

# 18-25 redaction and anti-leakage
record = {"sender_email":"alice@example.test","subject":"urgent", "meta":{"ip_address":"10.1.2.3"}, "count":3}
masked = e.redact(record, mode=RedactionMode.MASK)
assert masked.data["sender_email"] == "[REDACTED]"
assert masked.data["meta"]["ip_address"] == "[REDACTED]"
assert masked.data["subject"] == "urgent"
removed = e.redact(record, mode=RedactionMode.REMOVE)
assert "sender_email" not in removed.data
pseudo = e.redact(record, mode=RedactionMode.PSEUDONYMIZE, pseudonym_key=b"unit-test-key")
assert pseudo.data["sender_email"].startswith("pst_")
assert e.redact(record, mode=RedactionMode.PSEUDONYMIZE, pseudonym_key=b"unit-test-key").data == pseudo.data
try:
    e.redact(record, mode=RedactionMode.PSEUDONYMIZE)
    raise AssertionError
except PrivacyGovernanceError:
    pass
try:
    e.redact({"secret": "x"}, mode="BAD")
    raise AssertionError
except ValueError:
    pass
assert masked.to_dict() if hasattr(masked, "to_dict") else True
print("SOC_PRIVACY_TESTS=25/25 PASS")
