from __future__ import annotations

from enum import Enum

ANALYSIS_NAME = "privacy_data_governance"
ANALYSIS_VERSION = "1.0.0"
MAX_RECORD_FIELDS = 500
MAX_NESTING = 12
MAX_STRING_CHARS = 200_000
MAX_POLICY_NAME_CHARS = 128
MAX_PURPOSE_CHARS = 128
MAX_ACTOR_CHARS = 256
MAX_CLASSIFICATION_CHARS = 32
MAX_RETENTION_DAYS = 3650


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    RESTRICTED = "RESTRICTED"


class RedactionMode(str, Enum):
    MASK = "MASK"
    REMOVE = "REMOVE"
    PSEUDONYMIZE = "PSEUDONYMIZE"




class RetentionAction(str, Enum):
    RETAIN = "RETAIN"
    ELIGIBLE_FOR_PURGE = "ELIGIBLE_FOR_PURGE"
    LEGAL_HOLD = "LEGAL_HOLD"
    FORENSIC_HOLD = "FORENSIC_HOLD"


DEFAULT_RETENTION_DAYS = {
    DataClassification.PUBLIC.value: 30,
    DataClassification.INTERNAL.value: 90,
    DataClassification.SENSITIVE.value: 180,
    DataClassification.RESTRICTED.value: 365,
}

# Keys that are commonly privacy-sensitive in email/forensic records.
DEFAULT_SENSITIVE_FIELDS = frozenset({
    "email",
    "email_address",
    "sender_email",
    "recipient_email",
    "reply_to",
    "return_path",
    "display_name",
    "phone",
    "phone_number",
    "name",
    "full_name",
    "address",
    "ip",
    "ip_address",
    "user_agent",
    "authorization",
    "token",
    "secret",
    "cookie",
    "raw_email",
})
