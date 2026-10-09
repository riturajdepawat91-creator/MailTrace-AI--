from __future__ import annotations

from enum import Enum
import re


ANALYSIS_NAME = "evidence_preservation_chain_of_custody"
ANALYSIS_VERSION = "1.0.0"
STATIC_ONLY = True

MAX_EVIDENCE_ID_CHARS = 128
MAX_CASE_ID_CHARS = 128
MAX_ACTOR_CHARS = 256
MAX_SOURCE_CHARS = 2048
MAX_DESTINATION_CHARS = 2048
MAX_REASON_CHARS = 2048
MAX_PURPOSE_CHARS = 2048
MAX_PATH_CHARS = 4096
MAX_METADATA_KEYS = 100
MAX_EVENTS_PER_EVIDENCE = 10000
MAX_EVIDENCE_RECORDS = 100000
MAX_MANIFEST_ITEMS = 100000
MAX_EXPORT_ITEMS = 100000

SHA256 = "sha256"
SHA512 = "sha512"

READ_ONLY_STATES = {
    "SEALED",
    "ARCHIVED",
}

class EvidenceState(str, Enum):
    ACQUIRED = "ACQUIRED"
    SEALED = "SEALED"
    IN_CUSTODY = "IN_CUSTODY"
    ARCHIVED = "ARCHIVED"
    COMPROMISED = "COMPROMISED"


class CustodyEventType(str, Enum):
    COLLECTED = "COLLECTED"
    SEALED = "SEALED"
    TRANSFERRED = "TRANSFERRED"
    RECEIVED = "RECEIVED"
    ACCESSED = "ACCESSED"
    VERIFIED = "VERIFIED"
    EXPORTED = "EXPORTED"
    ARCHIVED = "ARCHIVED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


ALLOWED_TRANSITIONS = {
    "ACQUIRED": {
        "SEAL",
        "TRANSFER",
        "VERIFY",
        "COMPROMISE",
    },
    "SEALED": {
        "TRANSFER",
        "ACCESS",
        "VERIFY",
        "EXPORT",
        "ARCHIVE",
        "COMPROMISE",
    },
    "IN_CUSTODY": {
        "TRANSFER",
        "RECEIVE",
        "ACCESS",
        "VERIFY",
        "EXPORT",
        "ARCHIVE",
        "COMPROMISE",
    },
    "ARCHIVED": {
        "VERIFY",
        "ACCESS",
        "COMPROMISE",
    },
    "COMPROMISED": {
        "VERIFY",
    },
}

MAX_EVIDENCE_SIZE_BYTES = 2 * 1024 * 1024 * 1024

EVENT_TO_STATE = {
    "COLLECTED": "ACQUIRED",
    "SEALED": "SEALED",
    "TRANSFERRED": "IN_CUSTODY",
    "RECEIVED": "IN_CUSTODY",
    "ARCHIVED": "ARCHIVED",
    "INTEGRITY_FAILURE": "COMPROMISED",
}

SEVERITY_INFO = "INFO"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Durable persistence safety bounds.
MAX_PERSISTED_EVENT_BYTES = 512 * 1024
MAX_PERSISTED_STATE_BYTES = 64 * 1024 * 1024
STATE_SCHEMA_VERSION = 1

# ============================================================
# SOC+ STORAGE ISOLATION
# ============================================================

SAFE_EVIDENCE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)

FORBIDDEN_EVIDENCE_ID_VALUES = frozenset({
    ".",
    "..",
})
