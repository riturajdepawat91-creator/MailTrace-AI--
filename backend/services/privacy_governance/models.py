from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .rules import DataClassification, RedactionMode, RetentionAction


@dataclass(frozen=True)
class RetentionPolicy:
    policy_id: str
    name: str
    classification: str
    retention_days: int
    legal_hold_allowed: bool = True
    forensic_hold_allowed: bool = True
    purge_derived_views: bool = True
    purge_raw_evidence: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)






@dataclass(frozen=True)
class RetentionEvaluation:
    action: str
    evidence_id: str
    classification: str
    policy_id: str | None
    expires_at_utc: str
    legal_hold: bool
    forensic_hold: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RedactionResult:
    data: dict[str, Any]
    classification: str
    mode: str
    redacted_fields: tuple[str, ...] = field(default_factory=tuple)
    removed_fields: tuple[str, ...] = field(default_factory=tuple)
    pseudonymized_fields: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
