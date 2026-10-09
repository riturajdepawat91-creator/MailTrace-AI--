from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


ANALYSIS_VERSION = "1.1.0"
MODULE_NAME = "email_thread_intelligence"
STATIC_ONLY = True


@dataclass(frozen=True)
class ThreadEvidence:
    evidence_id: str
    category: str
    severity: str
    confidence: float
    description: str
    details: dict[str, Any]


@dataclass(frozen=True)
class ThreadAnalysisResult:
    thread_identity: dict[str, Any]
    thread_depth: int
    participant_graph: dict[str, Any]
    continuity: dict[str, Any]
    quoted_context: dict[str, Any]
    anomalies: list[dict[str, Any]]
    thread_risk_score: float
    confidence: float
    evidence: list[ThreadEvidence]
    recommended_actions: list[str]
    analysis_version: str
    static_only: bool
    hijacking_assessment: dict[str, Any] = field(default_factory=dict)
    risk_breakdown: dict[str, Any] = field(default_factory=dict)
    analyst_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = [
            asdict(item) if isinstance(item, ThreadEvidence) else item
            for item in self.evidence
        ]
        return result
