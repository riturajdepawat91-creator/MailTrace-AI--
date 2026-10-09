"""
Attachment Intelligence Engine - Core Data Models

Structured models used across attachment analysis modules.
Designed to keep findings, evidence, risk scores, and analysis
results consistent and API-ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """
    Represents one security finding generated during attachment analysis.
    """

    finding_id: str
    title: str
    description: str
    category: str
    severity: str
    confidence: float
    score: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    """
    Structured evidence attached to a finding or analysis result.
    """

    source: str
    field: str
    value: Any
    description: str = ""
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileHashes:
    """
    Cryptographic fingerprints for an attachment.
    """

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileIdentity:
    """
    Basic identity information about the analyzed attachment.
    """

    filename: str
    size_bytes: int
    extension: Optional[str] = None
    mime_type: Optional[str] = None
    detected_type: Optional[str] = None
    hashes: Optional[FileHashes] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class RiskAssessment:
    """
    Final risk calculation generated from all attachment findings.
    """

    score: float = 0.0
    severity: str = "UNKNOWN"
    confidence: float = 0.0
    verdict: str = "Not analyzed"
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttachmentAnalysisResult:
    """
    Complete result returned by the Attachment Intelligence Engine.
    """

    analysis_id: str
    engine: str
    engine_version: str
    analyzed_at: str

    file: FileIdentity

    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)

    risk: RiskAssessment = field(default_factory=RiskAssessment)

    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)

    def add_error(self, error: str) -> None:
        self.errors.append(str(error))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "analyzed_at": self.analyzed_at,
            "file": self.file.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": [evidence.to_dict() for evidence in self.evidence],
            "risk": self.risk.to_dict(),
            "metadata": self.metadata,
            "errors": self.errors,
        }


def utc_now_iso() -> str:
    """
    Return the current UTC timestamp in ISO-8601 format.
    """

    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "Finding",
    "Evidence",
    "FileHashes",
    "FileIdentity",
    "RiskAssessment",
    "AttachmentAnalysisResult",
    "utc_now_iso",
]
