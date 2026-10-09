from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class VisualFeatureProfile:
    aspect_ratio: float = 0.0
    grayscale_mean: float = 0.0
    grayscale_std: float = 0.0
    edge_density: float = 0.0
    dark_pixel_ratio: float = 0.0
    bright_pixel_ratio: float = 0.0

    connected_components: int = 0
    text_like_components: int = 0
    button_like_regions: int = 0
    card_like_regions: int = 0

    screenshot_like: bool = False
    dense_layout: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QRPayloadEvidence:
    index: int
    payload: str
    payload_type: str
    confidence: float
    points: list[list[float]] = field(default_factory=list)

    url_analysis: dict[str, Any] | None = None
    url_risk_score: float = 0.0
    url_severity: str | None = None
    url_verdict: str | None = None
    url_confidence: float = 0.0
    url_finding_ids: list[str] = field(default_factory=list)
    url_correlated: bool = False

    payload_truncated: bool = False
    correlation_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VisualAnalysisResult:
    module_name: str
    analysis_version: str
    static_only: bool

    success: bool
    filename: str | None

    image_format: str | None
    width: int | None
    height: int | None
    channels: int | None
    pixel_count: int

    qr_detected: bool
    qr_count: int
    qr_payloads: list[QRPayloadEvidence]

    visual_features: VisualFeatureProfile | None

    evidence: list[dict[str, Any]]
    recommended_actions: list[str]

    risk_score: float
    confidence: float
    verdict: str

    limits_applied: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    url_correlations: int = 0
    correlated_url_count: int = 0
    max_url_risk_score: float = 0.0
    highest_url_severity: str | None = None
    visual_url_correlation_score: float = 0.0

    correlation_failures: int = 0

    visual_signal_score: float = 0.0
    visual_signal_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
