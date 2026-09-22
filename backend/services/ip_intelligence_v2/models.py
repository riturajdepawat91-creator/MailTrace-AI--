from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ProviderResult:
    provider: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class Evidence:
    source: str
    category: str
    field: str
    value: Any
    confidence: float = 0.0
    description: str = ""


@dataclass
class IPProfile:
    ip: str
    valid: bool = False
    version: Optional[int] = None
    type: str = "unknown"

    hostname: Optional[str] = None

    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    continent: Optional[str] = None

    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None

    is_private: bool = False
    is_loopback: bool = False
    is_reserved: bool = False
    is_documentation: bool = False

    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_hosting: Optional[bool] = None

    reputation_score: Optional[float] = None

    risk: str = "UNKNOWN"
    risk_score: float = 0
    confidence: float = 0.0

    # ==========================================
    # ADVANCED RISK ENGINE
    # ==========================================

    signal_breakdown: dict[str, Any] = field(
        default_factory=dict
    )

    risk_engine: str = "v4"

    # ==========================================
    # EXPLAINABILITY
    # ==========================================

    notes: list[str] = field(
        default_factory=list
    )

    evidence: list[dict[str, Any]] = field(
        default_factory=list
    )

    provider_status: list[dict[str, Any]] = field(
        default_factory=list
    )

    # ==========================================
    # SERIALIZATION
    # ==========================================

    def to_dict(self) -> dict[str, Any]:

        return {
            "ip": self.ip,
            "valid": self.valid,
            "version": self.version,
            "type": self.type,

            "hostname": self.hostname,

            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "postal": self.postal,

            "latitude": self.latitude,
            "longitude": self.longitude,

            "timezone": self.timezone,
            "continent": self.continent,

            "asn": self.asn,
            "isp": self.isp,
            "organization": self.organization,

            "is_private": self.is_private,
            "is_loopback": self.is_loopback,
            "is_reserved": self.is_reserved,
            "is_documentation": self.is_documentation,

            "is_proxy": self.is_proxy,
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
            "is_hosting": self.is_hosting,

            "reputation_score": self.reputation_score,

            "risk": self.risk,
            "risk_score": self.risk_score,
            "confidence": self.confidence,

            "signal_breakdown": self.signal_breakdown,
            "risk_engine": self.risk_engine,

            "notes": self.notes,
            "evidence": self.evidence,
            "provider_status": self.provider_status
        }
