"""Shared feed synchronization path for analyst-triggered and scheduled updates."""

from __future__ import annotations

from database.database import (
    get_threat_intelligence_source_status,
    record_threat_intelligence_sync,
    save_threat_intelligence,
)
from services.threat_intelligence.engine import ThreatIntelligenceEngine


def sync_threat_intelligence_feeds(
    *,
    days: int = 1,
    synced_by: str | None = None,
) -> dict:
    """Fetch configured providers, persist indicators, and append source-health receipts."""
    bounded_days = max(1, min(7, int(days)))
    result = ThreatIntelligenceEngine.sync(days=bounded_days)
    indicators = result.get("indicators", [])
    providers = result.get("providers", {})
    inserted_by_provider: dict[str, int] = {}
    for provider in providers:
        provider_ok = bool(providers.get(provider, {}).get("success"))
        provider_indicators = [
            item for item in indicators
            if provider_ok
            and isinstance(item, dict)
            and str(item.get("source", "")).lower() == str(provider).lower()
            and isinstance(item.get("ioc"), str)
            and item.get("ioc").strip()
            and isinstance(item.get("ioc_type"), str)
            and item.get("ioc_type").strip()
        ]
        inserted_by_provider[provider] = save_threat_intelligence(provider_indicators)

    sync_id = record_threat_intelligence_sync(
        providers,
        inserted_by_provider,
        synced_by=synced_by,
    )
    return {
        "success": bool(result.get("success", False)),
        "providers": providers,
        "fetched": int(result.get("count", 0) or 0),
        "saved": sum(inserted_by_provider.values()),
        "sync_id": sync_id,
        "feed_freshness": get_threat_intelligence_source_status(),
    }


def configured_provider_count() -> int:
    return sum(
        bool(provider.get("configured"))
        for provider in ThreatIntelligenceEngine.provider_status().values()
    )
