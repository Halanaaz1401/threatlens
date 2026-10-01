from typing import List, Optional, Dict
from app.services.enrichment.base import (
    BaseThreatIntelProvider,
    NormalizedEnrichmentResult,
    sanitize_metadata,
)
from app.services.enrichment.virustotal import VirusTotalProvider
from app.services.enrichment.abuseipdb import AbuseIPDBProvider
from app.services.enrichment.otx import AlienVaultOTXProvider

_REGISTERED_PROVIDERS: Dict[str, BaseThreatIntelProvider] = {
    "virustotal": VirusTotalProvider(),
    "abuseipdb": AbuseIPDBProvider(),
    "alienvault_otx": AlienVaultOTXProvider(),
}

def get_available_providers() -> List[BaseThreatIntelProvider]:
    """Return all registered threat intelligence providers."""
    return list(_REGISTERED_PROVIDERS.values())

def get_provider_by_name(name: str) -> Optional[BaseThreatIntelProvider]:
    """Retrieve a provider instance by its canonical name."""
    return _REGISTERED_PROVIDERS.get(name.lower())

__all__ = [
    "BaseThreatIntelProvider",
    "NormalizedEnrichmentResult",
    "sanitize_metadata",
    "VirusTotalProvider",
    "AbuseIPDBProvider",
    "AlienVaultOTXProvider",
    "get_available_providers",
    "get_provider_by_name",
]
