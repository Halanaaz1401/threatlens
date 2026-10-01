from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# Sensitive key names to scrub from raw metadata
SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "key",
    "token",
    "secret",
    "authorization",
    "password",
    "x-apikey",
    "x-otx-api-key",
}

def sanitize_metadata(data: Any) -> Any:
    """Recursively scrub any sensitive credentials or API keys from raw metadata."""
    if isinstance(data, dict):
        clean_dict = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                clean_dict[k] = "[REDACTED]"
            else:
                clean_dict[k] = sanitize_metadata(v)
        return clean_dict
    elif isinstance(data, list):
        return [sanitize_metadata(item) for item in data]
    return data

class NormalizedEnrichmentResult(BaseModel):
    indicator_id: Optional[str] = None
    provider: str
    queried_value: str
    indicator_type: str
    verdict: str = "unknown"  # "clean", "suspicious", "malicious", "unknown"
    confidence: int = 0       # 0 - 100
    malicious_count: int = 0
    suspicious_count: int = 0
    reputation: Optional[int] = None
    categories: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    country: Optional[str] = None
    asn: Optional[str] = None
    network: Optional[str] = None
    external_references: List[str] = Field(default_factory=list)
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    success: bool = True
    error_message: Optional[str] = None

class BaseThreatIntelProvider(ABC):
    """Abstract interface for modular threat intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Canonical identifier for the provider (e.g. 'virustotal', 'abuseipdb')."""
        pass

    @property
    @abstractmethod
    def supported_ioc_types(self) -> List[str]:
        """List of supported IOC types ('ip', 'domain', 'url', 'hash_md5', 'hash_sha256', etc.)."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has necessary API keys/credentials configured."""
        pass

    @abstractmethod
    async def enrich(
        self,
        value: str,
        ioc_type: str,
        indicator_id: Optional[str] = None,
    ) -> NormalizedEnrichmentResult:
        """Query external threat intelligence and return normalized enrichment result."""
        pass

    def health_check(self) -> Dict[str, Any]:
        """Return provider configuration status and readiness."""
        return {
            "provider": self.provider_name,
            "configured": self.is_configured(),
            "supported_types": self.supported_ioc_types,
            "status": "ready" if self.is_configured() else "unconfigured",
        }
