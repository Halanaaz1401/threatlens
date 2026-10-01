import httpx
from typing import List, Optional
from datetime import datetime

from app.core.config import settings
from app.services.enrichment.base import (
    BaseThreatIntelProvider,
    NormalizedEnrichmentResult,
    sanitize_metadata,
)

class AlienVaultOTXProvider(BaseThreatIntelProvider):
    """Modular AlienVault OTX Threat Intelligence Provider."""

    OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    @property
    def provider_name(self) -> str:
        return "alienvault_otx"

    @property
    def supported_ioc_types(self) -> List[str]:
        return ["ip", "domain", "hash_md5", "hash_sha256"]

    def is_configured(self) -> bool:
        return bool(settings.OTX_API_KEY and settings.OTX_API_KEY.strip())

    def _get_target_endpoint(self, value: str, ioc_type: str) -> Optional[str]:
        t = ioc_type.lower()
        if t == "ip":
            return f"{self.OTX_BASE_URL}/IPv4/{value}/general"
        elif t == "domain":
            return f"{self.OTX_BASE_URL}/domain/{value}/general"
        elif t in ["hash_md5", "hash_sha256", "hash"]:
            return f"{self.OTX_BASE_URL}/file/{value}/general"
        return None

    async def enrich(
        self,
        value: str,
        ioc_type: str,
        indicator_id: Optional[str] = None,
    ) -> NormalizedEnrichmentResult:
        normalized_type = ioc_type.lower()

        # 1. Configuration check
        if not self.is_configured():
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message="AlienVault OTX provider not configured (missing OTX_API_KEY)",
            )

        # 2. Type compatibility check
        endpoint = self._get_target_endpoint(value, normalized_type)
        if not endpoint:
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message=f"Unsupported IOC type '{ioc_type}' for AlienVault OTX",
            )

        headers = {
            "X-OTX-API-KEY": settings.OTX_API_KEY.strip(),
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(endpoint, headers=headers)

                # Rate Limit (429)
                if response.status_code == 429:
                    return NormalizedEnrichmentResult(
                        indicator_id=indicator_id,
                        provider=self.provider_name,
                        queried_value=value,
                        indicator_type=normalized_type,
                        verdict="unknown",
                        confidence=0,
                        success=False,
                        error_message="AlienVault OTX rate limit exceeded (HTTP 429)",
                    )

                # Auth Error (401, 403)
                if response.status_code in (401, 403):
                    return NormalizedEnrichmentResult(
                        indicator_id=indicator_id,
                        provider=self.provider_name,
                        queried_value=value,
                        indicator_type=normalized_type,
                        verdict="unknown",
                        confidence=0,
                        success=False,
                        error_message=f"AlienVault OTX authentication rejected (HTTP {response.status_code})",
                    )

                # Not Found (404)
                if response.status_code == 404:
                    return NormalizedEnrichmentResult(
                        indicator_id=indicator_id,
                        provider=self.provider_name,
                        queried_value=value,
                        indicator_type=normalized_type,
                        verdict="clean",
                        confidence=30,
                        malicious_count=0,
                        suspicious_count=0,
                        success=True,
                        external_references=[f"https://otx.alienvault.com/indicator/{normalized_type}/{value}"],
                        raw_metadata={"status": "not_found", "code": 404},
                    )

                if response.status_code != 200:
                    return NormalizedEnrichmentResult(
                        indicator_id=indicator_id,
                        provider=self.provider_name,
                        queried_value=value,
                        indicator_type=normalized_type,
                        verdict="unknown",
                        confidence=0,
                        success=False,
                        error_message=f"AlienVault OTX lookup error (HTTP {response.status_code})",
                    )

                body = response.json()
                pulse_info = body.get("pulse_info", {})
                pulse_count = int(pulse_info.get("count", 0))
                pulses = pulse_info.get("pulses", [])

                # Collect tags, malware families, threat actors from pulses
                tags = set()
                malware_families = set()
                threat_actors = set()
                for p in pulses[:10]:
                    for tag in p.get("tags", []):
                        if isinstance(tag, str):
                            tags.add(tag)
                    adversary = p.get("adversary")
                    if adversary and isinstance(adversary, str):
                        threat_actors.add(adversary)
                    for fam in p.get("malware_families", []):
                        if isinstance(fam, dict) and fam.get("display_name"):
                            malware_families.add(fam["display_name"])
                        elif isinstance(fam, str):
                            malware_families.add(fam)

                # Verdict
                if pulse_count >= 2:
                    verdict = "malicious"
                    confidence = min(100, max(60, pulse_count * 20))
                elif pulse_count == 1:
                    verdict = "suspicious"
                    confidence = 50
                else:
                    verdict = "clean"
                    confidence = 35

                country = body.get("country_code")
                asn = str(body.get("asn")) if body.get("asn") else None

                sanitized_raw = sanitize_metadata({
                    "pulse_count": pulse_count,
                    "sections_available": body.get("sections_available", []),
                    "country_name": body.get("country_name"),
                    "city": body.get("city"),
                })

                return NormalizedEnrichmentResult(
                    indicator_id=indicator_id,
                    provider=self.provider_name,
                    queried_value=value,
                    indicator_type=normalized_type,
                    verdict=verdict,
                    confidence=confidence,
                    malicious_count=pulse_count if verdict == "malicious" else 0,
                    suspicious_count=pulse_count if verdict == "suspicious" else 0,
                    reputation=max(0, 100 - (pulse_count * 20)),
                    categories=["threat_pulse"] if pulse_count > 0 else [],
                    tags=list(tags)[:15],
                    malware_families=list(malware_families)[:5],
                    threat_actors=list(threat_actors)[:5],
                    country=country,
                    asn=asn,
                    network=None,
                    external_references=[f"https://otx.alienvault.com/indicator/{normalized_type}/{value}"],
                    raw_metadata=sanitized_raw,
                    success=True,
                )

        except httpx.TimeoutException:
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message="AlienVault OTX request timed out",
            )
        except Exception as e:
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message=f"AlienVault OTX error: {str(e)}",
            )
