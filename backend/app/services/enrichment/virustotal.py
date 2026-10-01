import base64
import httpx
from typing import List, Optional
from datetime import datetime

from app.core.config import settings
from app.services.enrichment.base import (
    BaseThreatIntelProvider,
    NormalizedEnrichmentResult,
    sanitize_metadata,
)

class VirusTotalProvider(BaseThreatIntelProvider):
    """Modular VirusTotal v3 Threat Intelligence Provider."""

    VT_BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def provider_name(self) -> str:
        return "virustotal"

    @property
    def supported_ioc_types(self) -> List[str]:
        return ["ip", "domain", "url", "hash_md5", "hash_sha256"]

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())

    def _get_target_endpoint(self, value: str, ioc_type: str) -> Optional[str]:
        t = ioc_type.lower()
        if t == "ip":
            return f"{self.VT_BASE_URL}/ip_addresses/{value}"
        elif t == "domain":
            return f"{self.VT_BASE_URL}/domains/{value}"
        elif t == "url":
            # VT v3 requires base64url encoding without padding for URLs
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"{self.VT_BASE_URL}/urls/{url_id}"
        elif t in ["hash_md5", "hash_sha256", "hash"]:
            return f"{self.VT_BASE_URL}/files/{value}"
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
                error_message="VirusTotal provider not configured (missing VIRUSTOTAL_API_KEY)",
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
                error_message=f"Unsupported IOC type '{ioc_type}' for VirusTotal",
            )

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY.strip(),
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
                        error_message="VirusTotal rate limit exceeded (HTTP 429)",
                    )

                # Authentication Error (401, 403)
                if response.status_code in (401, 403):
                    return NormalizedEnrichmentResult(
                        indicator_id=indicator_id,
                        provider=self.provider_name,
                        queried_value=value,
                        indicator_type=normalized_type,
                        verdict="unknown",
                        confidence=0,
                        success=False,
                        error_message=f"VirusTotal authentication rejected (HTTP {response.status_code})",
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
                        external_references=[f"https://www.virustotal.com/gui/search/{value}"],
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
                        error_message=f"VirusTotal lookup error (HTTP {response.status_code})",
                    )

                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total_engines = malicious + suspicious + harmless + undetected

                # Verdict
                if malicious >= 3:
                    verdict = "malicious"
                elif malicious >= 1 or suspicious >= 2:
                    verdict = "suspicious"
                elif total_engines > 0 and (harmless > 0 or undetected > 0):
                    verdict = "clean"
                else:
                    verdict = "unknown"

                # Confidence (0 - 100)
                if total_engines > 0:
                    threat_ratio = (malicious + (suspicious * 0.5)) / total_engines
                    confidence = min(100, max(20, int(threat_ratio * 100)))
                    if malicious >= 5:
                        confidence = max(confidence, 90)
                else:
                    confidence = 20

                # Threat categories / labels
                categories = []
                malware_families = []
                pop_threat = attributes.get("popular_threat_classification", {})
                if pop_threat.get("suggested_threat_label"):
                    malware_families.append(pop_threat["suggested_threat_label"])
                for cat in pop_threat.get("popular_threat_category", []):
                    if isinstance(cat, dict) and cat.get("value"):
                        categories.append(cat["value"])

                tags = attributes.get("tags", [])
                reputation = attributes.get("reputation", 0)
                country = attributes.get("country")
                asn = str(attributes.get("asn")) if attributes.get("asn") else attributes.get("as_owner")
                network = attributes.get("network")

                sanitized_raw = sanitize_metadata({
                    "last_analysis_stats": stats,
                    "reputation": reputation,
                    "tags": tags,
                    "categories": categories,
                    "network": network,
                    "country": country,
                })

                return NormalizedEnrichmentResult(
                    indicator_id=indicator_id,
                    provider=self.provider_name,
                    queried_value=value,
                    indicator_type=normalized_type,
                    verdict=verdict,
                    confidence=confidence,
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    reputation=reputation,
                    categories=categories,
                    tags=tags,
                    malware_families=malware_families,
                    threat_actors=[],
                    country=country,
                    asn=asn,
                    network=network,
                    external_references=[f"https://www.virustotal.com/gui/search/{value}"],
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
                error_message="VirusTotal request timed out",
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
                error_message=f"VirusTotal error: {str(e)}",
            )
