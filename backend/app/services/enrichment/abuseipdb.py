import httpx
from typing import List, Optional
from datetime import datetime

from app.core.config import settings
from app.services.enrichment.base import (
    BaseThreatIntelProvider,
    NormalizedEnrichmentResult,
    sanitize_metadata,
)

class AbuseIPDBProvider(BaseThreatIntelProvider):
    """Modular AbuseIPDB Threat Intelligence Provider."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    @property
    def supported_ioc_types(self) -> List[str]:
        return ["ip"]

    def is_configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY and settings.ABUSEIPDB_API_KEY.strip())

    async def enrich(
        self,
        value: str,
        ioc_type: str,
        indicator_id: Optional[str] = None,
    ) -> NormalizedEnrichmentResult:
        normalized_type = ioc_type.lower()

        # 1. Type compatibility: Only IP is supported
        if normalized_type != "ip":
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message=f"AbuseIPDB only supports IP indicators (received '{ioc_type}')",
            )

        # 2. Configuration check
        if not self.is_configured():
            return NormalizedEnrichmentResult(
                indicator_id=indicator_id,
                provider=self.provider_name,
                queried_value=value,
                indicator_type=normalized_type,
                verdict="unknown",
                confidence=0,
                success=False,
                error_message="AbuseIPDB provider not configured (missing ABUSEIPDB_API_KEY)",
            )

        headers = {
            "Key": settings.ABUSEIPDB_API_KEY.strip(),
            "Accept": "application/json",
        }
        params = {
            "ipAddress": value,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(self.API_URL, headers=headers, params=params)

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
                        error_message="AbuseIPDB rate limit exceeded (HTTP 429)",
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
                        error_message=f"AbuseIPDB authentication rejected (HTTP {response.status_code})",
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
                        error_message=f"AbuseIPDB lookup error (HTTP {response.status_code})",
                    )

                body = response.json()
                data = body.get("data", {})

                abuse_score = int(data.get("abuseConfidenceScore", 0))
                total_reports = int(data.get("totalReports", 0))
                is_whitelisted = bool(data.get("isWhitelisted", False))

                # Verdict
                if is_whitelisted:
                    verdict = "clean"
                    confidence = 90
                elif abuse_score >= 50:
                    verdict = "malicious"
                    confidence = abuse_score
                elif abuse_score >= 20 or total_reports >= 3:
                    verdict = "suspicious"
                    confidence = max(40, abuse_score)
                else:
                    verdict = "clean"
                    confidence = max(30, 100 - abuse_score)

                country = data.get("countryCode")
                isp = data.get("isp")
                domain = data.get("domain")
                usage_type = data.get("usageType")

                tags = []
                if is_whitelisted:
                    tags.append("whitelisted")
                if usage_type:
                    tags.append(usage_type)

                sanitized_raw = sanitize_metadata({
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": total_reports,
                    "numDistinctUsers": data.get("numDistinctUsers", 0),
                    "isWhitelisted": is_whitelisted,
                    "usageType": usage_type,
                    "isp": isp,
                    "domain": domain,
                })

                return NormalizedEnrichmentResult(
                    indicator_id=indicator_id,
                    provider=self.provider_name,
                    queried_value=value,
                    indicator_type=normalized_type,
                    verdict=verdict,
                    confidence=confidence,
                    malicious_count=total_reports if verdict == "malicious" else 0,
                    suspicious_count=total_reports if verdict == "suspicious" else 0,
                    reputation=100 - abuse_score,
                    categories=[usage_type] if usage_type else [],
                    tags=tags,
                    malware_families=[],
                    threat_actors=[],
                    country=country,
                    asn=isp,
                    network=domain,
                    external_references=[f"https://www.abuseipdb.com/check/{value}"],
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
                error_message="AbuseIPDB request timed out",
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
                error_message=f"AbuseIPDB error: {str(e)}",
            )
