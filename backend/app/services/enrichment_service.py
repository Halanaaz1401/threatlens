import redis
import httpx
import json
from typing import Dict, Any

CACHE_EXPIRE_SECONDS = 3600

def get_redis_client():
    try:
        client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True, socket_connect_timeout=1)
        client.ping()
        return client
    except Exception:
        return None

async def get_ip_enrichment(ip_address: str) -> Dict[str, Any]:
    cache_key = f"enrichment:ip:{ip_address}"
    redis_client = get_redis_client()
    
    # 1. Check Redis Cache
    if redis_client:
        try:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                data = json.loads(cached_data)
                data["cached"] = True
                return data
        except Exception:
            pass

    # 2. Fetch Geo/ASN & IP Info from External API
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("status") == "success":
                    enrichment_result = {
                        "ip": ip_address,
                        "country": res_data.get("country"),
                        "country_code": res_data.get("countryCode"),
                        "city": res_data.get("city"),
                        "isp": res_data.get("isp"),
                        "org": res_data.get("org"),
                        "asn": res_data.get("as"),
                        "cached": False
                    }
                    
                    if redis_client:
                        try:
                            redis_client.setex(cache_key, CACHE_EXPIRE_SECONDS, json.dumps(enrichment_result))
                        except Exception:
                            pass

                    return enrichment_result
    except Exception as e:
        return {"ip": ip_address, "status": "failed", "error": str(e), "cached": False}

    return {"ip": ip_address, "status": "not_found", "cached": False}

async def get_domain_enrichment(domain: str) -> Dict[str, Any]:
    cache_key = f"enrichment:domain:{domain}"
    redis_client = get_redis_client()
    
    if redis_client:
        try:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                data = json.loads(cached_data)
                data["cached"] = True
                return data
        except Exception:
            pass

    enrichment_result = {
        "domain": domain,
        "type": "Domain Name",
        "status": "Enriched",
        "cached": False
    }

    if redis_client:
        try:
            redis_client.setex(cache_key, CACHE_EXPIRE_SECONDS, json.dumps(enrichment_result))
        except Exception:
            pass

    return enrichment_result