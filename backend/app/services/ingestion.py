import httpx
import asyncio
from datetime import datetime
from app.services.scoring import calculate_severity_score

# 1. Feodo Tracker (Botnet C2 IPs)
async def fetch_feodo_c2_ips():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for entry in data[:15]:
                    score = calculate_severity_score(
                        reputation_score=95,
                        detection_positives=56,
                        detection_total=70,
                        last_seen=datetime.utcnow(),
                        internal_sightings=3
                    )
                    indicators.append({
                        "value": entry.get("ip_address"),
                        "type": "ip",
                        "severity_score": score,
                        "confidence": 90,
                        "source": "Feodo Tracker",
                        "mitre_technique": "T1071.001",
                        "tags": f"c2,botnet,{entry.get('malware', 'emotet')}",
                        "status": "active"
                    })
    except Exception as e:
        print(f"[!] Feodo Tracker Error: {e}")
    return indicators

# 2. URLhaus (Malicious & Phishing URLs)
async def fetch_urlhaus_urls():
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for _, urls in list(data.items())[:10]:
                    for item in urls:
                        score = calculate_severity_score(
                            reputation_score=85,
                            detection_positives=42,
                            detection_total=70,
                            last_seen=datetime.utcnow(),
                            internal_sightings=1
                        )
                        indicators.append({
                            "value": item.get("url"),
                            "type": "url",
                            "severity_score": score,
                            "confidence": 85,
                            "source": "URLhaus",
                            "mitre_technique": "T1566.002",
                            "tags": f"phishing,payload,{item.get('threat', 'malware')}",
                            "status": "active"
                        })
    except Exception as e:
        print(f"[!] URLhaus Error: {e}")
    return indicators

# 3. MalwareBazaar (SHA-256 Malware Hashes)
async def fetch_malware_bazaar():
    url = "https://mb-api.abuse.ch/api/v1/"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(url, data={"query": "get_recent", "selector": "time"})
            if res.status_code == 200:
                data = res.json()
                if data.get("query_status") == "ok":
                    for item in data.get("data", [])[:10]:
                        score = calculate_severity_score(
                            reputation_score=90,
                            detection_positives=61,
                            detection_total=70,
                            last_seen=datetime.utcnow(),
                            internal_sightings=2
                        )
                        indicators.append({
                            "value": item.get("sha256_hash"),
                            "type": "hash_sha256",
                            "severity_score": score,
                            "confidence": 95,
                            "source": "MalwareBazaar",
                            "mitre_technique": "T1027",
                            "tags": f"malware,hash,{item.get('file_type', 'exe')}",
                            "status": "active"
                        })
    except Exception as e:
        print(f"[!] MalwareBazaar Error: {e}")
    return indicators

# 4. ThreatFox (Fresh Compromise Indicators)
async def fetch_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(url, data='{"query": "get_iocs", "days": 1}')
            if res.status_code == 200:
                data = res.json()
                if data.get("query_status") == "ok":
                    for item in data.get("data", [])[:10]:
                        score = calculate_severity_score(
                            reputation_score=88,
                            detection_positives=48,
                            detection_total=70,
                            last_seen=datetime.utcnow(),
                            internal_sightings=1
                        )
                        ioc_type = "ip" if item.get("ioc_type") == "ip:port" else "domain"
                        indicators.append({
                            "value": item.get("ioc"),
                            "type": ioc_type,
                            "severity_score": score,
                            "confidence": int(item.get("confidence_level", 80)),
                            "source": "ThreatFox",
                            "mitre_technique": "T1071",
                            "tags": f"ioc,threatfox,{item.get('threat_type', 'c2')}",
                            "status": "active"
                        })
    except Exception as e:
        print(f"[!] ThreatFox Error: {e}")
    return indicators

# 5. AlienVault OTX Community Pulse Feed
async def fetch_alienvault_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/activity"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for pulse in data.get("results", [])[:5]:
                    pulse_name = pulse.get("name", "OTX Pulse")
                    for ind in pulse.get("indicators", [])[:3]:
                        val = ind.get("indicator")
                        ind_type = str(ind.get("type", "")).lower()
                        itype = "ip" if "ipv4" in ind_type else ("domain" if "domain" in ind_type else "url")
                        score = calculate_severity_score(
                            reputation_score=85,
                            detection_positives=45,
                            detection_total=70,
                            last_seen=datetime.utcnow(),
                            internal_sightings=1
                        )
                        if val:
                            indicators.append({
                                "value": val,
                                "type": itype,
                                "severity_score": score,
                                "confidence": 85,
                                "source": "AlienVault OTX",
                                "mitre_technique": "T1090.003",
                                "tags": f"otx,pulse,{pulse_name[:20].lower()}",
                                "status": "active"
                            })
    except Exception as e:
        print(f"[!] AlienVault OTX Error: {e}")
    return indicators

# 6. CISA KEV Exploited Vulnerabilities Catalog
async def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    indicators = []
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for vuln in data.get("vulnerabilities", [])[:10]:
                    cve_id = vuln.get("cveID")
                    score = calculate_severity_score(
                        reputation_score=100,
                        detection_positives=68,
                        detection_total=70,
                        last_seen=datetime.utcnow(),
                        internal_sightings=3
                    )
                    if cve_id:
                        indicators.append({
                            "value": cve_id,
                            "type": "cve",
                            "severity_score": score,
                            "confidence": 100,
                            "source": "CISA KEV",
                            "mitre_technique": "T1190",
                            "tags": f"cisa_kev,vulnerability,{str(vuln.get('vendorProject', 'exploit')).lower()}",
                            "status": "active"
                        })
    except Exception as e:
        print(f"[!] CISA KEV Error: {e}")
    return indicators

# Master Feed Ingestion Aggregator (6 Sources)
async def run_live_ingestion():
    feodo, urlhaus, mb, tf, otx, cisa = await asyncio.gather(
        fetch_feodo_c2_ips(),
        fetch_urlhaus_urls(),
        fetch_malware_bazaar(),
        fetch_threatfox(),
        fetch_alienvault_otx(),
        fetch_cisa_kev(),
        return_exceptions=True
    )
    results = []
    for item in [feodo, urlhaus, mb, tf, otx, cisa]:
        if isinstance(item, list):
            results.extend(item)
    return results
