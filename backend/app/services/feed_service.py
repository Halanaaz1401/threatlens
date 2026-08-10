import httpx
from sqlalchemy.orm import Session
from app.models.indicator import Indicator, IndicatorType, IndicatorStatus

async def fetch_urlhaus_recent_urls(db: Session):
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                urls_data = data.get("urls", [])[:20]
                
                count = 0
                for item in urls_data:
                    val = item.get("url")
                    if not val:
                        continue
                    
                    existing = db.query(Indicator).filter(Indicator.value == val).first()
                    if not existing:
                        indicator = Indicator(
                            value=val,
                            type=IndicatorType.URL,
                            status=IndicatorStatus.ACTIVE,
                            severity="high" if item.get("url_status") == "online" else "medium",
                            threat_actor="Unknown",
                            tags=["urlhaus", "malware"]
                        )
                        db.add(indicator)
                        count += 1
                
                db.commit()
                return {"status": "success", "fetched": len(urls_data), "added": count}
        except Exception as e:
            db.rollback()
            return {"status": "error", "message": str(e)}