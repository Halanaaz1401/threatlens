import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db, engine, Base
from app.models.indicator import Indicator, IndicatorSource
from app.services.ingestion import run_live_ingestion

Base.metadata.create_all(bind=engine)

router = APIRouter(prefix="/api/v1/indicators", tags=["Indicators"])

@router.get("/")
@router.get("")
def get_indicators(db: Session = Depends(get_db)):
    iocs = db.query(Indicator).order_by(Indicator.severity_score.desc()).limit(50).all()
    return {"status": "success", "count": len(iocs), "data": iocs}

@router.post("/sync-feeds")
async def sync_feeds(db: Session = Depends(get_db)):
    try:
        iocs = await run_live_ingestion()
        inserted_count = 0
        
        for item in iocs:
            existing = db.query(Indicator).filter(Indicator.value == item["value"]).first()
            if not existing:
                new_ioc = Indicator(
                    id=str(uuid.uuid4()),
                    value=item["value"],
                    type=item["type"],
                    severity_score=item.get("severity_score", 75),
                    confidence=item.get("confidence", 80),
                    tags=item.get("tags", "malware"),
                    mitre_technique=item.get("mitre_technique", "T1071"),
                    status="active"
                )
                db.add(new_ioc)
                db.commit()
                db.refresh(new_ioc)

                source = IndicatorSource(
                    id=str(uuid.uuid4()),
                    indicator_id=new_ioc.id,
                    source_name=item.get("source", "ThreatFeed"),
                    confidence=item.get("confidence", 80)
                )
                db.add(source)
                db.commit()
                inserted_count += 1

        return {"status": "success", "message": f"Successfully ingested {inserted_count} new IOCs"}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
