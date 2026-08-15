from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
import json
import csv
import io
from app.db.session import get_db
from app.models.indicator import Indicator

router = APIRouter()

@router.get("/stix")
def export_stix_bundle(db: Session = Depends(get_db)):
    indicators = db.query(Indicator).limit(100).all()
    
    stix_objects = []
    for ind in indicators:
        pattern_val = f"[{ind.type.lower()}:value = '{ind.value}']"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind.id}",
            "created": ind.created_at.isoformat() if hasattr(ind, 'created_at') and ind.created_at else "2026-08-15T00:00:00Z",
            "modified": ind.updated_at.isoformat() if hasattr(ind, 'updated_at') and ind.updated_at else "2026-08-15T00:00:00Z",
            "pattern": pattern_val,
            "pattern_type": "stix",
            "valid_from": ind.created_at.isoformat() if hasattr(ind, 'created_at') and ind.created_at else "2026-08-15T00:00:00Z",
            "confidence": getattr(ind, 'confidence', 80),
            "labels": [getattr(ind, 'category', 'malicious-activity') or "malicious-activity"],
            "custom_properties": {
                "x_threatlens_severity": getattr(ind, 'severity_score', 75),
                "x_threatlens_tlp": getattr(ind, 'tlp', 'AMBER')
            }
        })

    bundle = {
        "type": "bundle",
        "id": "bundle--threatlens-export-2026",
        "objects": stix_objects
    }
    
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=threatlens_stix_bundle.json"}
    )

@router.get("/csv")
def export_csv(db: Session = Depends(get_db)):
    indicators = db.query(Indicator).limit(500).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Type", "Value", "Severity Score", "Confidence", "TLP", "Category"])
    
    for ind in indicators:
        writer.writerow([
            ind.id,
            ind.type,
            ind.value,
            getattr(ind, 'severity_score', 0),
            getattr(ind, 'confidence', 0),
            getattr(ind, 'tlp', 'AMBER'),
            getattr(ind, 'category', 'Unknown') or "Unknown"
        ])
    
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlens_iocs.csv"}
    )