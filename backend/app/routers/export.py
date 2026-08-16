import uuid
import io
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.indicator import Indicator

router = APIRouter(prefix="/api/v1/export", tags=["Export & STIX 2.1"])

def to_stix_pattern(ioc_type: str, value: str) -> str:
    """Formats canonical IOC into standard STIX 2.1 Pattern"""
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    elif ioc_type == "url":
        return f"[url:value = '{value}']"
    elif ioc_type == "hash_sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    elif ioc_type == "cve":
        return f"[vulnerability:name = '{value}']"
    return f"[custom-ioc:value = '{value}']"

@router.get("/stix")
def export_stix_bundle(db: Session = Depends(get_db)):
    """Exports all active indicators into a STIX 2.1 JSON Bundle"""
    iocs = db.query(Indicator).filter(Indicator.status == "active").all()
    stix_objects = []

    for ioc in iocs:
        created_time = ioc.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z") if ioc.created_at else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stix_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc.id}",
            "created": created_time,
            "modified": created_time,
            "name": f"ThreatLens IOC: {ioc.value}",
            "description": f"Enriched threat indicator with score {ioc.severity_score}/100 and MITRE {ioc.mitre_technique or 'N/A'}",
            "indicator_types": ["malicious-activity"],
            "pattern": to_stix_pattern(ioc.type, ioc.value),
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": created_time,
            "confidence": ioc.confidence or 80,
            "labels": [tag.strip() for tag in (ioc.tags or "threatlens").split(",") if tag.strip()],
            "custom_properties": {
                "x_threatlens_severity_score": ioc.severity_score,
                "x_threatlens_tlp": ioc.tlp or "amber"
            }
        }
        stix_objects.append(stix_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects
    }

    return bundle

@router.get("/csv")
def export_csv(db: Session = Depends(get_db)):
    """Exports all active indicators as downloadable CSV"""
    iocs = db.query(Indicator).filter(Indicator.status == "active").all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Value", "Type", "Severity_Score", "Confidence", "TLP", "MITRE_Technique", "Tags", "First_Seen"])

    for ioc in iocs:
        writer.writerow([
            ioc.id,
            ioc.value,
            ioc.type,
            ioc.severity_score,
            ioc.confidence,
            ioc.tlp,
            ioc.mitre_technique,
            ioc.tags,
            ioc.first_seen
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlens_indicators.csv"}
    )
