import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.indicator import Indicator, IndicatorStatus
from app.services.audit_service import log_action
from app.services.search_service import index_indicator
from app.core.redis import publish_ioc_event

logger = logging.getLogger("threatlens.expiration_worker")

def expire_stale_indicators(db: Session, batch_size: int = 100) -> Dict[str, Any]:
    """
    FR-08 Background Expiration Worker:
    Identifies indicators whose expiration time has passed and deterministically transitions
    them from 'active' to 'expired'.
    
    Guarantees:
    - Idempotent: once transitioned to 'expired', indicators are not repeatedly processed.
    - Safe to restart: queries state directly from the database with bounded batching.
    - Auditable: records audit entries for lifecycle transitions.
    - Redis Event: publishes IOC_EXPIRED event for real-time subscribers.
    - ES Sync: updates Elasticsearch projection.
    """
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    stale_indicators = (
        db.query(Indicator)
        .filter(
            Indicator.status == IndicatorStatus.ACTIVE.value,
            Indicator.expires_at.isnot(None),
            Indicator.expires_at <= now_utc,
        )
        .order_by(Indicator.expires_at.asc())
        .limit(batch_size)
        .all()
    )

    if not stale_indicators:
        return {
            "expired_count": 0,
            "processed_ids": [],
            "batch_size": batch_size,
            "timestamp": now_utc.isoformat(),
        }

    processed_ids: List[str] = []
    for indicator in stale_indicators:
        indicator.status = IndicatorStatus.EXPIRED.value
        indicator.updated_at = now_utc
        processed_ids.append(str(indicator.id))

        # Project to Elasticsearch
        try:
            index_indicator({
                "id": str(indicator.id),
                "value": indicator.value,
                "type": str(indicator.type.value if hasattr(indicator.type, "value") else indicator.type),
                "source": indicator.source,
                "severity": str(indicator.severity.value if hasattr(indicator.severity, "value") else indicator.severity),
                "status": "expired",
                "threat_score": indicator.threat_score,
                "confidence": indicator.confidence,
                "tags": indicator.tags or [],
                "expires_at": indicator.expires_at.isoformat() if indicator.expires_at else None,
            })
        except Exception as es_err:
            logger.debug(f"ES index skip on expiration for {indicator.id}: {es_err}")

        # Audit log
        try:
            log_action(
                db,
                action="IOC_EXPIRED",
                actor="system:ttl_worker",
                target_resource=f"indicator:{indicator.id}",
                details={
                    "indicator_id": str(indicator.id),
                    "value": indicator.value,
                    "expires_at": indicator.expires_at.isoformat() if indicator.expires_at else None,
                    "previous_status": "active",
                    "new_status": "expired",
                }
            )
        except Exception as audit_err:
            logger.error(f"Audit log failed on expiration for {indicator.id}: {audit_err}")

        # Redis Event
        try:
            publish_ioc_event("IOC_EXPIRED", {
                "indicator_id": str(indicator.id),
                "value": indicator.value,
                "type": str(indicator.type.value if hasattr(indicator.type, "value") else indicator.type),
                "status": "expired",
                "expired_at": now_utc.isoformat(),
            })
        except Exception as redis_err:
            logger.debug(f"Redis event failed on expiration for {indicator.id}: {redis_err}")

    db.commit()

    logger.info(f"TTL Expiration Worker transitioned {len(processed_ids)} indicators to 'expired'")
    return {
        "expired_count": len(processed_ids),
        "processed_ids": processed_ids,
        "batch_size": batch_size,
        "timestamp": now_utc.isoformat(),
    }
