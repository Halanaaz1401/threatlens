from datetime import datetime

def calculate_severity_score(
    reputation_score: int = 0,
    detection_positives: int = 0,
    detection_total: int = 70,
    last_seen: datetime = None,
    internal_sightings: int = 0
) -> int:
    # External Reputation Weight (35%)
    rep_component = max(0, min(100, reputation_score)) * 0.35

    # Multi-Engine Detection Ratio Weight (35%)
    if detection_total > 0:
        ratio = min(1.0, detection_positives / detection_total)
        verdict_component = (ratio * 100) * 0.35
    else:
        verdict_component = 0.0

    # Recency Decay Weight (15%)
    if last_seen is None:
        last_seen = datetime.utcnow()
    
    age_days = (datetime.utcnow() - last_seen).total_seconds() / 86400.0
    if age_days <= 1:
        recency_score = 100
    elif age_days <= 7:
        recency_score = 80
    elif age_days <= 30:
        recency_score = 50
    else:
        recency_score = 20
    recency_component = recency_score * 0.15

    # Internal Org Sightings Weight (15%)
    if internal_sightings >= 5:
        sightings_score = 100
    elif internal_sightings >= 1:
        sightings_score = 60
    else:
        sightings_score = 0
    sightings_component = sightings_score * 0.15

    total = int(round(rep_component + verdict_component + recency_component + sightings_component))
    return max(0, min(100, total))
