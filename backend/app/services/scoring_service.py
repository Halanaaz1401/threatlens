from datetime import datetime, timezone
from typing import Dict, Any

# Source reliability weights (0.0 to 1.0)
SOURCE_WEIGHTS = {
    "urlhaus": 0.85,
    "threatfox": 0.90,
    "feodo": 0.95,
    "manual": 1.0,
    "default": 0.70
}

def calculate_ioc_severity(
    confidence: int,
    source: str,
    sightings_count: int = 1,
    first_seen: datetime = None
) -> Dict[str, Any]:
    """
    Calculate dynamic IOC Threat Score (0-100) and Severity Level.
    
    Formula Factors:
    1. Base Confidence (0-100)
    2. Source Reliability Multiplier (0.7 - 1.0)
    3. Sighting Multiplier (+5 per additional sighting, max +20)
    4. Time Decay Factor (-5 score per 30 days of age)
    
    Returns:
        Dict with 'score' (0-100) and 'severity' ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
    """
    # 1. Base Score calculation
    source_weight = SOURCE_WEIGHTS.get(source.lower(), SOURCE_WEIGHTS["default"])
    base_score = float(confidence) * source_weight

    # 2. Sighting Boost (More appearances = higher threat)
    sighting_boost = min((sightings_count - 1) * 5, 20)
    score = base_score + sighting_boost

    # 3. Time Decay (Older threats lose severity)
    if first_seen:
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_old = (now - first_seen).days
        decay = (days_old // 30) * 5
        score = max(score - decay, 0)

    # 4. Cap score between 0 and 100
    final_score = int(min(max(score, 0), 100))

    # 5. Map to Severity Level
    if final_score >= 85:
        severity = "CRITICAL"
    elif final_score >= 65:
        severity = "HIGH"
    elif final_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": final_score,
        "severity": severity
    }