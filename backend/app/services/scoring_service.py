from datetime import datetime, timezone
from typing import Dict, Any, Union

# Source reliability weights (0.0 to 1.0)
SOURCE_WEIGHTS = {
    "urlhaus": 0.85,
    "threatfox": 0.90,
    "feodo": 0.95,
    "feodo_tracker": 0.95,
    "malwarebazaar": 0.90,
    "manual": 1.0,
    "default": 0.70
}

class ScoringResult(dict):
    """
    Subclass of dict holding 'score' and 'severity', while enabling
    direct integer comparison (e.g., 0 <= score <= 100) for backward compatibility.
    """
    @property
    def score(self) -> int:
        return self["score"]

    @property
    def severity(self) -> str:
        return self["severity"]

    def __int__(self) -> int:
        return self["score"]

    def __ge__(self, other):
        if isinstance(other, (int, float)):
            return self["score"] >= other
        return super().__ge__(other)

    def __le__(self, other):
        if isinstance(other, (int, float)):
            return self["score"] <= other
        return super().__le__(other)

    def __gt__(self, other):
        if isinstance(other, (int, float)):
            return self["score"] > other
        return super().__gt__(other)

    def __lt__(self, other):
        if isinstance(other, (int, float)):
            return self["score"] < other
        return super().__lt__(other)

    def __eq__(self, other):
        if isinstance(other, (int, float)):
            return self["score"] == other
        return super().__eq__(other)

def calculate_ioc_severity(
    confidence: Union[int, Dict[str, Any]] = 80,
    source: str = "manual",
    sightings_count: int = 1,
    first_seen: datetime = None
) -> ScoringResult:
    """
    Calculate dynamic IOC Threat Score (0-100) and Severity Level.
    Accepts either separate parameters or a dict containing reputation/confidence/source.
    
    Formula Factors:
    1. Base Confidence (0-100)
    2. Source Reliability Multiplier (0.7 - 1.0)
    3. Sighting Multiplier (+5 per additional sighting, max +20)
    4. Time Decay Factor (-5 score per 30 days of age)
    
    Returns:
        ScoringResult (dict) with 'score' (0-100) and 'severity' ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
    """
    if isinstance(confidence, dict):
        d = confidence
        conf_val = d.get("confidence", d.get("reputation", 80))
        source_val = d.get("source", "manual")
        sightings_val = d.get("sightings_count", d.get("internal_sightings", 1))
        seen_val = d.get("first_seen", d.get("last_seen", None))
    else:
        conf_val = confidence
        source_val = source
        sightings_val = sightings_count
        seen_val = first_seen

    # 1. Base Score calculation
    source_weight = SOURCE_WEIGHTS.get(str(source_val).lower(), SOURCE_WEIGHTS["default"])
    base_score = float(conf_val) * source_weight

    # 2. Sighting Boost (More appearances = higher threat)
    sighting_boost = min(max(sightings_val - 1, 0) * 5, 20)
    score = base_score + sighting_boost

    # 3. Time Decay (Older threats lose severity)
    if seen_val:
        if seen_val.tzinfo is None:
            seen_val = seen_val.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_old = (now - seen_val).days
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

    return ScoringResult({
        "score": final_score,
        "severity": severity
    })