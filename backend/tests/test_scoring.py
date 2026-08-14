from datetime import datetime, timezone, timedelta
import pytest
from app.services.scoring_service import calculate_ioc_severity

def test_high_confidence_threatfox():
    """Verify high confidence threat from threatfox yields HIGH or CRITICAL severity."""
    result = calculate_ioc_severity(confidence=90, source="threatfox", sightings_count=1)
    assert result["score"] >= 80
    assert result["severity"] in ["HIGH", "CRITICAL"]

def test_low_confidence_default_source():
    """Verify low confidence threat defaults to LOW severity."""
    result = calculate_ioc_severity(confidence=20, source="unknown_source", sightings_count=1)
    assert result["score"] < 35
    assert result["severity"] == "LOW"

def test_multiple_sightings_boost():
    """Verify multiple sightings increase the threat score."""
    single_sighting = calculate_ioc_severity(confidence=70, source="urlhaus", sightings_count=1)
    multiple_sightings = calculate_ioc_severity(confidence=70, source="urlhaus", sightings_count=5)
    assert multiple_sightings["score"] > single_sighting["score"]

def test_time_decay():
    """Verify indicators decay over time."""
    now = datetime.now(timezone.utc)
    old_date = now - timedelta(days=90)
    
    fresh = calculate_ioc_severity(confidence=80, source="feodo", sightings_count=1, first_seen=now)
    decayed = calculate_ioc_severity(confidence=80, source="feodo", sightings_count=1, first_seen=old_date)
    assert decayed["score"] < fresh["score"]

def test_score_limits():
    """Ensure score never exceeds 100 or drops below 0."""
    high_limit = calculate_ioc_severity(confidence=150, source="feodo", sightings_count=20)
    assert high_limit["score"] <= 100
    
    low_limit = calculate_ioc_severity(confidence=0, source="unknown", sightings_count=0)
    assert low_limit["score"] >= 0