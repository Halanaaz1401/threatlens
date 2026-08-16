import sys
from pathlib import Path

# Add backend directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.scoring_service import calculate_ioc_severity

def test_scoring_basic():
    score = calculate_ioc_severity({"reputation": 80, "confidence": 90})
    assert 0 <= score <= 100