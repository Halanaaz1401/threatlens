import sys
from pathlib import Path

# Add backend directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.search_service import search_indicators_es


def test_search_indicators_es_returns_fallback_when_unavailable(monkeypatch):
    """Verify search gracefully falls back to empty structure when Elasticsearch is unreachable."""
    monkeypatch.setattr("app.services.search_service.get_es_client", lambda: None)
    result = search_indicators_es(query_str="malware")
    assert result["source"] == "elasticsearch_unavailable"
    assert result["hits"] == []
    assert result["total"] == 0
