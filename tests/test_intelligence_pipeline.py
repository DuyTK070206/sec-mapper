from pathlib import Path

from src.intelligence import IntelligencePipeline, LocalJsonAdapter


def test_local_adapter_loads_advisories():
    db_path = Path(__file__).resolve().parent.parent / "src" / "vuln_db.json"
    adapter = LocalJsonAdapter(db_path)
    advisories = adapter.fetch("lodash", "npm", "4.17.20")

    assert advisories
    assert advisories[0].package == "lodash"
    assert advisories[0].ecosystem == "npm"


def test_intelligence_pipeline_cache_roundtrip(tmp_path):
    db_path = Path(__file__).resolve().parent.parent / "src" / "vuln_db.json"
    cache_file = tmp_path / "cache.json"

    pipeline = IntelligencePipeline(
        adapters=[LocalJsonAdapter(db_path)],
        cache_path=cache_file,
    )

    first = pipeline.fetch("lodash", "npm", "4.17.20")
    second = pipeline.fetch("lodash", "npm", "4.17.20")

    assert "local-db" in first
    assert "local-db" in second
    assert len(second["local-db"]) >= 1


def test_discrepancy_detection():
    db_path = Path(__file__).resolve().parent.parent / "src" / "vuln_db.json"
    pipeline = IntelligencePipeline(
        adapters=[LocalJsonAdapter(db_path)],
        cache_path=Path(__file__).resolve().parent.parent / "scan_cache" / "test-cache.json",
    )

    per_source = pipeline.fetch("lodash", "npm", "4.17.20")
    discrepancies = pipeline.find_discrepancies(per_source)
    assert isinstance(discrepancies, list)
