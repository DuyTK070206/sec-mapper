from pathlib import Path

from src.scanner import DependencyScanner


def test_findings_include_confidence_and_path():
    scanner = DependencyScanner()
    manifest = Path(__file__).resolve().parent.parent / "samples" / "package.json"
    result = scanner.scan_file(manifest)

    assert result["findings"]
    for finding in result["findings"]:
        assert "confidence" in finding
        assert "confidence_score" in finding
        assert "dependency_path" in finding
        assert isinstance(finding["dependency_path"], list)


def test_findings_are_deduplicated_by_package_and_vuln_id():
    scanner = DependencyScanner()
    manifest = Path(__file__).resolve().parent.parent / "samples" / "package.json"
    lock_path = Path(__file__).resolve().parent.parent / "samples" / "package-lock.json"
    result = scanner.scan_file(manifest, lock_path=lock_path)

    seen = set()
    for finding in result["findings"]:
        key = (finding.get("package"), finding.get("vulnerability_id", finding.get("cve")))
        assert key not in seen
        seen.add(key)
