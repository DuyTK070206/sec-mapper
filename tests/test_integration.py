from pathlib import Path

from src.scanner import DependencyScanner


def test_scan_package_json_direct():
    scanner = DependencyScanner()
    manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
    result = scanner.scan_file(manifest_path)

    assert result['direct_dependencies'] == 4
    assert any(f['package'] == 'lodash' for f in result['findings'])


def test_scan_package_with_lock_transitive():
    scanner = DependencyScanner()
    manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
    lock_path = Path(__file__).resolve().parent.parent / 'samples' / 'package-lock.json'
    result = scanner.scan_file(manifest_path, lock_path=lock_path)

    assert result['transitive_dependencies'] >= 1
    assert any(f['package'] == 'follow-redirects' for f in result['findings'])


def test_poc_generation_in_findings():
    scanner = DependencyScanner()
    manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
    result = scanner.scan_file(manifest_path)

    assert any('poc' in f and f['poc'] for f in result['findings'])


def test_sarif_report_format():
    scanner = DependencyScanner()
    manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
    result = scanner.scan_file(manifest_path)
    
    sarif = scanner.generate_sarif_report(result)
    assert '2.1.0' in sarif
    assert 'runs' in sarif
    assert 'results' in sarif


def test_json_report_includes_all_fields():
    scanner = DependencyScanner()
    manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
    result = scanner.scan_file(manifest_path)
    
    json_report = scanner.generate_json_report(result)
    assert 'metadata' in json_report
    assert 'summary' in json_report
    assert 'findings' in json_report
    assert 'remediation_plan' in json_report
