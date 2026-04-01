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
