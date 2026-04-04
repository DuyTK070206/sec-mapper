#!/usr/bin/env python3
"""Quick test to see all vulnerabilities found"""

from pathlib import Path
from src.scanner import DependencyScanner

def test_scan():
    scanner = DependencyScanner()
    result = scanner.scan_file(Path('samples/package.json'), lock_path=Path('samples/package-lock.json'))
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Total findings: {len(result['findings'])}")
    print()
    
    for finding in result['findings']:
        print(f"📦 Package: {finding['package']} v{finding['version']}")
        print(f"   CVE: {finding['cve']}")
        print(f"   Severity: {finding['severity'].upper()}")
        print(f"   Description: {finding['description'][:60]}...")
        print(f"   Fixed: {finding['fixed_version']}")
        print()
    
    print("="*60)
    print(f"Summary by severity:")
    for k in ['critical', 'high', 'medium', 'low']:
        count = len([f for f in result['findings'] if f['severity'] == k])
        if count > 0:
            print(f"  {k.upper()}: {count}")

if __name__ == '__main__':
    test_scan()
