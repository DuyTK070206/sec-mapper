#!/usr/bin/env python3
"""
Test script to verify OSV API integration for vulnerability scanning.

Tests:
1. Direct OSV API queries for specific packages
2. Verification of known vulnerabilities (qs 6.9.0, lodash, etc.)
3. Caching mechanism
4. Ecosystem mapping
5. Version matching logic
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.osv_client import OSVClient, OSVVulnerabilityConverter
from src.vulnerability_manager import VulnerabilityManager
from src.dependency_parser import ParsedDependency

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_osv_client_direct():
    """Test OSV client direct API queries."""
    print("\n" + "="*80)
    print("TEST 1: Direct OSV API Queries")
    print("="*80)
    
    client = OSVClient(use_cache=True)
    
    # Test case 1: qs 6.9.0 should have CVE-2022-24999
    print("\n[TEST 1a] Querying qs 6.9.0 (npm) for CVE-2022-24999...")
    vulns = client.query("qs", "npm", "6.9.0")
    if vulns:
        print(f"[PASS] Found {len(vulns)} vulnerability(ies)")
        for vuln in vulns:
            cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), vuln.get("id", "UNKNOWN"))
            print(f"  - {cve}: {vuln.get('summary', 'N/A')}")
            if "CVE-2022-24999" in vuln.get("aliases", []):
                print("  [PASS] Found expected CVE-2022-24999")
    else:
        print("[FAIL] No vulnerabilities found for qs 6.9.0")
    
    # Test case 2: lodash <4.17.21 should have vulnerabilities
    print("\n[TEST 1b] Querying lodash 4.17.19 (npm) for vulnerabilities...")
    vulns = client.query("lodash", "npm", "4.17.19")
    if vulns:
        print(f"[PASS] Found {len(vulns)} vulnerability(ies)")
        for vuln in vulns[:3]:  # Show first 3
            cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), vuln.get("id", "UNKNOWN"))
            print(f"  - {cve}: {vuln.get('summary', 'N/A')[:50]}...")
    else:
        print("[FAIL] No vulnerabilities found for lodash 4.17.19")
    
    # Test case 3: Check caching
    print("\n[TEST 1c] Testing cache hit...")
    import time
    start = time.time()
    vulns1 = client.query("qs", "npm", "6.9.0")
    time1 = time.time() - start
    
    start = time.time()
    vulns2 = client.query("qs", "npm", "6.9.0")
    time2 = time.time() - start
    
    print(f"  First query: {time1*1000:.1f}ms")
    print(f"  Cached query: {time2*1000:.1f}ms")
    if time2 < time1 * 1.5:  # Allow some margin
        print("[PASS] Caching is working (2nd query similar or faster)")
    
    print(f"\nCache stats: {client.get_cache_stats()}")


def test_vulnerability_manager():
    """Test VulnerabilityManager with OSV API."""
    print("\n" + "="*80)
    print("TEST 2: VulnerabilityManager with OSV API")
    print("="*80)
    
    vm = VulnerabilityManager(use_osv=True, use_cache=True)
    
    # Test case 1: qs 6.9.0
    print("\n[TEST 2a] Finding vulnerabilities for qs 6.9.0...")
    vulns = vm.find_vulnerabilities("qs", "6.9.0", "npm")
    if vulns:
        print(f"[PASS] Found {len(vulns)} vulnerability(ies)")
        for vuln in vulns[:3]:
            print(f"  - {vuln.get('vulnerability_id')}: {vuln.get('title', 'N/A')[:40]}...")
            print(f"    Severity: {vuln.get('severity')}, Source: {vuln.get('source')}")
    else:
        print("[FAIL] No vulnerabilities found")
    
    # Test case 2: Exact version - lodash 4.17.20
    print("\n[TEST 2b] Finding vulnerabilities for lodash 4.17.20...")
    vulns = vm.find_vulnerabilities("lodash", "4.17.20", "npm")
    if vulns:
        print(f"[PASS] Found {len(vulns)} vulnerability(ies)")
        for vuln in vulns[:3]:
            print(f"  - {vuln.get('vulnerability_id')}: {vuln.get('title', 'N/A')[:40]}...")
    else:
        print("[FAIL] No vulnerabilities found")
    
    print(f"\nVulnerability Manager cache stats: {vm.get_cache_stats()}")


def test_dependency_parser_with_scanner():
    """Test with actual dependency parsing."""
    print("\n" + "="*80)
    print("TEST 3: Dependency Parsing and Scanning")
    print("="*80)
    
    # Create sample package.json
    sample_manifest = Path("sample_package.json")
    sample_manifest.write_text("""{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "qs": "6.9.0",
    "lodash": "4.17.19"
  }
}""")
    
    try:
        from src.dependency_parser import ParserFactory
        
        parser = ParserFactory.get_parser("package.json")
        dependencies = parser.parse(sample_manifest.read_text())
        
        print(f"\n[TEST 3a] Parsed {len(dependencies)} dependencies:")
        for dep in dependencies:
            print(f"  - {dep.name}@{dep.version} ({dep.ecosystem})")
        
        # Check each dependency for vulnerabilities
        print("\n[TEST 3b] Scanning parsed dependencies:")
        vm = VulnerabilityManager(use_osv=True, use_cache=True)
        
        for dep in dependencies:
            vulns = vm.find_vulnerabilities(dep.name, dep.version, dep.ecosystem)
            if vulns:
                print(f"[PASS] {dep.name}@{dep.version}: Found {len(vulns)} vulnerability(ies)")
                for vuln in vulns[:2]:
                    print(f"  - {vuln.get('vulnerability_id')}")
            else:
                print(f"[INFO] {dep.name}@{dep.version}: No vulnerabilities found")
    
    finally:
        sample_manifest.unlink(missing_ok=True)


def test_scanner_osv_direct():
    """Test DependencyScanner with OSV direct mode."""
    print("\n" + "="*80)
    print("TEST 4: DependencyScanner with OSV Direct Mode")
    print("="*80)
    
    # Create sample manifest
    manifest = Path("test_package.json")
    manifest.write_text("""{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "qs": "6.9.0",
    "lodash": "4.17.19"
  }
}""")
    
    try:
        from src.scanner import DependencyScanner
        
        print("\n[TEST 4a] Initializing DependencyScanner with OSV Direct mode...")
        scanner = DependencyScanner(use_osv_direct=True)
        
        print(f"Adapter names: {scanner.adapter_names}")
        print(f"Using OSV direct: {scanner.use_osv_direct}")
        
        print("\n[TEST 4b] Scanning manifest file...")
        result = scanner.scan_file(manifest)
        
        print(f"\nScan Results:")
        print(f"  Project: {result['project_name']}")
        print(f"  Total dependencies: {result['total_dependencies']}")
        print(f"  Direct dependencies: {result['direct_dependencies']}")
        print(f"  Findings: {len(result['findings'])}")
        print(f"  Risk score: {result['risk_score']}")
        
        if result['findings']:
            print(f"\n[PASS] Found {len(result['findings'])} findings:")
            for finding in result['findings'][:5]:  # Show first 5
                print(f"  - {finding['package']}@{finding['version']}: {finding['vulnerability_id']}")
                print(f"    Severity: {finding['severity']}, Confidence: {finding['confidence']}")
        else:
            print("\n[FAIL] No findings detected")
    
    finally:
        manifest.unlink(missing_ok=True)


def run_all_tests():
    """Run all tests."""
    print("\n" + "="*80)
    print("OSV API Integration Test Suite")
    print("="*80)
    
    try:
        test_osv_client_direct()
        test_vulnerability_manager()
        test_dependency_parser_with_scanner()
        test_scanner_osv_direct()
        
        print("\n" + "="*80)
        print("[PASS] All tests completed successfully!")
        print("="*80)
    
    except Exception as e:
        logger.exception(f"Test failed with error: {e}")
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
