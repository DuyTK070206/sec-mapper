#!/usr/bin/env python3
"""Debug script to trace vulnerability matching"""

from src.vulnerability_manager import VulnerabilityManager
from src.dependency_parser import ParserFactory
from pathlib import Path

def debug_matching():
    """Run a debug trace for dependency parsing and vulnerability matching."""
    # Load deps
    parser = ParserFactory.get_parser('package.json')
    package_content = Path('samples/package.json').read_text()
    deps = parser.parse(package_content)
    
    print("="*60)
    print("DEPENDENCIES FOUND IN package.json:")
    print("="*60)
    for dep in deps:
        print(f"  {dep.name} v{dep.version}")
    
    # Load vuln manager
    vuln_mgr = VulnerabilityManager()
    
    print("\n" + "="*60)
    print("VULNERABILITY DATABASE:")
    print("="*60)
    for vuln in vuln_mgr._vulnerabilities:
        print(f"  {vuln['package']} {vuln['ecosystem']}: {vuln['cve_id']} - {vuln['affected_versions']}")
    
    print("\n" + "="*60)
    print("VULNERABILITY DETECTION:")
    print("="*60)
    
    for dep in deps:
        print(f"\n🔍 Checking {dep.name} v{dep.version}:")
        vulns = vuln_mgr.find_vulnerabilities(dep.name, dep.version, dep.ecosystem)
        if vulns:
            for vuln in vulns:
                print(f"  ✅ Found: {vuln['cve_id']} (severity: {vuln['severity']})")
        else:
            print(f"  ❌ No vulnerabilities found")
            
            # Debug: Check why not found
            for vuln in vuln_mgr._vulnerabilities:
                if vuln['package'].lower() == dep.name.lower():
                    print(f"    But found {vuln['package']} in DB!")
                    print(f"    Affected versions: {vuln['affected_versions']}")
                    print(f"    Checking if {dep.version} matches...")
                    
                    # Manual check
                    hits = vuln_mgr._hits(vuln['affected_versions'], dep.version, dep.ecosystem)
                    print(f"    Result: {hits}")

if __name__ == '__main__':
    debug_matching()
