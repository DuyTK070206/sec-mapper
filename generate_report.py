#!/usr/bin/env python3
"""Generate full vulnerability report with lock file"""

from pathlib import Path
from src.scanner import DependencyScanner

def generate_full_report():
    """Run a full scan on the sample manifest and lock file, then generate an HTML report."""
    print("🔍 Scanning dependencies with lock file analysis...")
    print("="*60)
    
    # Initialize scanner
    scanner = DependencyScanner()
    
    # Scan WITH lock file (this will include transitive deps)
    manifest_path = Path('samples/package.json')
    lock_path = Path('samples/package-lock.json')
    
    print(f"📦 Manifest: {manifest_path}")
    print(f"🔒 Lock file: {lock_path}")
    print()
    
    result = scanner.scan_file(manifest_path, lock_path=lock_path)
    
    # Print summary
    print(f"Total dependencies scanned: {result['total_dependencies']}")
    print(f"  - Direct: {result['direct_dependencies']}")
    print(f"  - Transitive: {result['transitive_dependencies']}")
    print(f"Overall Risk Score: {result['risk_score']:.1f}/100")
    print()
    
    print("🔴 Vulnerabilities found:")
    print("-"*60)
    for finding in result['findings']:
        severity_icon = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }.get(finding['severity'], '⚪')
        
        print(f"{severity_icon} {finding['package']} v{finding['version']}")
        print(f"   CVE: {finding['cve']}")
        print(f"   Severity: {finding['severity'].upper()}")
        if finding['transitive']:
            print(f"   Type: Transitive (indirect)")
        print()
    
    # Generate HTML report
    print("="*60)
    print("📄 Generating HTML report...")
    html_content = scanner.generate_html_report(result)
    
    # Write to file
    output_file = Path('samples/package.report.html')
    output_file.write_text(html_content, encoding='utf-8')
    
    print(f"✅ Report saved to: {output_file}")
    print(f"📊 Open in browser: {output_file.resolve()}")
    print()
    print("="*60)
    print(f"✨ Full report generated with {len(result['findings'])} vulnerabilities!")

if __name__ == '__main__':
    generate_full_report()
