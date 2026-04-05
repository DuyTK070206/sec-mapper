#!/usr/bin/env python3
"""Generate both JSON and HTML reports with proper sorting by severity."""

import json
from pathlib import Path
from src.scanner import DependencyScanner

ROOT_DIR = Path(__file__).resolve().parent

def severity_order(severity):
    """Return order for sorting by severity (critical first)."""
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    return order.get(severity, 4)

def generate_reports():
    """Scan the sample project and export JSON and HTML reports sorted by severity."""
    # Initialize scanner
    scanner = DependencyScanner()
    
    # Scan WITH lock file
    manifest_path = ROOT_DIR / 'samples' / 'package.json'
    lock_path = ROOT_DIR / 'samples' / 'package-lock.json'
    
    print("[*] Scanning dependencies with lock file analysis...")
    result = scanner.scan_file(manifest_path, lock_path=lock_path)
    
    # Sort findings by severity (critical first)
    result['findings'].sort(key=lambda x: (severity_order(x['severity']), x['package']))
    
    # Print summary
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    print("Total dependencies: {}".format(result['total_dependencies']))
    print("  Direct: {}".format(result['direct_dependencies']))
    print("  Transitive: {}".format(result['transitive_dependencies']))
    print("Overall Risk Score: {:.1f}/100".format(result['risk_score']))
    print()
    
    # Count by severity
    critical = len([f for f in result['findings'] if f['severity'] == 'critical'])
    high = len([f for f in result['findings'] if f['severity'] == 'high'])
    medium = len([f for f in result['findings'] if f['severity'] == 'medium'])
    low = len([f for f in result['findings'] if f['severity'] == 'low'])
    
    print("VULNERABILITIES BY SEVERITY:")
    if critical > 0:
        print("  CRITICAL: {}".format(critical))
    if high > 0:
        print("  HIGH: {}".format(high))
    if medium > 0:
        print("  MEDIUM: {}".format(medium))
    if low > 0:
        print("  LOW: {}".format(low))
    print()
    
    # Display sorted findings
    print("="*70)
    print("VULNERABILITIES (Sorted by Severity)")
    print("="*70)
    for idx, finding in enumerate(result['findings'], 1):
        severity_display = {
            'critical': '[CRITICAL]',
            'high': '[HIGH]',
            'medium': '[MEDIUM]',
            'low': '[LOW]'
        }.get(finding['severity'], '[UNKNOWN]')
        
        dep_type = "TRANSITIVE" if finding.get('transitive', False) else "DIRECT"
        
        print("\n{}. {} {} - {}".format(
            idx,
            severity_display,
            finding['package'],
            dep_type
        ))
        print("   Version: {}".format(finding['version']))
        print("   CVE: {}".format(finding['cve']))
        print("   Description: {}".format(finding['description'][:80]))
        print("   Fixed Version: {}".format(finding['fixed_version']))
        print("   Effort: {}".format(finding['effort']))
    
    # Generate JSON report
    print("\n" + "="*70)
    print("[*] Generating JSON report...")
    json_content = scanner.generate_json_report(result)
    
    json_file = Path('samples/package.report.json')
    json_file.write_text(json_content, encoding='utf-8')
    print("[OK] JSON report saved to: {}".format(json_file))
    
    # Parse and re-save with sorted findings
    json_data = json.loads(json_content)
    json_data['findings'].sort(key=lambda x: severity_order(x['severity']))
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print("[OK] JSON sorted by severity")
    
    # Generate HTML report  
    print("[*] Generating HTML report...")
    html_content = scanner.generate_html_report(result)
    
    html_file = ROOT_DIR / 'samples' / 'package.report.html'
    html_file.write_text(html_content, encoding='utf-8')
    print("[OK] HTML report saved to: {}".format(html_file))
    
    print("\n" + "="*70)
    print("[SUCCESS] Both reports generated successfully!")
    print("="*70)
    print("JSON: samples/package.report.json")
    print("HTML: samples/package.report.html")
    print()
    print("Open HTML file in browser to view interactive report with:")
    print("  - All {} vulnerabilities sorted by severity".format(len(result['findings'])))
    print("  - Risk scoring details")
    print("  - Remediation plans")
    print("  - PoC exploit code")
    print("  - CVE references (NVD, Mitre)")

if __name__ == '__main__':
    generate_reports()
