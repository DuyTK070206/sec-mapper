from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from src.dependency_parser import ParserFactory, ParsedDependency
from src.vulnerability_manager import VulnerabilityManager
from src.report_generator import ReportGenerator
from src.exploit_generator import ExploitGeneratorFactory


class DependencyScanner:
    """Coordinate parsing, vulnerability matching, exploit generation, and report formatting."""

    def __init__(self, db_path: Optional[str] = None, nvd_api_key: Optional[str] = None, github_token: Optional[str] = None) -> None:
        """Initialize the dependency scanner with optional vulnerability data sources."""
        self.vuln_manager = VulnerabilityManager(db_path, nvd_api_key, github_token)
        self.exploit_generator = ExploitGeneratorFactory()
    def scan_file(self, manifest_path: Path, lock_path: Optional[Path] = None) -> Dict:
        """Scan the manifest and optional lock file for known vulnerabilities."""
        dependencies = self._load_dependencies(manifest_path, lock_path)
        findings: List[Dict] = []

        for dep in dependencies:
            vulns = self.vuln_manager.find_vulnerabilities(
                name=dep.name,
                version_spec=dep.version,
                ecosystem=dep.ecosystem,
            )
            for vuln in vulns:
                poc = None
                generator = ExploitGeneratorFactory.get_generator(vuln)
                if generator is not None:
                    try:
                        poc = generator.generate_poc(vuln)
                    except Exception:
                        poc = None

                findings.append({
                    'package': dep.name,
                    'version': dep.version,
                    'ecosystem': dep.ecosystem,
                    'source': dep.source,
                    'transitive': dep.is_transitive,
                    'cve': vuln['cve_id'],
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'reference': vuln['reference'],
                    'fixed_version': vuln['fixed_version'],
                    'has_patch': vuln['has_patch'],
                    'effort': self._estimate_effort(dep.version, vuln['fixed_version'], vuln['has_patch']),
                    'recommended_version': vuln['fixed_version'],
                    'poc': poc,
                })

        total_direct, total_transitive = self._dependency_counts(dependencies)
        return {
            'project_name': manifest_path.stem,
            'scan_time': datetime.now().isoformat(),
            'total_dependencies': len(dependencies),
            'direct_dependencies': total_direct,
            'transitive_dependencies': total_transitive,
            'findings': findings,
            'risk_score': self._calculate_overall_risk_score(findings),
        }

    def _load_dependencies(self, manifest_path: Path, lock_path: Optional[Path] = None) -> List[ParsedDependency]:
        """Load dependencies from the manifest and merge optional lock file data."""
        root_parser = ParserFactory.get_parser(manifest_path.name)
        root_deps = root_parser.parse(manifest_path.read_text(encoding='utf-8'))

        if lock_path and lock_path.exists():
            lock_parser = ParserFactory.get_parser(lock_path.name)
            lock_deps = lock_parser.parse(lock_path.read_text(encoding='utf-8'))
            return self._merge_dependencies(root_deps, lock_deps)

        return root_deps

    def _merge_dependencies(
        self,
        root_deps: List[ParsedDependency],
        lock_deps: List[ParsedDependency],
    ) -> List[ParsedDependency]:
        """Merge root manifest dependencies with lock file dependencies.

        Root dependencies have priority and transitive dependencies are marked
        appropriately when loaded from the lock file.
        """
        merged: Dict[Tuple[str, str, str], ParsedDependency] = {}
        root_names = {dep.name.lower() for dep in root_deps}

        for dep in root_deps:
            key = (dep.name.lower(), dep.version, dep.ecosystem)
            merged[key] = dep

        for dep in lock_deps:
            key = (dep.name.lower(), dep.version, dep.ecosystem)
            if key in merged:
                continue
            dep.is_transitive = dep.is_transitive or (dep.name.lower() not in root_names)
            merged[key] = dep

        return list(merged.values())

    def _dependency_counts(self, dependencies: List[ParsedDependency]) -> Tuple[int, int]:
        """Count direct and transitive dependencies in the scan."""
        direct = sum(1 for dep in dependencies if not dep.is_transitive)
        transitive = sum(1 for dep in dependencies if dep.is_transitive)
        return direct, transitive

    def format_report(self, scan_result: Dict, manifest_path: Path) -> str:
        """Format the scan result as a human-readable text report."""
        lines = [
            '=' * 60,
            'DEPENDENCY VULNERABILITY SCAN REPORT',
            '=' * 60,
            '',
            '[SCAN SUMMARY]',
            f'{"─" * 60}',
            f'File: {manifest_path}',
            f'Scan Time: {scan_result["scan_time"]}',
            f'Overall Risk Score: {scan_result["risk_score"]}/100',
            f'Total Dependencies: {scan_result["total_dependencies"]}',
            f'  - Direct: {scan_result["direct_dependencies"]}',
            f'  - Transitive: {scan_result["transitive_dependencies"]}',
            f'Vulnerabilities Found: {len(scan_result["findings"])}',
            f'  - Critical: {sum(1 for f in scan_result["findings"] if f["severity"] == "critical")}',
            f'  - High: {sum(1 for f in scan_result["findings"] if f["severity"] == "high")}',
            f'  - Medium: {sum(1 for f in scan_result["findings"] if f["severity"] == "medium")}',
            f'  - Low: {sum(1 for f in scan_result["findings"] if f["severity"] == "low")}',
            '',
        ]

        if not scan_result['findings']:
            lines.append('[OK] No known vulnerabilities found for analyzed dependencies.')
            return '\n'.join(lines)

        lines.extend([
            '[DETAILED FINDINGS]',
            f'{"─" * 60}',
            ''
        ])

        for idx, finding in enumerate(scan_result['findings'], 1):
            severity_marker = {'critical': '[CRITICAL]', 'high': '[HIGH]', 'medium': '[MEDIUM]', 'low': '[LOW]'}.get(finding['severity'], '[UNKNOWN]')
            
            lines.extend([
                f'{idx}. {severity_marker} {finding["package"]} ({finding["ecosystem"]})',
                f'   Current Version: {finding["version"]}',
                f'   Severity: {finding["severity"].upper()}',
                f'   Type: {"Transitive" if finding["transitive"] else "Direct"}',
                f'   CVE ID: {finding["cve"]}',
                f'   Description: {finding["description"]}',
                f'   Reference: {finding["reference"]}',
                f'   Patched Version: {finding["recommended_version"]}',
                f'   Patch Available: {"Yes" if finding["has_patch"] else "No"}',
                f'   Fix Effort: {finding["effort"].upper()}',
                f'   Breaking Changes: {"Possible" if self._check_breaking_changes(finding["version"], finding["recommended_version"]) else "None expected"}',
                '',
            ])

            if finding.get('poc'):
                lines.extend([
                    f'   [PROOF OF CONCEPT]:',
                    f'   {"-" * 55}',
                ])
                poc_lines = finding['poc'].split('\n')
                for poc_line in poc_lines[:30]:  # Show first 30 lines
                    lines.append(f'   {poc_line}')
                if len(poc_lines) > 30:
                    lines.append(f'   ... (and {len(poc_lines) - 30} more lines)')
                lines.append('')

        lines.extend([
            '[REMEDIATION PLAN]',
            f'{"─" * 60}',
        ])
        
        sorted_findings = sorted(scan_result['findings'], 
                                key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4))
        
        for idx, finding in enumerate(sorted_findings, 1):
            effort_map = {"low": "< 5 min", "medium": "5-30 min", "high": "> 30 min"}
            effort_time = effort_map.get(finding["effort"], "Unknown")
            priority_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW'}
            priority = priority_map.get(finding['severity'], 'UNKNOWN')
            
            lines.extend([
                f'{idx}. PRIORITY: {priority}',
                f'   Package: {finding["package"]}@{finding["version"]} -> {finding["recommended_version"]}',
                f'   Estimated Time: {effort_time}',
                f'   Testing: Unit tests, Integration tests, Regression tests',
                '',
            ])

        lines.extend([
            '[RECOMMENDATIONS]',
            f'{"─" * 60}',
            f'1. Review and prioritize vulnerabilities based on severity',
            f'2. Start with CRITICAL and HIGH severity vulnerabilities',
            f'3. Update dependencies to recommended versions',
            f'4. Run full test suite after updates',
            f'5. Monitor for any breaking changes',
            f'6. Consider using lock files (package-lock.json) for consistency',
            '',
        ])

        return '\n'.join(lines)
    
    def _check_breaking_changes(self, current_version: str, fixed_version: str) -> bool:
        """Check whether a version update crosses a major version boundary."""
        try:
            from packaging import version
            current = version.parse(current_version.lstrip('^~'))
            fixed = version.parse(fixed_version)
            return fixed.major > current.major
        except Exception:
            return False

    def generate_json_report(self, scan_result: Dict) -> str:
        """Generate a JSON-formatted report from the scan result."""
        return ReportGenerator(scan_result).generate_json_report()

    def generate_html_report(self, scan_result: Dict) -> str:
        """Generate an HTML dashboard report from the scan result."""
        return ReportGenerator(scan_result).generate_html_report()
    
    def generate_sarif_report(self, scan_result: Dict) -> str:
        """Generate a SARIF report for IDE and CI integration."""
        return ReportGenerator(scan_result).generate_sarif_report()

    def _estimate_effort(self, current_version: str, fixed_version: str, has_patch: bool) -> str:
        """Estimate remediation effort based on patch availability and version delta."""
        if not has_patch:
            return 'high'

        try:
            from packaging import version
            current = version.parse(current_version.lstrip('^~'))
            fixed = version.parse(fixed_version)
        except Exception:
            return 'medium'

        if fixed.major > current.major:
            return 'high'
        if fixed.minor > current.minor:
            return 'medium'
        return 'low'

    def _calculate_overall_risk_score(self, findings: List[Dict]) -> int:
        """Compute an overall risk score from the scanned vulnerability findings."""
        if not findings:
            return 0

        score_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 20}
        scores = [score_map.get(f['severity'], 0) for f in findings]
        return int(sum(scores) / len(scores))

