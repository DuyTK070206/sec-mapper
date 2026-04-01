from pathlib import Path
from typing import Dict, List

from src.dependency_parser import ParserFactory
from src.vulnerability_manager import VulnerabilityManager
from src.report_generator import ReportGenerator


class DependencyScanner:
    def __init__(self) -> None:
        self.vuln_manager = VulnerabilityManager()

    def scan_file(self, manifest_path: Path) -> Dict:
        parser = ParserFactory.get_parser(manifest_path.name)
        content = manifest_path.read_text(encoding='utf-8')
        dependencies = parser.parse(content)

        findings: List[Dict] = []
        for dep in dependencies:
            vulns = self.vuln_manager.find_vulnerabilities(
                name=dep.name,
                version_spec=dep.version,
                ecosystem=dep.ecosystem,
            )
            for vuln in vulns:
                findings.append({
                    'package': dep.name,
                    'version': dep.version,
                    'ecosystem': dep.ecosystem,
                    'cve': vuln['cve_id'],
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'reference': vuln['reference'],
                    'fixed_version': vuln['fixed_version'],
                    'has_patch': vuln['has_patch'],
                    'effort': self._estimate_effort(dep.version, vuln['fixed_version'], vuln['has_patch']),
                    'recommended_version': vuln['fixed_version'],
                })

        return {
            'project_name': manifest_path.stem,
            'scan_time': '',
            'total_dependencies': len(dependencies),
            'findings': findings,
            'risk_score': self._calculate_overall_risk_score(findings),
        }

    def format_report(self, scan_result: Dict, manifest_path: Path) -> str:
        lines = [
            f'Scan report for: {manifest_path}',
            '=' * 60,
        ]

        if not scan_result['findings']:
            lines.append('No known vulnerabilities found for direct dependencies.')
            return '\n'.join(lines)

        for finding in scan_result['findings']:
            lines.extend([
                f"Package: {finding['package']} ({finding['ecosystem']})",
                f"  Declared version: {finding['version']}",
                f"  CVE: {finding['cve']} ({finding['severity']})",
                f"  Description: {finding['description']}",
                f"  Reference: {finding['reference']}",
                f"  Recommended update: {finding['recommended_version']}",
                '',
            ])

        return '\n'.join(lines)

    def generate_json_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_json_report()

    def generate_html_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_html_report()

    def _estimate_effort(self, current_version: str, fixed_version: str, has_patch: bool) -> str:
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
        if not findings:
            return 0

        score_map = {'critical': 90, 'high': 70, 'medium': 50, 'low': 20}
        scores = [score_map.get(f['severity'], 0) for f in findings]
        return int(sum(scores) / len(scores))
