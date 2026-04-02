from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.dependency_parser import ParserFactory, ParsedDependency
from src.vulnerability_manager import VulnerabilityManager
from src.report_generator import ReportGenerator
from src.exploit_generator import ExploitGeneratorFactory


class DependencyScanner:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.vuln_manager = VulnerabilityManager(db_path)
        self.exploit_generator = ExploitGeneratorFactory()
    def scan_file(self, manifest_path: Path, lock_path: Optional[Path] = None) -> Dict:
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
            'scan_time': '',
            'total_dependencies': len(dependencies),
            'direct_dependencies': total_direct,
            'transitive_dependencies': total_transitive,
            'findings': findings,
            'risk_score': self._calculate_overall_risk_score(findings),
        }

    def _load_dependencies(self, manifest_path: Path, lock_path: Optional[Path] = None) -> List[ParsedDependency]:
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
        direct = sum(1 for dep in dependencies if not dep.is_transitive)
        transitive = sum(1 for dep in dependencies if dep.is_transitive)
        return direct, transitive

    def format_report(self, scan_result: Dict, manifest_path: Path) -> str:
        lines = [
            f'Scan report for: {manifest_path}',
            '=' * 60,
            f"Total dependencies: {scan_result['total_dependencies']}",
            f"  direct: {scan_result['direct_dependencies']}",
            f"  transitive: {scan_result['transitive_dependencies']}",
            '',
        ]

        if not scan_result['findings']:
            lines.append('No known vulnerabilities found for analyzed dependencies.')
            return '\n'.join(lines)

        for finding in scan_result['findings']:
            lines.extend([
                f"Package: {finding['package']} ({finding['ecosystem']})",
                f"  Version: {finding['version']}",
                f"  Source: {finding['source']}",
                f"  Transitive: {finding['transitive']}",
                f"  CVE: {finding['cve']} ({finding['severity']})",
                f"  Description: {finding['description']}",
                f"  Reference: {finding['reference']}",
                f"  Recommended update: {finding['recommended_version']}",
                f"  PoC snippet: {finding.get('poc', 'N/A')[:120] if finding.get('poc') else 'N/A'}",
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

