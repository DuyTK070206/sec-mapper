# blast_radius_analyzer.py

"""
Blast Radius Analysis Module

Calculates the potential impact spread of vulnerabilities through dependency chains.
Measures how far a compromise could propagate through the dependency graph.
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import deque


@dataclass
class BlastRadiusResult:
    """Result of blast radius analysis for a vulnerability."""
    score: float  # 0-100
    depth: int  # How many levels deep the exploit can propagate
    affected_count: int  # Number of downstream dependencies
    reachability_score: float  # How reachable the vulnerability is
    supply_chain_risk: str  # "low", "medium", "high", "critical"
    impacted_packages: List[str] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    explanation: str = ""


class BlastRadiusAnalyzer:
    """
    Analyzes the blast radius of vulnerabilities in dependency graphs.
    
    Determines how far a compromise could spread through:
    - Direct dependencies
    - Transitive dependencies
    - Shared dependencies (choke points)
    """
    
    def __init__(self, dependencies: List[Dict], findings: List[Dict]):
        """
        Initialize with dependency data and vulnerability findings.
        
        Args:
            dependencies: List of dependency objects with name, version, transitive info
            findings: List of vulnerability findings from the scanner
        """
        self.dependencies = dependencies
        self.findings = findings
        self._build_dependency_map()
        self._build_reverse_deps_map()
    
    def _build_dependency_map(self) -> None:
        """Build a map of package -> dependencies it depends on."""
        self.dep_map: Dict[str, Set[str]] = {}
        
        for dep in self.dependencies:
            name = dep.get('name', '')
            # In a real scenario, we'd have the full tree
            # For now, mark direct vs transitive
            if name not in self.dep_map:
                self.dep_map[name] = set()
    
    def _build_reverse_deps_map(self) -> None:
        """Build a reverse map: package -> packages that depend on it (downstream)."""
        self.reverse_dep_map: Dict[str, Set[str]] = {}
        
        # For each finding, track which packages could be affected
        for finding in self.findings:
            vuln_pkg = finding.get('package', '')
            if vuln_pkg:
                self.reverse_dep_map[vuln_pkg] = set()
        
        # In a real implementation, we'd parse the full lock file tree
        # to determine actual downstream dependencies
    
    def analyze_blast_radius(self, vulnerability: Dict) -> BlastRadiusResult:
        """
        Calculate the blast radius for a specific vulnerability.
        
        Args:
            vulnerability: A vulnerability finding dict
            
        Returns:
            BlastRadiusResult with score and analysis details
        """
        pkg_name = vulnerability.get('package', '')
        severity = vulnerability.get('severity', 'medium')
        
        # Base score from severity
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 40,
            'low': 20
        }
        base_score = severity_scores.get(severity, 40)
        
        # Calculate depth (how many levels deep can this propagate)
        depth = self._calculate_propagation_depth(pkg_name)
        
        # Count affected downstream packages
        affected_count = self._count_affected_packages(pkg_name)
        
        # Calculate reachability (is this internet-facing?)
        reachability = self._calculate_reachability(vulnerability)
        
        # Determine supply chain risk
        supply_chain_risk = self._assess_supply_chain_risk(pkg_name)
        
        # Calculate final score
        score = self._compute_blast_radius_score(
            base_score, depth, affected_count, reachability, supply_chain_risk
        )
        
        # Get impacted packages
        impacted = self._get_impacted_packages(pkg_name)
        attack_surface = self._get_attack_surface(pkg_name)
        
        # Generate explanation
        explanation = self._generate_explanation(
            pkg_name, severity, depth, affected_count, supply_chain_risk
        )
        
        return BlastRadiusResult(
            score=score,
            depth=depth,
            affected_count=affected_count,
            reachability_score=reachability,
            supply_chain_risk=supply_chain_risk,
            impacted_packages=impacted,
            attack_surface=attack_surface,
            explanation=explanation
        )
    
    def _calculate_propagation_depth(self, package: str) -> int:
        """
        Calculate how many levels deep a compromise can propagate.
        
        Returns the maximum depth of transitive dependencies.
        """
        # Check if this package is a transitive dependency
        is_transitive = any(
            dep.get('package') == package and dep.get('transitive', False)
            for dep in self.findings
        )
        
        if is_transitive:
            # Transitive deps can affect 2+ levels
            return 3
        else:
            # Direct deps can affect 1+ levels
            return 2
    
    def _count_affected_packages(self, package: str) -> int:
        """
        Count how many downstream packages would be affected by a compromise.
        """
        # In a real implementation, this would traverse the full dependency tree
        # For now, estimate based on common patterns
        
        # Known high-impact packages that affect many downstream deps
        high_impact_packages = {
            'lodash': 47,
            'axios': 23,
            'express': 35,
            'moment': 42,
            'underscore': 28,
            'request': 31,
            'follow-redirects': 18,
        }
        
        return high_impact_packages.get(package.lower(), 1)
    
    def _calculate_reachability(self, vulnerability: Dict) -> float:
        """
        Calculate how reachable the vulnerability is from the outside.
        
        Returns a score 0-100 based on:
        - Is it a direct dependency?
        - Is there a public exploit?
        - Is it network-facing?
        """
        score = 50.0  # Base score
        
        # Direct dependencies are more reachable
        if not vulnerability.get('transitive', True):
            score += 20
        
        # Check for exploit availability
        if vulnerability.get('has_exploit', False):
            score += 25
        
        # Check severity
        severity = vulnerability.get('severity', 'medium')
        if severity == 'critical':
            score += 15
        elif severity == 'high':
            score += 10
        
        return min(score, 100)
    
    def _assess_supply_chain_risk(self, package: str) -> str:
        """
        Assess the supply chain risk level of a package.
        
        High risk = package is a popular dependency that many others depend on
        """
        # Known high-risk supply chain packages
        critical_packages = {'lodash', 'axios', 'moment', 'underscore', 'request'}
        high_packages = {'express', 'expressjs', 'follow-redirects', 'minimist'}
        
        pkg_lower = package.lower()
        
        if pkg_lower in critical_packages:
            return 'critical'
        elif pkg_lower in high_packages:
            return 'high'
        elif self._count_affected_packages(package) > 10:
            return 'medium'
        else:
            return 'low'
    
    def _compute_blast_radius_score(
        self,
        base_score: float,
        depth: int,
        affected_count: int,
        reachability: float,
        supply_chain_risk: str
    ) -> float:
        """
        Compute the final blast radius score (0-100).
        """
        # Weight factors
        depth_weight = 1.2
        affected_weight = 0.5
        reachability_weight = 0.8
        
        # Supply chain risk multiplier
        risk_multipliers = {
            'critical': 1.5,
            'high': 1.3,
            'medium': 1.1,
            'low': 1.0
        }
        
        score = base_score
        score += (depth * depth_weight * 5)
        score += min(affected_count * affected_weight, 30)
        score += (reachability * reachability_weight * 0.3)
        score *= risk_multipliers.get(supply_chain_risk, 1.0)
        
        return min(round(score, 1), 100)
    
    def _get_impacted_packages(self, package: str) -> List[str]:
        """Get list of packages that would be impacted by this vulnerability."""
        # In real implementation, traverse the dependency tree
        impacted = []
        
        # Known downstream relationships
        downstream_map = {
            'lodash': ['lodash-debounce', 'lodash-mock', 'express-lodash-pagination'],
            'axios': ['axios-extensions', 'axios-fetch-adapter'],
            'follow-redirects': ['axios', 'got', 'node-fetch'],
            'express': ['express-router', 'express-validator'],
        }
        
        impacted = downstream_map.get(package.lower(), [])
        return impacted
    
    def _get_attack_surface(self, package: str) -> List[str]:
        """
        Get the attack surface - entry points that could exploit this vulnerability.
        """
        attack_surface = []
        
        # Direct API exposure
        attack_surface.append(f"Direct import: require('{package}')")
        
        # Transitive exposure
        attack_surface.append(f"Transitive usage via dependent packages")
        
        # Common attack vectors
        if package.lower() in ['lodash', 'axios', 'follow-redirects']:
            attack_surface.append("HTTP request handling")
            attack_surface.append("Data serialization/deserialization")
        
        return attack_surface
    
    def _generate_explanation(
        self,
        package: str,
        severity: str,
        depth: int,
        affected_count: int,
        supply_chain_risk: str
    ) -> str:
        """Generate human-readable explanation of the blast radius."""
        
        risk_desc = {
            'critical': 'CRITICAL supply chain risk - affects many downstream packages',
            'high': 'HIGH supply chain risk - significant downstream impact',
            'medium': 'MODERATE supply chain risk - limited downstream impact',
            'low': 'LOW supply chain risk - minimal downstream impact'
        }
        
        explanation = f"""
The vulnerability in '{package}' has a {supply_chain_risk.upper()} blast radius:

• Severity: {severity.upper()}
• Propagation depth: {depth} levels
• Potentially affected packages: {affected_count}
• Supply chain risk: {risk_desc.get(supply_chain_risk, 'Unknown')}

This vulnerability can propagate through {depth} dependency levels and potentially 
impact {affected_count} downstream packages. The {supply_chain_risk} supply chain 
risk indicates that compromising this package could have significant ripple effects 
across the dependency graph.
""".strip()
        
        return explanation
    
    def analyze_all_findings(self) -> Dict[str, BlastRadiusResult]:
        """
        Analyze blast radius for all vulnerability findings.
        
        Returns:
            Dict mapping CVE ID to BlastRadiusResult
        """
        results = {}
        
        for finding in self.findings:
            cve_id = finding.get('cve', '')
            if cve_id:
                results[cve_id] = self.analyze_blast_radius(finding)
        
        return results
    
    def get_top_blast_radius(self, limit: int = 10) -> List[Tuple[str, BlastRadiusResult]]:
        """
        Get the top vulnerabilities by blast radius score.
        
        Returns:
            List of (cve_id, BlastRadiusResult) tuples sorted by score
        """
        all_results = self.analyze_all_findings()
        
        sorted_results = sorted(
            all_results.items(),
            key=lambda x: x[1].score,
            reverse=True
        )
        
        return sorted_results[:limit]
    
    def get_summary_statistics(self) -> Dict:
        """
        Get summary statistics for all blast radius analyses.
        """
        results = self.analyze_all_findings()
        
        if not results:
            return {
                'total_analyzed': 0,
                'average_score': 0,
                'max_score': 0,
                'critical_count': 0,
                'high_count': 0
            }
        
        scores = [r.score for r in results.values()]
        
        return {
            'total_analyzed': len(results),
            'average_score': round(sum(scores) / len(scores), 1),
            'max_score': max(scores),
            'critical_count': sum(1 for r in results.values() if r.score >= 80),
            'high_count': sum(1 for r in results.values() if 60 <= r.score < 80),
            'medium_count': sum(1 for r in results.values() if 40 <= r.score < 60),
            'low_count': sum(1 for r in results.values() if r.score < 40)
        }