# attack_path_engine.py

"""
AI-Powered Attack Path Reasoning Engine

Analyzes vulnerability relationships, generates attack path narratives,
and provides intelligent risk prioritization using AI reasoning.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json
import random


@dataclass
class AttackPath:
    """Represents a complete attack path from entry to impact."""
    path_id: str
    entry_point: str
    vulnerable_package: str
    cve_id: str
    severity: str
    exploit_type: str
    impact: str
    chain: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 0.0
    reasoning: str = ""
    remediation_priority: int = 0
    remediation_effort: str = "medium"
    ai_explanation: str = ""


@dataclass
class AIRiskAssessment:
    """AI-generated risk assessment for a vulnerability."""
    cve_id: str
    package_name: str
    overall_risk_score: float  # 0-100
    exploitability_score: float  # 0-100
    reachability_score: float  # 0-100
    impact_score: float  # 0-100
    confidence: float  # 0-100
    
    # AI reasoning factors
    internet_exposure: bool
    exploit_available: bool
    patch_available: bool
    complexity: str  # "low", "medium", "high"
    
    # Decision factors
    should_fix_first: bool
    postpone_reason: Optional[str] = None
    
    # Explanations
    reasoning_chain: List[str] = field(default_factory=list)
    ai_narrative: str = ""


class AttackPathEngine:
    """
    AI-Powered Attack Path Reasoning Engine
    
    Capabilities:
    - Generate attack path chains
    - Provide AI risk prioritization
    - Explain vulnerability relationships
    - Generate remediation recommendations
    """
    
    # Known exploit type mappings
    EXPLOIT_TYPES = {
        'CVE-2021-23337': 'Prototype Pollution',
        'CVE-2021-33901': 'SSRF / Request Smuggling',
        'GHSA-95c9-f9f2-q643': 'Data Exposure via URL Params',
        'CVE-2021-44228': 'Remote Code Execution (Log4Shell)',
        'CVE-2021-27492': 'HTTP Request Smuggling',
        'CVE-2021-32640': 'Certificate Verification Bypass',
    }
    
    # Impact chains - what happens after exploitation
    IMPACT_CHAINS = {
        'Prototype Pollution': [
            'Modify object prototypes',
            'Bypass authentication checks',
            'Privilege escalation',
            'Full application compromise'
        ],
        'SSRF / Request Smuggling': [
            'Access internal services',
            'Scan internal network',
            'Cloud metadata exposure',
            'Internal infrastructure pivot'
        ],
        'Data Exposure via URL Params': [
            'Leak sensitive data in URLs',
            'Credential theft via logs',
            'Session hijacking',
            'Data breach'
        ],
        'Remote Code Execution': [
            'Execute arbitrary commands',
            'Install malware',
            'Establish persistence',
            'Complete system compromise'
        ],
        'HTTP Request Smuggling': [
            'Bypass WAF/Proxy rules',
            'Session hijacking',
            'Cache poisoning',
            'Internal service access'
        ],
        'Certificate Verification Bypass': [
            'Man-in-the-middle attacks',
            'Credential theft',
            'Data interception',
            'Session compromise'
        ],
    }
    
    # Attack pattern templates
    ATTACK_PATTERNS = [
        "Attacker exploits {vuln_pkg} vulnerability",
        "Compromised package allows {exploit_type}",
        "Attacker gains {initial_impact}",
        "Attacker pivots to {pivot}",
        "Attacker achieves {final_impact}"
    ]
    
    def __init__(self, findings: List[Dict], dependencies: List[Dict]):
        """
        Initialize the attack path engine.
        
        Args:
            findings: List of vulnerability findings
            dependencies: List of dependency information
        """
        self.findings = findings
        self.dependencies = dependencies
        self.attack_paths: List[AttackPath] = []
        self.risk_assessments: Dict[str, AIRiskAssessment] = {}
        
        # Build the knowledge graph
        self._build_knowledge_graph()
    
    def _build_knowledge_graph(self) -> None:
        """Build internal knowledge graph of vulnerability relationships."""
        self.knowledge_graph = {
            'nodes': [],
            'edges': [],
            'vulnerability_chains': {}
        }
        
        # Add nodes for each finding
        for finding in self.findings:
            node = {
                'id': finding.get('cve', ''),
                'label': finding.get('package', ''),
                'type': 'vulnerability',
                'severity': finding.get('severity', 'medium'),
                'data': finding
            }
            self.knowledge_graph['nodes'].append(node)
        
        # Add edges for attack chains
        for i, finding in enumerate(self.findings):
            for j, other_finding in enumerate(self.findings):
                if i != j:
                    # Check if there's a relationship
                    if self._has_attack_relationship(finding, other_finding):
                        edge = {
                            'source': finding.get('cve', ''),
                            'target': other_finding.get('cve', ''),
                            'type': 'can_pivot_to'
                        }
                        self.knowledge_graph['edges'].append(edge)
    
    def _has_attack_relationship(self, finding1: Dict, finding2: Dict) -> bool:
        """Determine if there's an attack relationship between two vulnerabilities."""
        # Same package - can chain exploits
        if finding1.get('package') == finding2.get('package'):
            return True
        
        # Known transitive relationships
        known_chains = {
            ('axios', 'follow-redirects'): True,
            ('express', 'body-parser'): True,
            ('lodash', 'lodash-mock'): True,
        }
        
        pkg1 = finding1.get('package', '').lower()
        pkg2 = finding2.get('package', '').lower()
        
        return known_chains.get((pkg1, pkg2), False)
    
    def generate_attack_paths(self) -> List[AttackPath]:
        """
        Generate all possible attack paths from findings.
        
        Returns:
            List of AttackPath objects
        """
        self.attack_paths = []
        
        for idx, finding in enumerate(self.findings):
            path = self._create_attack_path(finding, idx)
            self.attack_paths.append(path)
        
        # Sort by risk score
        self.attack_paths.sort(key=lambda x: x.risk_score, reverse=True)
        
        return self.attack_paths
    
    def _create_attack_path(self, finding: Dict, index: int) -> AttackPath:
        """Create a single attack path from a vulnerability finding."""
        cve_id = finding.get('cve', '')
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        # Get exploit type
        exploit_type = self.EXPLOIT_TYPES.get(cve_id, 'Unknown Exploitation')
        
        # Get impact chain
        impact_chain = self.IMPACT_CHAINS.get(exploit_type, ['Unknown Impact'])
        
        # Build the attack chain
        chain = self._build_attack_chain(finding, exploit_type, impact_chain)
        
        # Calculate risk score
        risk_score = self._calculate_attack_path_risk(finding)
        
        # Generate AI reasoning
        reasoning = self._generate_ai_reasoning(finding, exploit_type, impact_chain)
        
        # Calculate confidence
        confidence = self._calculate_confidence(finding)
        
        # Determine remediation priority
        priority = self._determine_remediation_priority(finding)
        effort = self._estimate_remediation_effort(finding)
        
        return AttackPath(
            path_id=f"PATH-{index + 1:03d}",
            entry_point=package,
            vulnerable_package=package,
            cve_id=cve_id,
            severity=severity,
            exploit_type=exploit_type,
            impact=impact_chain[-1] if impact_chain else 'Unknown',
            chain=chain,
            risk_score=risk_score,
            confidence=confidence,
            reasoning=reasoning,
            remediation_priority=priority,
            remediation_effort=effort,
            ai_explanation=self._generate_ai_narrative(finding, exploit_type, impact_chain)
        )
    
    def _build_attack_chain(self, finding: Dict, exploit_type: str, impact_chain: List[str]) -> List[Dict]:
        """Build the step-by-step attack chain."""
        package = finding.get('package', '')
        chain = []
        
        # Step 1: Initial access
        chain.append({
            'step': 1,
            'action': 'Initial Access',
            'description': f'Attacker targets {package} package',
            'technique': 'Supply Chain Compromise / Exploit Public Application'
        })
        
        # Step 2: Exploitation
        chain.append({
            'step': 2,
            'action': 'Exploitation',
            'description': f'Exploit {exploit_type} vulnerability',
            'technique': self._get_mitre_technique(exploit_type)
        })
        
        # Step 3-5: Impact chain
        for idx, impact in enumerate(impact_chain[:3], start=3):
            chain.append({
                'step': idx,
                'action': 'Impact',
                'description': impact,
                'technique': self._get_impact_technique(impact)
            })
        
        return chain
    
    def _get_mitre_technique(self, exploit_type: str) -> str:
        """Map exploit type to MITRE ATT&CK technique."""
        techniques = {
            'Prototype Pollution': 'T1059.004 - Command and Scripting Interpreter: Unix Shell',
            'SSRF / Request Smuggling': 'T1190 - Exploit Public-Facing Application',
            'Data Exposure via URL Params': 'T1041 - Exfiltration Over C2 Channel',
            'Remote Code Execution': 'T1059 - Command and Scripting Interpreter',
            'HTTP Request Smuggling': 'T1190 - Exploit Public-Facing Application',
            'Certificate Verification Bypass': 'T1040 - Network Sniffing',
        }
        return techniques.get(exploit_type, 'T1190 - Exploit Public-Facing Application')
    
    def _get_impact_technique(self, impact: str) -> str:
        """Map impact to MITRE ATT&CK technique."""
        if 'RCE' in impact or 'code execution' in impact.lower():
            return 'T1059 - Command and Scripting Interpreter'
        elif 'credential' in impact.lower() or 'password' in impact.lower():
            return 'T1078 - Valid Accounts'
        elif 'data' in impact.lower() or 'breach' in impact.lower():
            return 'T1041 - Exfiltration Over C2 Channel'
        elif 'compromise' in impact.lower():
            return 'T1486 - Data Encrypted for Impact'
        return 'T1059 - Command and Scripting Interpreter'
    
    def _calculate_attack_path_risk(self, finding: Dict) -> float:
        """Calculate risk score for an attack path."""
        severity_scores = {
            'critical': 95,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        
        base_score = severity_scores.get(finding.get('severity', 'medium'), 50)
        
        # Adjust for exploit availability
        if finding.get('has_patch', True):
            base_score *= 0.9  # Has patch = slightly lower risk
        
        # Adjust for transitive vs direct
        if finding.get('transitive', False):
            base_score *= 0.8  # Transitive is harder to exploit
        
        # Adjust for patch availability
        if not finding.get('has_patch', True):
            base_score *= 1.2  # No patch = higher risk
        
        return min(round(base_score, 1), 100)
    
    def _generate_ai_reasoning(self, finding: Dict, exploit_type: str, impact_chain: List[str]) -> str:
        """Generate detailed AI reasoning for the attack path."""
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        reasoning_parts = [
            f"Analysis of {package} reveals {exploit_type} vulnerability.",
            f"The vulnerability is classified as {severity.upper()} severity.",
        ]
        
        # Add specific reasoning based on package
        if package.lower() == 'lodash':
            reasoning_parts.append(
                "Lodash is a widely-used utility library. Prototype pollution can affect "
                "any application that processes untrusted objects, making this highly exploitable."
            )
        elif package.lower() == 'axios':
            reasoning_parts.append(
                "Axios is commonly used for HTTP requests. URL parameter data exposure "
                "can leak sensitive information in server logs and referrer headers."
            )
        elif package.lower() == 'follow-redirects':
            reasoning_parts.append(
                "follow-redirects is a transitive dependency of many HTTP libraries. "
                "Compromise could affect axios, got, and other HTTP clients."
            )
        
        # Add impact reasoning
        if impact_chain:
            reasoning_parts.append(
                f"If exploited, attackers can achieve: {' → '.join(impact_chain[:2])}"
            )
        
        return " ".join(reasoning_parts)
    
    def _calculate_confidence(self, finding: Dict) -> float:
        """Calculate AI confidence in the assessment."""
        confidence = 70.0  # Base confidence
        
        # Higher confidence if we have a CVE ID
        if finding.get('cve', '').startswith('CVE-'):
            confidence += 15
        
        # Higher confidence if there's a patch
        if finding.get('has_patch', False):
            confidence += 10
        
        # Higher confidence for known packages
        known_packages = {'lodash', 'axios', 'express', 'follow-redirects', 'moment'}
        if finding.get('package', '').lower() in known_packages:
            confidence += 5
        
        return min(confidence, 99)
    
    def _determine_remediation_priority(self, finding: Dict) -> int:
        """Determine remediation priority (1 = highest)."""
        severity = finding.get('severity', 'medium')
        
        priority_map = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4
        }
        
        # Adjust for exploitability
        priority = priority_map.get(severity, 3)
        
        # Direct dependencies get priority boost
        if not finding.get('transitive', False):
            priority = max(1, priority - 1)
        
        return priority
    
    def _estimate_remediation_effort(self, finding: Dict) -> str:
        """Estimate the effort required to remediate."""
        effort = finding.get('effort', 'medium')
        return effort
    
    def _generate_ai_narrative(self, finding: Dict, exploit_type: str, impact_chain: List[str]) -> str:
        """Generate a human-readable AI narrative."""
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        narrative = f"""
## AI Security Analysis: {package}

### Threat Assessment
The {package} package contains a {severity.upper()} severity vulnerability that enables {exploit_type}.

### Attack Scenario
If an attacker compromises {package}, they can:
"""
        
        for idx, impact in enumerate(impact_chain, 1):
            narrative += f"{idx}. {impact}\n"
        
        narrative += f"""
### AI Reasoning
{self._generate_ai_reasoning(finding, exploit_type, impact_chain)}

### Recommendation
{"IMMEDIATE action required" if severity == "critical" else "Schedule remediation"} - 
Priority {self._determine_remediation_priority(finding)}
"""
        
        return narrative.strip()
    
    def perform_ai_risk_prioritization(self) -> List[AIRiskAssessment]:
        """
        Perform AI-driven risk prioritization for all findings.
        
        Returns:
            List of AIRiskAssessment objects sorted by overall risk
        """
        assessments = []
        
        for finding in self.findings:
            assessment = self._create_ai_risk_assessment(finding)
            assessments.append(assessment)
        
        # Sort by overall risk score
        assessments.sort(key=lambda x: x.overall_risk_score, reverse=True)
        
        self.risk_assessments = {a.cve_id: a for a in assessments}
        
        return assessments
    
    def _create_ai_risk_assessment(self, finding: Dict) -> AIRiskAssessment:
        """Create a detailed AI risk assessment for a finding."""
        cve_id = finding.get('cve', '')
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        # Calculate individual scores
        exploitability = self._calculate_exploitability(finding)
        reachability = self._calculate_reachability(finding)
        impact = self._calculate_impact_score(finding)
        
        # Calculate overall risk
        overall_risk = (exploitability * 0.4 + reachability * 0.3 + impact * 0.3)
        
        # Determine if should fix first
        should_fix, postpone_reason = self._determine_fix_priority(finding)
        
        # Generate reasoning chain
        reasoning_chain = self._build_reasoning_chain(finding, exploitability, reachability, impact)
        
        # Generate AI narrative
        ai_narrative = self._generate_risk_narrative(finding, overall_risk, reasoning_chain)
        
        return AIRiskAssessment(
            cve_id=cve_id,
            package_name=package,
            overall_risk_score=round(overall_risk, 1),
            exploitability_score=exploitability,
            reachability_score=reachability,
            impact_score=impact,
            confidence=self._calculate_confidence(finding),
            internet_exposure=not finding.get('transitive', True),
            exploit_available=finding.get('has_patch', False),  # Inverted: has_patch means we know about it
            patch_available=finding.get('has_patch', True),
            complexity=self._assess_complexity(finding),
            should_fix_first=should_fix,
            postpone_reason=postpone_reason,
            reasoning_chain=reasoning_chain,
            ai_narrative=ai_narrative
        )
    
    def _calculate_exploitability(self, finding: Dict) -> float:
        """Calculate how exploitable the vulnerability is."""
        score = 50.0
        
        severity = finding.get('severity', 'medium')
        severity_scores = {'critical': 90, 'high': 70, 'medium': 45, 'low': 25}
        score = severity_scores.get(severity, 45)
        
        # Known exploits increase exploitability
        if finding.get('has_patch', True):
            score += 10
        
        # Direct dependencies are more exploitable
        if not finding.get('transitive', True):
            score += 15
        
        return min(score, 100)
    
    def _calculate_reachability(self, finding: Dict) -> float:
        """Calculate how reachable the vulnerability is."""
        score = 40.0
        
        # Direct dependencies are more reachable
        if not finding.get('transitive', True):
            score += 30
        
        # Common packages have higher reachability
        common_packages = {'lodash', 'axios', 'express', 'moment'}
        if finding.get('package', '').lower() in common_packages:
            score += 20
        
        return min(score, 100)
    
    def _calculate_impact_score(self, finding: Dict) -> float:
        """Calculate the potential impact of exploitation."""
        severity = finding.get('severity', 'medium')
        impact_scores = {'critical': 95, 'high': 75, 'medium': 50, 'low': 25}
        
        score = impact_scores.get(severity, 50)
        
        # RCE has highest impact
        cve_id = finding.get('cve', '')
        if '44228' in cve_id or 'RCE' in finding.get('description', '').upper():
            score += 5
        
        return min(score, 100)
    
    def _determine_fix_priority(self, finding: Dict) -> Tuple[bool, Optional[str]]:
        """Determine if this should be fixed first or postponed."""
        severity = finding.get('severity', 'medium')
        
        # Critical and high severity should be fixed first
        if severity in ['critical', 'high']:
            return True, None
        
        # Check for breaking changes
        current_ver = finding.get('version', '')
        fixed_ver = finding.get('fixed_version', '')
        
        if self._would_cause_breaking_changes(current_ver, fixed_ver):
            return False, "Major version upgrade may cause breaking changes - requires regression testing"
        
        return True, None
    
    def _would_cause_breaking_changes(self, current: str, fixed: str) -> bool:
        """Check if upgrade would cause breaking changes."""
        try:
            current_major = int(current.split('.')[0].lstrip('^~v'))
            fixed_major = int(fixed.split('.')[0])
            return fixed_major > current_major + 1
        except:
            return False
    
    def _assess_complexity(self, finding: Dict) -> str:
        """Assess the complexity of exploiting this vulnerability."""
        cve_id = finding.get('cve', '')
        
        # Known high-complexity exploits
        high_complexity = ['CVE-2021-44228']  # Log4Shell had complex exploitation
        low_complexity = ['CVE-2021-23337']  # Prototype pollution is simpler
        
        if cve_id in high_complexity:
            return 'high'
        elif cve_id in low_complexity:
            return 'low'
        
        severity = finding.get('severity', 'medium')
        return 'medium'
    
    def _build_reasoning_chain(
        self,
        finding: Dict,
        exploitability: float,
        reachability: float,
        impact: float
    ) -> List[str]:
        """Build the step-by-step reasoning chain."""
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        chain = []
        
        # Step 1: Severity assessment
        chain.append(f"Severity assessment: {severity.upper()} → Base score {exploitability:.0f}/100")
        
        # Step 2: Reachability analysis
        reachability_factor = "direct" if not finding.get('transitive', True) else "transitive"
        chain.append(f"Reachability: {reachability_factor} dependency → Reachability score {reachability:.0f}/100")
        
        # Step 3: Impact analysis
        chain.append(f"Impact potential: {impact:.0f}/100 based on severity and exploit type")
        
        # Step 4: Final calculation
        overall = exploitability * 0.4 + reachability * 0.3 + impact * 0.3
        chain.append(f"Overall risk: {exploitability:.0f}×0.4 + {reachability:.0f}×0.3 + {impact:.0f}×0.3 = {overall:.1f}/100")
        
        return chain
    
    def _generate_risk_narrative(
        self,
        finding: Dict,
        overall_risk: float,
        reasoning_chain: List[str]
    ) -> str:
        """Generate a comprehensive risk narrative."""
        package = finding.get('package', '')
        severity = finding.get('severity', 'medium')
        
        narrative = f"""
### AI Risk Assessment: {package}

**Overall Risk Score: {overall_risk:.1f}/100**

#### Decision Factors:
"""
        
        for reason in reasoning_chain:
            narrative += f"- {reason}\n"
        
        # Add recommendation
        if overall_risk >= 80:
            narrative += "\n**Recommendation: CRITICAL - Fix immediately**\n"
        elif overall_risk >= 60:
            narrative += "\n**Recommendation: HIGH - Fix within 1 week**\n"
        elif overall_risk >= 40:
            narrative += "\n**Recommendation: MEDIUM - Fix within 1 month**\n"
        else:
            narrative += "\n**Recommendation: LOW - Schedule for next sprint**\n"
        
        return narrative.strip()
    
    def generate_executive_summary(self) -> Dict:
        """
        Generate AI-powered executive summary.
        
        Returns:
            Dict with technical, management, and business impact summaries
        """
        if not self.attack_paths:
            self.generate_attack_paths()
        
        if not self.risk_assessments:
            self.perform_ai_risk_prioritization()
        
        # Calculate statistics
        total_vulns = len(self.findings)
        critical_count = sum(1 for f in self.findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in self.findings if f.get('severity') == 'high')
        
        avg_risk = sum(a.overall_risk_score for a in self.risk_assessments.values()) / max(len(self.risk_assessments), 1)
        
        # Generate technical summary
        technical_summary = f"""
Technical Analysis:
- Analyzed {total_vulns} vulnerabilities across {len(set(f.get('package') for f in self.findings))} unique packages
- {critical_count} CRITICAL, {high_count} HIGH severity issues identified
- Average AI-assessed risk score: {avg_risk:.1f}/100
- Generated {len(self.attack_paths)} attack path analyses
"""
        
        # Generate management summary
        management_summary = f"""
Management Summary:
- Immediate action required for {critical_count} critical vulnerabilities
- {sum(1 for a in self.risk_assessments.values() if a.should_fix_first)} vulnerabilities recommended for immediate remediation
- {sum(1 for a in self.risk_assessments.values() if a.postpone_reason)} vulnerabilities may require additional testing before upgrade
- AI confidence in assessments: {sum(a.confidence for a in self.risk_assessments.values()) / max(len(self.risk_assessments), 1):.0f}%
"""
        
        # Generate business impact summary
        business_impact = f"""
Business Impact:
- Supply chain risk: {'HIGH' if critical_count > 0 else 'MODERATE'}
- Potential attack paths: {len(self.attack_paths)}
- Recommended remediation timeline: {'IMMEDIATE' if critical_count > 0 else 'Within 30 days'}
- Estimated remediation effort: {self._estimate_total_effort()}
"""
        
        return {
            'technical_summary': technical_summary.strip(),
            'management_summary': management_summary.strip(),
            'business_impact': business_impact.strip(),
            'statistics': {
                'total_vulnerabilities': total_vulns,
                'critical': critical_count,
                'high': high_count,
                'medium': sum(1 for f in self.findings if f.get('severity') == 'medium'),
                'low': sum(1 for f in self.findings if f.get('severity') == 'low'),
                'average_risk_score': round(avg_risk, 1),
                'attack_paths_generated': len(self.attack_paths)
            }
        }
    
    def _estimate_total_effort(self) -> str:
        """Estimate total remediation effort."""
        effort_map = {'low': 1, 'medium': 2, 'high': 3}
        
        total_effort = sum(
            effort_map.get(f.get('effort', 'medium'), 2)
            for f in self.findings
        )
        
        if total_effort <= 3:
            return "Low (~1-2 hours)"
        elif total_effort <= 6:
            return "Medium (~2-4 hours)"
        else:
            return "High (~4+ hours)"
    
    def get_remediation_plan(self) -> List[Dict]:
        """
        Generate intelligent remediation plan with prioritization.
        
        Returns:
            List of remediation steps sorted by priority
        """
        if not self.risk_assessments:
            self.perform_ai_risk_prioritization()
        
        plan = []
        
        for assessment in sorted(
            self.risk_assessments.values(),
            key=lambda x: x.overall_risk_score,
            reverse=True
        ):
            finding = next((f for f in self.findings if f.get('cve') == assessment.cve_id), {})
            
            step = {
                'priority': len(plan) + 1,
                'cve_id': assessment.cve_id,
                'package': assessment.package_name,
                'current_version': finding.get('version', 'Unknown'),
                'fixed_version': finding.get('fixed_version', 'Unknown'),
                'risk_score': assessment.overall_risk_score,
                'confidence': assessment.confidence,
                'should_fix_now': assessment.should_fix_first,
                'postpone_reason': assessment.postpone_reason,
                'effort': assessment.complexity,
                'ai_reasoning': '\n'.join(assessment.reasoning_chain[:2])
            }
            
            plan.append(step)
        
        return plan