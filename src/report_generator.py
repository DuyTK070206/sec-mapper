# report_generator.py

import json
import html as html_module
from datetime import datetime
from typing import List, Dict
from urllib.parse import quote_plus

class ReportGenerator:
    """
    Generate various report formats:
    - JSON (machine-readable)
    - HTML (interactive dashboard)
    - PDF (compliance report)
    - SARIF (GitHub/IDE integration)
    """
    
    def __init__(self, scan_result: Dict):
        self.scan_result = scan_result
        self.timestamp = datetime.now().isoformat()
    
    def generate_json_report(self) -> str:
        """Machine-readable JSON report"""
        
        report = {
            'metadata': {
                'scan_time': self.timestamp,
                'project': self.scan_result.get('project_name'),
                'tool_version': '1.0.0',
            },
            'summary': {
                'total_dependencies': self.scan_result.get('total_dependencies'),
                'vulnerabilities': {
                    'critical': len([v for v in self.scan_result.get('findings', [])
                                   if v['severity'] == 'critical']),
                    'high': len([v for v in self.scan_result.get('findings', [])
                               if v['severity'] == 'high']),
                    'medium': len([v for v in self.scan_result.get('findings', [])
                                 if v['severity'] == 'medium']),
                    'low': len([v for v in self.scan_result.get('findings', [])
                              if v['severity'] == 'low']),
                },
                'overall_risk_score': self.scan_result.get('risk_score'),
            },
            'findings': self.scan_result.get('findings', []),
            'remediation_plan': self._generate_remediation_plan(),
        }
        
        return json.dumps(report, indent=2)
    
    def generate_html_report(self) -> str:
        """Interactive HTML dashboard with detailed CVE information"""

        findings_html_parts = []
        remediation_items = []

        for finding in self.scan_result.get('findings', []):
            cve_id = finding.get('cve', '')
            nvd_link = f'https://nvd.nist.gov/vuln/detail/{quote_plus(cve_id)}' if cve_id else '#'
            mitre_link = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={quote_plus(cve_id)}' if cve_id else '#'
            additional_reference = finding.get('reference', '') or ''
            additional_reference_html = (
                f'<a href="{html_module.escape(additional_reference)}" target="_blank" rel="noopener noreferrer" class="ref-link">Additional Reference</a>'
                if additional_reference else '<span class="ref-link disabled">No additional reference</span>'
            )
            poc_text = finding.get('poc', '') or ''
            poc_html = (
                f"""
                            <div class=\"poc-section\">
                                <div class=\"poc-header\">Proof of Concept (PoC)</div>
                                <div class=\"poc-code\"><code>{html_module.escape(poc_text)}</code></div>
                            </div>
                        """ if poc_text else ''
            )
            finding_html = f"""
                        <div class=\"finding-card\">
                            <div class=\"finding-header {(finding.get('severity') or 'unknown').lower()}\">
                                <div>
                                    <div class=\"finding-title\">{html_module.escape(finding.get('package', 'Unknown'))} @ {html_module.escape(finding.get('version', 'Unknown'))}</div>
                                    <div class=\"finding-meta\">
                                        <div class=\"meta-item\"><strong>CVE:</strong> {html_module.escape(cve_id or 'Unknown')}</div>
                                        <div class=\"meta-item\"><span class=\"severity-badge {(finding.get('severity') or 'unknown').lower()}\">{html_module.escape((finding.get('severity') or 'unknown').upper())}</span></div>
                                        <div class=\"meta-item\"><strong>Type:</strong> {'Transitive' if finding.get('transitive') else 'Direct'}</div>
                                        <div class=\"meta-item\"><strong>Effort:</strong> {html_module.escape(finding.get('effort', 'Unknown') or 'Unknown')}</div>
                                    </div>
                                </div>
                                <button class=\"finding-toggle\" onclick=\"toggleDetails(this, event)\">▲</button>
                            </div>
                            <div class=\"finding-details\">
                                <div class=\"description-section\">
                                    <div class=\"label\">Description</div>
                                    <div class=\"detail-value\">{html_module.escape(finding.get('description', 'No description available') or 'No description available')}</div>
                                </div>
                                <div class=\"detail-grid\">
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Current Version</div>
                                        <div class=\"detail-value code\">{html_module.escape(finding.get('version', 'Unknown'))}</div>
                                    </div>
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Patched Version</div>
                                        <div class=\"detail-value code\">{html_module.escape(finding.get('fixed_version', 'Unknown') or 'Unknown')}</div>
                                    </div>
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Patch Status</div>
                                        <div class=\"detail-value\">{'[OK] Available' if finding.get('has_patch') else '[NOT AVAILABLE]'}</div>
                                    </div>
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Fix Effort</div>
                                        <div class=\"detail-value\">{html_module.escape(finding.get('effort', 'Unknown') or 'Unknown')}</div>
                                    </div>
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Ecosystem</div>
                                        <div class=\"detail-value\">{html_module.escape(finding.get('ecosystem', 'Unknown') or 'Unknown')}</div>
                                    </div>
                                    <div class=\"detail-item\">
                                        <div class=\"detail-label\">Recommended Version</div>
                                        <div class=\"detail-value code\">{html_module.escape(finding.get('recommended_version', finding.get('fixed_version', 'N/A')) or 'N/A')}</div>
                                    </div>
                                </div>
                                <div class=\"reference-links\">
                                    <a href=\"{nvd_link}\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"ref-link\">NVD Details</a>
                                    <a href=\"{mitre_link}\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"ref-link\">CVE Mitre</a>
                                    {additional_reference_html}
                                </div>
                                {poc_html}
                            </div>
                        </div>
                    """
            findings_html_parts.append(finding_html)
            remediation_items.append(f"<li><strong>[{html_module.escape((finding.get('severity') or 'unknown').upper())}] {html_module.escape(finding.get('package', 'Unknown'))}</strong>: Update from {html_module.escape(finding.get('version', 'Unknown'))} to {html_module.escape(finding.get('recommended_version', finding.get('fixed_version', 'Unknown')) or 'Unknown')} (Effort: {html_module.escape(finding.get('effort', 'Unknown') or 'Unknown')})</li>")

        findings_html = '\n'.join(findings_html_parts)
        remediation_html = '\n'.join(remediation_items)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dependency Vulnerability Report</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    padding: 20px;
                }}
                h1 {{ color: #333; margin-top: 0; }}
                h2 {{ color: #555; margin-top: 30px; }}
                h3 {{ color: #777; margin-top: 20px; }}
                .metadata {{ color: #666; margin-bottom: 10px; }}
                
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .stats-card {{
                    padding: 20px;
                    border-radius: 8px;
                    background: #f9f9f9;
                    border-left: 4px solid #ddd;
                    text-align: center;
                }}
                .stats-card.critical {{ border-left-color: #dc3545; }}
                .stats-card.high {{ border-left-color: #fd7e14; }}
                .stats-card.medium {{ border-left-color: #ffc107; }}
                .stats-card.low {{ border-left-color: #28a745; }}
                .stats-card .label {{ 
                    color: #666; 
                    font-size: 14px; 
                    margin-bottom: 10px;
                }}
                .stats-card .score {{ 
                    font-size: 32px; 
                    font-weight: bold;
                    color: #333;
                }}
                
                .finding-card {{
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    margin-bottom: 15px;
                    overflow: hidden;
                    background: #fff;
                }}
                .finding-header {{
                    padding: 15px;
                    background: #f9f9f9;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border-bottom: 1px solid #eee;
                    transition: background 0.2s;
                }}
                .finding-header:hover {{
                    background: #f0f0f0;
                }}
                .finding-header.critical {{ border-left: 4px solid #dc3545; }}
                .finding-header.high {{ border-left: 4px solid #fd7e14; }}
                .finding-header.medium {{ border-left: 4px solid #ffc107; }}
                .finding-header.low {{ border-left: 4px solid #28a745; }}
                
                .finding-title {{
                    flex: 1;
                    font-weight: 600;
                    font-size: 16px;
                }}
                .finding-meta {{
                    display: flex;
                    gap: 20px;
                    flex-wrap: wrap;
                }}
                .meta-item {{
                    display: flex;
                    align-items: center;
                    gap: 5px;
                    font-size: 14px;
                }}
                .severity-badge {{
                    padding: 4px 12px;
                    border-radius: 4px;
                    font-weight: 600;
                    font-size: 12px;
                }}
                .severity-badge.critical {{ 
                    background: #dc3545; 
                    color: white;
                }}
                .severity-badge.high {{ 
                    background: #fd7e14; 
                    color: white;
                }}
                .severity-badge.medium {{ 
                    background: #ffc107; 
                    color: white;
                }}
                .severity-badge.low {{ 
                    background: #28a745; 
                    color: white;
                }}
                
                .finding-toggle {{
                    background: none;
                    border: none;
                    cursor: pointer;
                    font-size: 20px;
                    padding: 0;
                    color: #666;
                }}
                
                .finding-details {{
                    display: block;
                    padding: 20px;
                    border-top: 1px solid #eee;
                }}
                
                .detail-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .detail-item {{
                    background: #f9f9f9;
                    padding: 12px;
                    border-radius: 4px;
                }}
                .detail-label {{
                    font-weight: 600;
                    color: #666;
                    font-size: 12px;
                    text-transform: uppercase;
                    margin-bottom: 5px;
                }}
                .detail-value {{
                    color: #333;
                    word-break: break-word;
                }}
                .detail-value.code {{
                    font-family: 'Courier New', monospace;
                    font-size: 13px;
                    padding: 8px;
                    background: #f0f0f0;
                    border-radius: 3px;
                }}
                
                .description-section {{
                    background: #f9f9f9;
                    padding: 12px;
                    border-radius: 4px;
                    margin-bottom: 15px;
                    border-left: 3px solid #0066cc;
                }}
                .description-section .label {{
                    font-weight: 600;
                    color: #0066cc;
                    font-size: 12px;
                    text-transform: uppercase;
                    margin-bottom: 8px;
                }}
                
                .poc-section {{
                    background: #f5f5f5;
                    padding: 12px;
                    border-radius: 4px;
                    margin-top: 15px;
                    border-left: 3px solid #dc3545;
                }}
                .poc-header {{
                    font-weight: 600;
                    color: #dc3545;
                    font-size: 12px;
                    text-transform: uppercase;
                    margin-bottom: 8px;
                }}
                .poc-code {{
                    background: #1e1e1e;
                    color: #d4d4d4;
                    padding: 12px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    overflow-x: auto;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    max-height: 300px;
                    overflow-y: auto;
                }}
                
                .reference-links {{
                    margin-top: 15px;
                    display: flex;
                    gap: 10px;
                    flex-wrap: wrap;
                }}
                .ref-link {{
                    display: inline-block;
                    padding: 8px 12px;
                    background: #e7f3ff;
                    border-left: 3px solid #0066cc;
                    text-decoration: none;
                    color: #0066cc;
                    border-radius: 3px;
                    font-size: 13px;
                }}
                .ref-link:hover {{
                    background: #d4e9ff;
                }}
                .ref-link.disabled {{
                    background: #f0f0f0;
                    border-left-color: #999;
                    color: #666;
                    pointer-events: none;
                    cursor: default;
                }}
                
                .remediation {{
                    background: #e7f3ff;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 20px;
                    border-left: 4px solid #0066cc;
                }}
                .remediation h3 {{
                    margin-top: 0;
                    color: #0066cc;
                }}
                .remediation ol {{
                    margin: 10px 0;
                    padding-left: 20px;
                }}
                .remediation li {{
                    margin-bottom: 8px;
                    line-height: 1.5;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Dependency Vulnerability Report</h1>
                <div class="metadata">
                    <p><strong>Project:</strong> {self.scan_result.get('project_name')}</p>
                    <p><strong>Scan Time:</strong> {self.timestamp}</p>
                </div>
                
                <div class="summary">
                    <div class="stats-card critical">
                        <div class="label">Critical</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'critical'])}</div>
                    </div>
                    <div class="stats-card high">
                        <div class="label">High</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'high'])}</div>
                    </div>
                    <div class="stats-card medium">
                        <div class="label">Medium</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'medium'])}</div>
                    </div>
                    <div class="stats-card low">
                        <div class="label">Low</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'low'])}</div>
                    </div>
                </div>
                
                <h2>Overall Risk Score: {self.scan_result.get('risk_score')}/100</h2>
                
                <h3>Detailed Vulnerability Findings</h3>
                <div id="findings-container">
                    {findings_html}
                </div>
                
                <div class="remediation">
                    <h3>Remediation Plan</h3>
                    <p>Prioritize fixes based on severity and exploitability:</p>
                    <ol id="remediation-list">
                        {remediation_html}
                    </ol>
                </div>
                
                <script>
                    function toggleDetails(button, event) {{
                        event.stopPropagation();
                        const details = button.closest('.finding-card').querySelector('.finding-details');
                        const isExpanded = details.style.display !== 'none';
                        details.style.display = isExpanded ? 'none' : 'block';
                        button.textContent = isExpanded ? '▼' : '▲';
                    }}
                    
                    document.querySelectorAll('.finding-header').forEach(header => {{
                        header.addEventListener('click', function(event) {{
                            if (event.target !== this.querySelector('.finding-toggle')) {{
                                this.querySelector('.finding-toggle').click();
                            }}
                        }});
                    }});
                </script>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def generate_sarif_report(self) -> str:
        """Generate SARIF (Static Analysis Results Format) for GitHub integration"""
        
        runs = []
        results = []
        
        for finding in self.scan_result.get('findings', []):
            result = {
                'ruleId': finding['cve'],
                'level': self._map_severity_to_sarif_level(finding['severity']),
                'message': {
                    'text': f"{finding['package']}@{finding['version']}: {finding['description']}"
                },
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri': f"{finding['ecosystem']}/{finding['package']}/package.json"
                            }
                        }
                    }
                ],
                'properties': {
                    'package': finding['package'],
                    'installed_version': finding['version'],
                    'fixed_version': finding['recommended_version'],
                    'has_patch': finding['has_patch'],
                    'source': finding.get('source', 'unknown'),
                    'remediation_effort': finding['effort'],
                }
            }
            results.append(result)
        
        sarif = {
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'Dependency Vulnerability Mapper',
                            'version': '1.0.0',
                            'informationUri': 'https://github.com/sec-mapper',
                            'rules': []
                        }
                    },
                    'results': results,
                    'properties': {
                        'scan_date': self.timestamp,
                        'project_name': self.scan_result.get('project_name'),
                        'total_dependencies': self.scan_result.get('total_dependencies'),
                        'overall_risk_score': self.scan_result.get('risk_score'),
                    }
                }
            ]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _map_severity_to_sarif_level(self, severity: str) -> str:
        """Map our severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
        }
        return mapping.get(severity, 'note')

    def _generate_remediation_plan(self) -> List[Dict]:
        """Generate prioritized remediation steps"""
        
        findings = sorted(
            self.scan_result.get('findings', []),
            key=lambda x: {
                'critical': 0,
                'high': 1,
                'medium': 2,
                'low': 3,
            }.get(x.get('severity', 'low'))
        )
        
        plan = []
        for i, finding in enumerate(findings, 1):
            plan.append({
                'priority': i,
                'package': finding.get('package'),
                'current_version': finding.get('version'),
                'recommended_version': finding.get('fixed_version'),
                'severity': finding.get('severity'),
                'cve': finding.get('cve'),
                'estimated_effort': finding.get('effort'),
                'breaking_changes': self._check_breaking_changes(finding),
                'testing_required': self._get_testing_requirements(finding),
            })
        
        return plan
    
    def _check_breaking_changes(self, finding: Dict) -> bool:
        """Check if update would introduce breaking changes"""
        # Simplified: compare major versions
        from packaging import version
        
        current_spec = finding.get('version', '0').strip()
        fixed_spec = finding.get('fixed_version', '0').strip()
        
        # Strip npm version markers (^, ~, >, <, =)
        import re
        current_clean = re.sub(r'^[\^~>=<]+', '', current_spec)
        fixed_clean = re.sub(r'^[\^~>=<]+', '', fixed_spec)
        
        try:
            current = version.parse(current_clean)
            fixed = version.parse(fixed_clean)
            return current.major != fixed.major
        except Exception:
            return False
    
    def _get_testing_requirements(self, finding: Dict) -> List[str]:
        """Get list of testing recommendations"""
        
        requirements = []
        
        if finding.get('has_patch'):
            requirements.append('Unit tests')
            requirements.append('Integration tests')
        
        if self._check_breaking_changes(finding):
            requirements.append('Regression tests')
            requirements.append('API compatibility tests')
        
        if finding.get('effort') == 'high':
            requirements.append('Full application testing')
            requirements.append('Security testing')
        
        return requirements

    def generate_attack_graph_html(self, attack_analysis: Dict) -> str:
        """
        Generate an interactive AI-powered attack graph HTML report.
        
        This creates a cyber-security themed dashboard with:
        - D3.js force-directed graph visualization
        - Animated attack path propagation
        - AI risk assessments with confidence scores
        - Blast radius analysis
        - Interactive filtering and exploration
        
        Args:
            attack_analysis: The attack analysis dictionary from AttackPathEngine
            
        Returns:
            Complete HTML string for the interactive attack graph
        """
        import json as json_module
        
        # Extract data from analysis
        attack_paths = attack_analysis.get('attack_paths', [])
        blast_radius = attack_analysis.get('blast_radius', {})
        ai_assessments = attack_analysis.get('ai_assessments', [])
        remediation_plan = attack_analysis.get('remediation_plan', [])
        executive_summary = attack_analysis.get('executive_summary', {})
        graph_data = attack_analysis.get('graph_data', {})
        
        # Get statistics
        stats = blast_radius.get('summary', {})
        vuln_stats = stats.get('vulnerabilities', {})
        
        # Serialize graph data for JavaScript
        graph_json = json_module.dumps(graph_data)
        
        # Build attack path cards HTML
        path_cards_html = ""
        for path in attack_paths[:5]:  # Top 5 paths
            severity_class = path.get('severity', 'medium').lower()
            confidence = path.get('confidence', 0)
            risk_score = path.get('risk_score', 0)
            
            path_cards_html += f"""
            <div class="attack-path-card {severity_class}">
                <div class="path-header">
                    <div class="path-id">{path.get('path_id', 'N/A')}</div>
                    <div class="path-severity {severity_class}">{path.get('severity', 'UNKNOWN').upper()}</div>
                </div>
                <div class="path-content">
                    <div class="path-package">
                        <span class="label">Target:</span>
                        <span class="value">{path.get('vulnerable_package', 'Unknown')}</span>
                    </div>
                    <div class="path-cve">
                        <span class="label">CVE:</span>
                        <span class="value">{path.get('cve_id', 'N/A')}</span>
                    </div>
                    <div class="path-exploit">
                        <span class="label">Exploit:</span>
                        <span class="value">{path.get('exploit_type', 'Unknown')}</span>
                    </div>
                    <div class="path-impact">
                        <span class="label">Impact:</span>
                        <span class="value">{path.get('impact', 'Unknown')}</span>
                    </div>
                </div>
                <div class="path-metrics">
                    <div class="metric">
                        <span class="metric-label">Risk Score</span>
                        <span class="metric-value">{risk_score:.1f}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">AI Confidence</span>
                        <span class="metric-value">{confidence:.0f}%</span>
                    </div>
                </div>
                <div class="path-reasoning">
                    <div class="reasoning-header">AI Reasoning</div>
                    <div class="reasoning-text">{path.get('reasoning', 'No reasoning available')[:200]}...</div>
                </div>
            </div>
            """
        
        # Build AI assessment cards
        assessment_cards_html = ""
        for assessment in ai_assessments[:5]:
            severity = 'high' if assessment.get('overall_risk_score', 0) >= 70 else 'medium' if assessment.get('overall_risk_score', 0) >= 50 else 'low'
            
            assessment_cards_html += f"""
            <div class="assessment-card {severity}">
                <div class="assessment-header">
                    <div class="assessment-package">{assessment.get('package_name', 'Unknown')}</div>
                    <div class="assessment-confidence">{assessment.get('confidence', 0):.0f}% confidence</div>
                </div>
                <div class="assessment-scores">
                    <div class="score-bar">
                        <div class="score-label">Overall Risk</div>
                        <div class="score-track">
                            <div class="score-fill" style="width: {assessment.get('overall_risk_score', 0)}%"></div>
                        </div>
                        <div class="score-value">{assessment.get('overall_risk_score', 0):.1f}</div>
                    </div>
                    <div class="score-bar">
                        <div class="score-label">Exploitability</div>
                        <div class="score-track">
                            <div class="score-fill exploit" style="width: {assessment.get('exploitability_score', 0)}%"></div>
                        </div>
                        <div class="score-value">{assessment.get('exploitability_score', 0):.1f}</div>
                    </div>
                    <div class="score-bar">
                        <div class="score-label">Reachability</div>
                        <div class="score-track">
                            <div class="score-fill reach" style="width: {assessment.get('reachability_score', 0)}%"></div>
                        </div>
                        <div class="score-value">{assessment.get('reachability_score', 0):.1f}</div>
                    </div>
                </div>
                <div class="assessment-decision">
                    {"✅ FIX NOW" if assessment.get('should_fix_first') else f"⏸️ POSTPONE: {assessment.get('postpone_reason', 'Requires testing')[:50]}..."}
                </div>
            </div>
            """
        
        # Build remediation plan
        remediation_html = ""
        for item in remediation_plan[:8]:
            severity_class = 'critical' if item.get('risk_score', 0) >= 80 else 'high' if item.get('risk_score', 0) >= 60 else 'medium'
            
            remediation_html += f"""
            <div class="remediation-item {severity_class}">
                <div class="remediation-priority">#{item.get('priority', 0)}</div>
                <div class="remediation-details">
                    <div class="rem-package">{item.get('package', 'Unknown')}</div>
                    <div class="rem-versions">{item.get('current_version', '?')} → {item.get('fixed_version', '?')}</div>
                </div>
                <div class="remediation-meta">
                    <div class="rem-risk">Risk: {item.get('risk_score', 0):.1f}</div>
                    <div class="rem-effort">{item.get('effort', 'medium').upper()}</div>
                </div>
            </div>
            """
        
        # Executive summary sections
        tech_summary = executive_summary.get('technical_summary', 'No data')
        mgmt_summary = executive_summary.get('management_summary', 'No data')
        biz_impact = executive_summary.get('business_impact', 'No data')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Attack Path Intelligence Dashboard</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        :root {{
            --bg-dark: #0a0e17;
            --bg-panel: #111827;
            --bg-card: #1a2234;
            --accent-cyan: #00f0ff;
            --accent-magenta: #ff00aa;
            --accent-green: #00ff88;
            --accent-red: #ff3366;
            --accent-orange: #ff9900;
            --accent-yellow: #ffee00;
            --text-primary: #e8eaed;
            --text-secondary: #9aa0a6;
            --border-glow: rgba(0, 240, 255, 0.3);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', 'Roboto', monospace;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        /* Cyber background effect */
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at 20% 20%, rgba(0, 240, 255, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(255, 0, 170, 0.06) 0%, transparent 50%),
                linear-gradient(180deg, #0a0e17 0%, #0d1420 100%);
            pointer-events: none;
            z-index: -1;
        }}
        
        .dashboard {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 30px;
            background: linear-gradient(90deg, rgba(0,240,255,0.1) 0%, rgba(255,0,170,0.05) 100%);
            border: 1px solid var(--border-glow);
            border-radius: 12px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }}
        
        .header::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
        }}
        
        .header h1 {{
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px rgba(0, 240, 255, 0.5);
        }}
        
        .header-meta {{
            display: flex;
            gap: 30px;
            color: var(--text-secondary);
            font-size: 14px;
        }}
        
        .header-meta span {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .header-meta .value {{
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid rgba(0, 240, 255, 0.15);
            border-radius: 10px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .stat-card:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.15);
            transform: translateY(-2px);
        }}
        
        .stat-card.critical {{ border-left: 3px solid var(--accent-red); }}
        .stat-card.high {{ border-left: 3px solid var(--accent-orange); }}
        .stat-card.medium {{ border-left: 3px solid var(--accent-yellow); }}
        .stat-card.low {{ border-left: 3px solid var(--accent-green); }}
        
        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 8px;
            letter-spacing: 1px;
        }}
        
        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .stat-card.critical .stat-value {{ color: var(--accent-red); }}
        .stat-card.high .stat-value {{ color: var(--accent-orange); }}
        
        /* Main Content Grid */
        .content-grid {{
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 24px;
        }}
        
        /* Graph Container */
        .graph-container {{
            background: var(--bg-panel);
            border: 1px solid rgba(0, 240, 255, 0.15);
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }}
        
        .graph-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid rgba(0, 240, 255, 0.1);
            background: rgba(0, 0, 0, 0.3);
        }}
        
        .graph-title {{
            font-size: 16px;
            font-weight: 600;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .graph-title::before {{
            content: '◉';
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        
        .graph-filters {{
            display: flex;
            gap: 10px;
        }}
        
        .filter-btn {{
            padding: 6px 14px;
            background: rgba(0, 240, 255, 0.1);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover, .filter-btn.active {{
            background: rgba(0, 240, 255, 0.2);
            color: var(--accent-cyan);
            border-color: var(--accent-cyan);
        }}
        
        #attack-graph {{
            width: 100%;
            height: 500px;
            background: radial-gradient(ellipse at center, #0d1420 0%, #0a0e17 100%);
        }}
        
        /* Sidebar */
        .sidebar {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        
        .panel {{
            background: var(--bg-panel);
            border: 1px solid rgba(0, 240, 255, 0.15);
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .panel-header {{
            padding: 14px 18px;
            background: rgba(0, 0, 0, 0.3);
            border-bottom: 1px solid rgba(0, 240, 255, 0.1);
            font-size: 14px;
            font-weight: 600;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .panel-content {{
            padding: 16px;
            max-height: 350px;
            overflow-y: auto;
        }}
        
        .panel-content::-webkit-scrollbar {{
            width: 6px;
        }}
        
        .panel-content::-webkit-scrollbar-track {{
            background: rgba(0, 0, 0, 0.2);
        }}
        
        .panel-content::-webkit-scrollbar-thumb {{
            background: var(--accent-cyan);
            border-radius: 3px;
        }}
        
        /* Attack Path Cards */
        .attack-path-card {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 12px;
            transition: all 0.2s;
        }}
        
        .attack-path-card:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.1);
        }}
        
        .attack-path-card.critical {{ border-left: 3px solid var(--accent-red); }}
        .attack-path-card.high {{ border-left: 3px solid var(--accent-orange); }}
        
        .path-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        
        .path-id {{
            font-family: monospace;
            font-size: 12px;
            color: var(--text-secondary);
        }}
        
        .path-severity {{
            font-size: 10px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        
        .path-severity.critical {{ background: var(--accent-red); color: white; }}
        .path-severity.high {{ background: var(--accent-orange); color: white; }}
        .path-severity.medium {{ background: var(--accent-yellow); color: black; }}
        
        .path-content {{
            font-size: 13px;
            margin-bottom: 10px;
        }}
        
        .path-content .label {{
            color: var(--text-secondary);
            margin-right: 6px;
        }}
        
        .path-content .value {{
            color: var(--text-primary);
            font-weight: 500;
        }}
        
        .path-metrics {{
            display: flex;
            gap: 20px;
            padding: 10px 0;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            margin-bottom: 10px;
        }}
        
        .metric {{
            text-align: center;
        }}
        
        .metric-label {{
            font-size: 10px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        
        .metric-value {{
            font-size: 18px;
            font-weight: 700;
            color: var(--accent-cyan);
        }}
        
        .path-reasoning {{
            font-size: 12px;
            color: var(--text-secondary);
        }}
        
        .reasoning-header {{
            font-weight: 600;
            color: var(--accent-magenta);
            margin-bottom: 4px;
        }}
        
        /* Assessment Cards */
        .assessment-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 12px;
        }}
        
        .assessment-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
        }}
        
        .assessment-package {{
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .assessment-confidence {{
            font-size: 11px;
            color: var(--accent-green);
        }}
        
        .assessment-scores {{
            margin-bottom: 10px;
        }}
        
        .score-bar {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        
        .score-label {{
            font-size: 11px;
            color: var(--text-secondary);
            width: 80px;
        }}
        
        .score-track {{
            flex: 1;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            overflow: hidden;
        }}
        
        .score-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
            border-radius: 3px;
            transition: width 0.5s ease;
        }}
        
        .score-fill.exploit {{ background: linear-gradient(90deg, var(--accent-red), var(--accent-orange)); }}
        .score-fill.reach {{ background: linear-gradient(90deg, var(--accent-green), var(--accent-cyan)); }}
        
        .score-value {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-primary);
            width: 35px;
            text-align: right;
        }}
        
        .assessment-decision {{
            font-size: 12px;
            padding: 8px;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 4px;
            color: var(--accent-green);
            text-align: center;
        }}
        
        /* Remediation Items */
        .remediation-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: var(--bg-card);
            border-radius: 8px;
            margin-bottom: 8px;
            border-left: 3px solid transparent;
        }}
        
        .remediation-item.critical {{ border-left-color: var(--accent-red); }}
        .remediation-item.high {{ border-left-color: var(--accent-orange); }}
        .remediation-item.medium {{ border-left-color: var(--accent-yellow); }}
        
        .remediation-priority {{
            font-size: 14px;
            font-weight: 700;
            color: var(--accent-cyan);
            width: 30px;
        }}
        
        .remediation-details {{
            flex: 1;
        }}
        
        .rem-package {{
            font-weight: 600;
            font-size: 13px;
        }}
        
        .rem-versions {{
            font-size: 11px;
            color: var(--text-secondary);
            font-family: monospace;
        }}
        
        .remediation-meta {{
            text-align: right;
        }}
        
        .rem-risk {{
            font-size: 12px;
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        
        .rem-effort {{
            font-size: 10px;
            color: var(--text-secondary);
        }}
        
        /* Executive Summary */
        .summary-section {{
            margin-top: 24px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }}
        
        .summary-card {{
            background: var(--bg-panel);
            border: 1px solid rgba(0, 240, 255, 0.15);
            border-radius: 12px;
            padding: 20px;
        }}
        
        .summary-card h3 {{
            font-size: 14px;
            color: var(--accent-cyan);
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(0, 240, 255, 0.1);
        }}
        
        .summary-card p {{
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.6;
            white-space: pre-line;
        }}
        
        /* Graph Legend */
        .graph-legend {{
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(0, 0, 0, 0.7);
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 11px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }}
        
        .legend-item:last-child {{
            margin-bottom: 0;
        }}
        
        .legend-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }}
        
        .legend-dot.root {{ background: #4a90d9; }}
        .legend-dot.direct {{ background: #50c878; }}
        .legend-dot.transitive {{ background: #9b59b6; }}
        .legend-dot.vuln-critical {{ background: #e74c3c; }}
        .legend-dot.vuln-high {{ background: #e67e22; }}
        .legend-dot.vuln-medium {{ background: #f1c40f; }}
        .legend-dot.impact {{ background: #9b59b6; }}
        
        /* Tooltip */
        .graph-tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 1000;
            max-width: 300px;
        }}
        
        .graph-tooltip.visible {{
            opacity: 1;
        }}
        
        .tooltip-title {{
            font-weight: 600;
            color: var(--accent-cyan);
            margin-bottom: 6px;
        }}
        
        .tooltip-info {{
            color: var(--text-secondary);
        }}
        
        /* Export buttons */
        .export-btns {{
            display: flex;
            gap: 10px;
        }}
        
        .export-btn {{
            padding: 8px 16px;
            background: linear-gradient(135deg, rgba(0,240,255,0.2), rgba(255,0,170,0.1));
            border: 1px solid var(--accent-cyan);
            border-radius: 6px;
            color: var(--accent-cyan);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .export-btn:hover {{
            background: linear-gradient(135deg, rgba(0,240,255,0.3), rgba(255,0,170,0.2));
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.3);
        }}
        
        /* Node animations */
        @keyframes nodeGlow {{
            0%, 100% {{ filter: drop-shadow(0 0 5px currentColor); }}
            50% {{ filter: drop-shadow(0 0 15px currentColor); }}
        }}
        
        .node-vulnerable {{
            animation: nodeGlow 2s ease-in-out infinite;
        }}
        
        /* Responsive */
        @media (max-width: 1200px) {{
            .content-grid {{
                grid-template-columns: 1fr;
            }}
            .stats-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="dashboard">
        <!-- Header -->
        <div class="header">
            <h1>⚡ AI Attack Path Intelligence</h1>
            <div class="header-meta">
                <span>Project: <span class="value">{self.scan_result.get('project_name', 'Unknown')}</span></span>
                <span>Scan: <span class="value">{self.scan_result.get('scan_time', 'N/A')[:10]}</span></span>
                <span>Risk Score: <span class="value">{self.scan_result.get('risk_score', 0)}/100</span></span>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-label">Critical</div>
                <div class="stat-value">{vuln_stats.get('critical', 0)}</div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High</div>
                <div class="stat-value">{vuln_stats.get('high', 0)}</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-label">Medium</div>
                <div class="stat-value">{vuln_stats.get('medium', 0)}</div>
            </div>
            <div class="stat-card low">
                <div class="stat-label">Low</div>
                <div class="stat-value">{vuln_stats.get('low', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Blast Radius</div>
                <div class="stat-value">{stats.get('average_score', 0):.0f}</div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="content-grid">
            <!-- Graph Container -->
            <div class="graph-container">
                <div class="graph-header">
                    <div class="graph-title">Attack Path Visualization</div>
                    <div class="graph-filters">
                        <button class="filter-btn active" data-filter="all">All</button>
                        <button class="filter-btn" data-filter="critical">Critical</button>
                        <button class="filter-btn" data-filter="high">High</button>
                        <button class="filter-btn" data-filter="exploitable">Exploitable</button>
                    </div>
                </div>
                <div id="attack-graph"></div>
                <div class="graph-legend">
                    <div class="legend-item"><div class="legend-dot root"></div> Application Root</div>
                    <div class="legend-item"><div class="legend-dot direct"></div> Direct Dependency</div>
                    <div class="legend-item"><div class="legend-dot transitive"></div> Transitive Dependency</div>
                    <div class="legend-item"><div class="legend-dot vuln-critical"></div> Critical Vulnerability</div>
                    <div class="legend-item"><div class="legend-dot vuln-high"></div> High Vulnerability</div>
                    <div class="legend-item"><div class="legend-dot impact"></div> Potential Impact</div>
                </div>
                <div class="graph-tooltip" id="tooltip">
                    <div class="tooltip-title"></div>
                    <div class="tooltip-info"></div>
                </div>
            </div>
            
            <!-- Sidebar -->
            <div class="sidebar">
                <!-- Attack Paths Panel -->
                <div class="panel">
                    <div class="panel-header">🎯 Top Attack Paths</div>
                    <div class="panel-content">
                        {path_cards_html if path_cards_html else '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No attack paths identified</div>'}
                    </div>
                </div>
                
                <!-- AI Assessments Panel -->
                <div class="panel">
                    <div class="panel-header">🤖 AI Risk Assessments</div>
                    <div class="panel-content">
                        {assessment_cards_html if assessment_cards_html else '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No assessments available</div>'}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Remediation Plan -->
        <div class="panel" style="margin-top: 24px;">
            <div class="panel-header">🔧 AI-Optimized Remediation Plan</div>
            <div class="panel-content" style="max-height: none;">
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px;">
                    {remediation_html if remediation_html else '<div style="color: var(--text-secondary);">No remediation needed</div>'}
                </div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="summary-section">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>📊 Technical Summary</h3>
                    <p>{tech_summary}</p>
                </div>
                <div class="summary-card">
                    <h3>👔 Management Summary</h3>
                    <p>{mgmt_summary}</p>
                </div>
                <div class="summary-card">
                    <h3>💼 Business Impact</h3>
                    <p>{biz_impact}</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Graph data from analysis
        const graphData = {graph_json};
        
        // D3.js Force-Directed Graph
        const container = document.getElementById('attack-graph');
        const width = container.clientWidth;
        const height = container.clientHeight;
        
        // Color scale
        const colorScale = {{
            'root': '#4a90d9',
            'dependency': '#50c878',
            'vulnerability': '#e74c3c',
            'impact': '#9b59b6'
        }};
        
        const severityColors = {{
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f1c40f',
            'low': '#2ecc71'
        }};
        
        // Create SVG
        const svg = d3.select('#attack-graph')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        // Add glow filter
        const defs = svg.append('defs');
        const filter = defs.append('filter')
            .attr('id', 'glow');
        filter.append('feGaussianBlur')
            .attr('stdDeviation', '3')
            .attr('result', 'coloredBlur');
        const feMerge = filter.append('feMerge');
        feMerge.append('feMergeNode').attr('in', 'coloredBlur');
        feMerge.append('feMergeNode').attr('in', 'SourceGraphic');
        
        // Prepare nodes and links
        const nodes = graphData.nodes || [];
        const links = (graphData.edges || []).map(e => ({{
            source: e.source,
            target: e.target,
            type: e.type,
            animated: e.animated
        }}));
        
        // Create simulation
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(30));
        
        // Draw links
        const link = svg.append('g')
            .selectAll('line')
            .data(links)
            .enter()
            .append('line')
            .attr('stroke', d => d.type === 'exploits' ? '#e74c3c' : d.type === 'leads_to' ? '#e67e22' : '#7f8c8d')
            .attr('stroke-width', d => d.animated ? 2 : 1)
            .attr('stroke-dasharray', d => d.animated ? '5,5' : 'none')
            .attr('opacity', 0.6);
        
        // Draw nodes
        const node = svg.append('g')
            .selectAll('g')
            .data(nodes)
            .enter()
            .append('g')
            .attr('class', d => d.type === 'vulnerability' ? 'node-vulnerable' : '')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Node circles
        node.append('circle')
            .attr('r', d => d.type === 'root' ? 20 : d.type === 'vulnerability' ? 15 : 10)
            .attr('fill', d => {{
                if (d.type === 'root') return '#4a90d9';
                if (d.type === 'vulnerability') return severityColors[d.severity] || '#e74c3c';
                if (d.type === 'impact') return '#9b59b6';
                return d.is_transitive ? '#9b59b6' : '#50c878';
            }})
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .attr('filter', d => d.type === 'vulnerability' ? 'url(#glow)' : '');
        
        // Node labels
        node.append('text')
            .text(d => d.label.length > 15 ? d.label.substring(0, 12) + '...' : d.label)
            .attr('x', 0)
            .attr('y', d => (d.type === 'root' ? 25 : d.type === 'vulnerability' ? 22 : 17))
            .attr('text-anchor', 'middle')
            .attr('fill', '#9aa0a6')
            .attr('font-size', '10px');
        
        // Tooltip
        const tooltip = document.getElementById('tooltip');
        
        node.on('mouseover', function(event, d) {{
            tooltip.classList.add('visible');
            tooltip.querySelector('.tooltip-title').textContent = d.label;
            tooltip.querySelector('.tooltip-info').innerHTML = 
                `Type: ${{d.type}}<br>` +
                (d.severity ? `Severity: ${{d.severity}}<br>` : '') +
                (d.version ? `Version: ${{d.version}}<br>` : '') +
                (d.cve_id ? `CVE: ${{d.cve_id}}` : '');
            
            const rect = container.getBoundingClientRect();
            tooltip.style.left = (event.clientX - rect.left + 10) + 'px';
            tooltip.style.top = (event.clientY - rect.top + 10) + 'px';
        }})
        .on('mouseout', function() {{
            tooltip.classList.remove('visible');
        }});
        
        // Animation for attack paths
        function animateAttackPath() {{
            link.attr('stroke-dashoffset', 0)
                .transition()
                .duration(2000)
                .attr('stroke-dashoffset', -100)
                .on('end', animateAttackPath);
        }}
        
        // Start animation for animated edges
        setTimeout(animateAttackPath, 1000);
        
        // Simulation tick
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', function() {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                const filter = this.dataset.filter;
                node.style('opacity', d => {{
                    if (filter === 'all') return 1;
                    if (filter === 'critical') return d.severity === 'critical' ? 1 : 0.3;
                    if (filter === 'high') return d.severity === 'critical' || d.severity === 'high' ? 1 : 0.3;
                    if (filter === 'exploitable') return d.type === 'vulnerability' ? 1 : 0.3;
                    return 1;
                }});
            }});
        }});
        
        // Export functionality
        function exportGraph() {{
            const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(graphData));
            const downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute('href', dataStr);
            downloadAnchorNode.setAttribute('download', 'attack_graph.json');
            document.body.appendChild(downloadAnchorNode);
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        }}
    </script>
</body>
</html>
"""
        
        return html