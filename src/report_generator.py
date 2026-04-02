# report_generator.py

import json
from datetime import datetime
from typing import List, Dict

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
        """Interactive HTML dashboard"""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dependency Vulnerability Report</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI";
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    padding: 20px;
                }}
                h1 {{ color: #333; }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .card {{
                    padding: 20px;
                    border-radius: 8px;
                    background: #f9f9f9;
                    border-left: 4px solid #ddd;
                }}
                .critical {{ border-left-color: #dc3545; }}
                .high {{ border-left-color: #fd7e14; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #28a745; }}
                .score {{ font-size: 32px; font-weight: bold; }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background: #f1f1f1;
                    font-weight: 600;
                }}
                .cve-link {{
                    color: #0066cc;
                    text-decoration: none;
                }}
                .cve-link:hover {{ text-decoration: underline; }}
                .remediation {{
                    background: #e7f3ff;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 20px;
                    border-left: 4px solid #0066cc;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Dependency Vulnerability Report</h1>
                <p>Project: {self.scan_result.get('project_name')}</p>
                <p>Scan Time: {self.timestamp}</p>
                
                <div class="summary">
                    <div class="card critical">
                        <div class="label">Critical</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'critical'])}</div>
                    </div>
                    <div class="card high">
                        <div class="label">High</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'high'])}</div>
                    </div>
                    <div class="card medium">
                        <div class="label">Medium</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'medium'])}</div>
                    </div>
                    <div class="card low">
                        <div class="label">Low</div>
                        <div class="score">{len([v for v in self.scan_result.get('findings', []) if v['severity'] == 'low'])}</div>
                    </div>
                </div>
                
                <h2>Overall Risk Score: {self.scan_result.get('risk_score')}/100</h2>
                
                <h3>Detailed Findings</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Version</th>
                            <th>CVE</th>
                            <th>Severity</th>
                            <th>Patch Available</th>
                            <th>Effort</th>
                            <th>PoC</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for finding in self.scan_result.get('findings', []):
            patch = "✓ Yes" if finding.get('has_patch') else "✗ No"
            severity_class = finding['severity'].lower()
            
            poc_preview = ''
            if finding.get('poc'):
                poc_preview = finding['poc'].strip().replace('\n', ' ')[:120] + '...'

            html += f"""
                        <tr>
                            <td>{finding['package']}</td>
                            <td>{finding['version']}</td>
                            <td>
                                <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={finding['cve']}"
                                   class="cve-link" target="_blank">
                                    {finding['cve']}
                                </a>
                            </td>
                            <td><span class="{severity_class}">{finding['severity'].upper()}</span></td>
                            <td>{patch}</td>
                            <td>{finding['effort']}</td>
                            <td title="PoC snippet">{poc_preview}</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
                
                <div class="remediation">
                    <h3>Remediation Plan</h3>
                    <p>Prioritize fixes based on severity and exploitability:</p>
                    <ol id="remediation-list"></ol>
                </div>
                
                <script>
                    // Add remediation items
                    const findings = """ + json.dumps(self.scan_result.get('findings', [])) + """;
                    const list = document.getElementById('remediation-list');
                    
                    findings.forEach(f => {
                        const item = document.createElement('li');
                        item.innerHTML = `<strong>${f.package}</strong>: Update from ${f.version} to ${f.recommended_version} (Estimated effort: ${f.effort})`;
                        list.appendChild(item);
                    });
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
        
        current = version.parse(finding.get('version', '0'))
        fixed = version.parse(finding.get('fixed_version', '0'))
        
        return current.major != fixed.major
    
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