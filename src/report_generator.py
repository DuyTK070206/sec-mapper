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
        """Interactive HTML dashboard with detailed CVE information"""
        
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
                <div id="findings-container"></div>
                
                <div class="remediation">
                    <h3>Remediation Plan</h3>
                    <p>Prioritize fixes based on severity and exploitability:</p>
                    <ol id="remediation-list"></ol>
                </div>
                
                <script>
                    const findings = """ + json.dumps(self.scan_result.get('findings', [])) + """;
                    const container = document.getElementById('findings-container');
                    
                    findings.forEach((f, idx) => {
                        const div = document.createElement('div');
                        div.className = 'finding-card';
                        
                        const severity = f.severity.toLowerCase();
                        const cveLink = `https://nvd.nist.gov/vuln/detail/${f.cve}`;
                        const cveMitreLink = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${f.cve}`;
                        
                        const pocHtml = f.poc ? `
                            <div class="poc-section">
                                <div class="poc-header">Proof of Concept (PoC)</div>
                                <div class="poc-code"><code>${f.poc.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></div>
                            </div>
                        ` : '';
                        
                        div.innerHTML = `
                            <div class="finding-header ${severity}">
                                <div>
                                    <div class="finding-title">${f.package} @ ${f.version}</div>
                                    <div class="finding-meta">
                                        <div class="meta-item"><strong>CVE:</strong> ${f.cve}</div>
                                        <div class="meta-item"><span class="severity-badge ${severity}">${f.severity.toUpperCase()}</span></div>
                                        <div class="meta-item"><strong>Type:</strong> ${f.transitive ? 'Transitive' : 'Direct'}</div>
                                        <div class="meta-item"><strong>Effort:</strong> ${f.effort || 'Unknown'}</div>
                                    </div>
                                </div>
                                <button class="finding-toggle" onclick="toggleDetails(this, event)">▲</button>
                            </div>
                            <div class="finding-details">
                                <div class="description-section">
                                    <div class="label">Description</div>
                                    <div class="detail-value">${f.description || 'No description available'}</div>
                                </div>
                                
                                <div class="detail-grid">
                                    <div class="detail-item">
                                        <div class="detail-label">Current Version</div>
                                        <div class="detail-value code">${f.version}</div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">Patched Version</div>
                                        <div class="detail-value code">${f.fixed_version || 'Unknown'}</div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">Patch Status</div>
                                        <div class="detail-value">${f.has_patch ? '[OK] Available' : '[NOT AVAILABLE]'}</div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">Fix Effort</div>
                                        <div class="detail-value">${f.effort || 'Unknown'}</div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">Ecosystem</div>
                                        <div class="detail-value">${f.ecosystem || 'Unknown'}</div>
                                    </div>
                                    <div class="detail-item">
                                        <div class="detail-label">Recommended Version</div>
                                        <div class="detail-value code">${f.recommended_version || f.fixed_version || 'N/A'}</div>
                                    </div>
                                </div>
                                
                                <div class="reference-links">
                                    <a href="${cveLink}" target="_blank" class="ref-link">NVD Details</a>
                                    <a href="${cveMitreLink}" target="_blank" class="ref-link">CVE Mitre</a>
                                    <a href="${f.reference}" target="_blank" class="ref-link">Additional Reference</a>
                                </div>
                                
                                ${pocHtml}
                            </div>
                        `;
                        container.appendChild(div);
                    });
                    
                    // Remediation list
                    const list = document.getElementById('remediation-list');
                    findings.forEach(f => {
                        const item = document.createElement('li');
                        item.innerHTML = `<strong>[${f.severity.toUpperCase()}] ${f.package}</strong>: Update from ${f.version} to ${f.recommended_version} (Effort: ${f.effort})`;
                        list.appendChild(item);
                    });
                    
                    function toggleDetails(button, event) {
                        event.stopPropagation();
                        const details = button.closest('.finding-card').querySelector('.finding-details');
                        const isExpanded = details.style.display !== 'none';
                        details.style.display = isExpanded ? 'none' : 'block';
                        button.textContent = isExpanded ? '▼' : '▲';
                    }
                    
                    // Make header clickable
                    document.querySelectorAll('.finding-header').forEach(header => {
                        header.addEventListener('click', function() {{
                            if (event.target !== this.querySelector('.finding-toggle')) {{
                                this.querySelector('.finding-toggle').click();
                            }}
                        }});
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