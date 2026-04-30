import html as html_module
import json
from datetime import datetime
from typing import Dict, List
from urllib.parse import quote_plus


class ReportGenerator:
    def __init__(self, scan_result: Dict):
        self.scan_result = scan_result
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def generate_json_report(self) -> str:
        report = {
            "metadata": {
                "scan_time": self.timestamp,
                "project": self.scan_result.get("project_name"),
                "tool_version": "2.0.0",
                "schema": "sec-mapper-json-v2",
                "scan_targets": self.scan_result.get("scan_targets", []),
            },
            "summary": self._summary(),
            "scan_health": self.scan_result.get("scan_health", {}),
            "findings": self.scan_result.get("findings", []),
            "remediation_plan": self._generate_remediation_plan(),
            "post_scan_system_state": self.scan_result.get("scan_health", {}).get("post_scan_system_state", {}),
        }
        return json.dumps(report, indent=2)

    def generate_api_report(self) -> str:
        payload = {
            "api_version": "v1",
            "kind": "sec-mapper-scan-result",
            "generated_at": self.timestamp,
            "project": self.scan_result.get("project_name"),
            "risk_score": self.scan_result.get("risk_score", 0),
            "summary": self._summary(),
            "health": self.scan_result.get("scan_health", {}),
            "findings": self.scan_result.get("findings", []),
            "scan_targets": self.scan_result.get("scan_targets", []),
        }
        return json.dumps(payload, indent=2)

    def generate_html_report(self) -> str:
        findings = self.scan_result.get("findings", [])
        # Sort findings by severity (critical, high, medium, low) and confidence_score desc
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_sorted = sorted(
            findings,
            key=lambda f: (
                severity_order.get((f.get("severity") or "unknown").lower(), 4),
                -float(f.get("confidence_score", 0) or 0),
            ),
        )
        # Assign remediation priority
        for idx, f in enumerate(findings_sorted, 1):
            try:
                f["remediation_priority"] = int(f.get("remediation_priority") or idx)
            except Exception:
                f["remediation_priority"] = idx

        findings_html = "\n".join([self._finding_card_html(f) for f in findings_sorted])
        severity = self._severity_counts(findings)
        post = self.scan_result.get("scan_health", {}).get("post_scan_system_state", {})
        discrepancy_count = self.scan_result.get("scan_health", {}).get("discrepancy_count", 0)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Sec Mapper Report</title>
    <style>
        body {{ font-family: Segoe UI, Tahoma, sans-serif; margin: 0; background: #f2f4f7; color: #111827; }}
        .container {{ max-width: 1280px; margin: 24px auto; background: #ffffff; border-radius: 12px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }}
        .card {{ padding: 14px; border-radius: 10px; background: #eef2ff; }}
        .finding-card {{ border: 1px solid #d1d5db; border-radius: 10px; margin-bottom: 14px; overflow: hidden; }}
        .finding-header {{ padding: 12px 14px; background: #f9fafb; border-left: 4px solid #6b7280; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
        .finding-header.critical {{ border-left-color: #b91c1c; }}
        .finding-header.high {{ border-left-color: #dc2626; }}
        .finding-header.medium {{ border-left-color: #d97706; }}
        .finding-header.low {{ border-left-color: #059669; }}
        .finding-details {{ padding: 14px; }}
        .badge {{ padding: 2px 8px; border-radius: 999px; font-size: 12px; background: #e5e7eb; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; margin-top: 10px; }}
        .kv {{ background: #f9fafb; border-radius: 8px; padding: 10px; }}
        .label {{ font-size: 11px; text-transform: uppercase; color: #6b7280; margin-bottom: 4px; }}
        .value {{ font-size: 14px; line-height: 1.35; word-break: break-word; }}
        .mono {{ font-family: Consolas, monospace; }}
        .section-title {{ margin-top: 24px; }}
        ul {{ margin: 6px 0 0 18px; }}
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Dependency Vulnerability Report</h1>
        <p><strong>Project:</strong> {html_module.escape(str(self.scan_result.get('project_name', 'unknown')))}</p>
        <p><strong>Scan Time:</strong> {html_module.escape(self.timestamp)}</p>
        <p><strong>Risk Score:</strong> {self.scan_result.get('risk_score', 0)}/100</p>

        <div class=\"summary\">
            <div class=\"card\"><div class=\"label\">Critical</div><div class=\"value\">{severity['critical']}</div></div>
            <div class=\"card\"><div class=\"label\">High</div><div class=\"value\">{severity['high']}</div></div>
            <div class=\"card\"><div class=\"label\">Medium</div><div class=\"value\">{severity['medium']}</div></div>
            <div class=\"card\"><div class=\"label\">Low</div><div class=\"value\">{severity['low']}</div></div>
            <div class=\"card\"><div class=\"label\">Discrepancies</div><div class=\"value\">{discrepancy_count}</div></div>
        </div>

        <h2 class=\"section-title\">Post-Scan System State</h2>
        <div class=\"grid\">
            <div class=\"kv\"><div class=\"label\">Vulnerable Right Now</div><div class=\"value\">{post.get('vulnerable_now', 0)}</div></div>
            <div class=\"kv\"><div class=\"label\">Known Fix Available</div><div class=\"value\">{post.get('known_fix_available', 0)}</div></div>
            <div class=\"kv\"><div class=\"label\">Needs Immediate Upgrade</div><div class=\"value\">{post.get('immediate_upgrade', 0)}</div></div>
            <div class=\"kv\"><div class=\"label\">Temporary Mitigation</div><div class=\"value\">{post.get('temporary_mitigation', 0)}</div></div>
            <div class=\"kv\"><div class=\"label\">Uncertain</div><div class=\"value\">{post.get('uncertain', 0)}</div></div>
        </div>

        <h2 class=\"section-title\">Findings</h2>
        {findings_html}
    </div>

    <script>
        function toggleCard(btn) {{
            const details = btn.closest('.finding-card').querySelector('.finding-details');
            const hidden = details.style.display === 'none';
            details.style.display = hidden ? 'block' : 'none';
            btn.textContent = hidden ? 'Hide' : 'Show';
        }}

        function toggleMitigation(id) {{
            const el = document.getElementById(id + '-pre');
            if (!el) return;
            el.style.display = (el.style.display === 'none' || el.style.display === '') ? 'block' : 'none';
        }}

        function copyText(elemId) {{
            const el = document.getElementById(elemId);
            if (!el) return;
            const text = el.innerText || el.textContent || '';
            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(text).catch(() => alert('Copy failed'));
            }} else {{
                // Fallback
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                try {{ document.execCommand('copy'); }} catch (e) {{ alert('Copy failed'); }}
                ta.remove();
            }}
        }}
    </script>
</body>
</html>
"""
        return html

    def _finding_card_html(self, finding: Dict) -> str:
        cve_id = finding.get("vulnerability_id", finding.get("cve", ""))
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{quote_plus(cve_id)}" if cve_id else "#"
        mitre_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={quote_plus(cve_id)}" if cve_id else "#"
        refs = finding.get("references", [])
        # Support references that may be dicts (from various sources) - extract a URL or stringify
        def _ref_to_str(r):
            if isinstance(r, dict):
                return r.get("url") or r.get("reference") or json.dumps(r)
            return str(r)

        refs_html = "".join(
            [
                f"<li><a href=\"{html_module.escape(_ref_to_str(r))}\" target=\"_blank\" rel=\"noopener noreferrer\">{html_module.escape(_ref_to_str(r))}</a></li>"
                for r in refs
                if r
            ]
        )
        path = " > ".join(finding.get("dependency_path", []))
        evidence_html = "".join([f"<li>{html_module.escape(x)}</li>" for x in finding.get("evidence", [])])
        source_list = ", ".join(finding.get("advisory_sources", []))
        mit_id = quote_plus(cve_id or finding.get('title', 'mitigation'))

        return f"""
<div class=\"finding-card\">
    <div class=\"finding-header {html_module.escape((finding.get('severity') or 'unknown').lower())}\">
        <div>
            <strong>{html_module.escape(finding.get('title', 'Vulnerability'))}</strong>
                            <span class=\"badge\">PRIO {html_module.escape(str(finding.get('remediation_priority') or ''))}</span>
                            <span class=\"badge\">{html_module.escape(str(finding.get('fix_priority') or ''))}</span>
                            <span class=\"badge\">{html_module.escape((finding.get('severity') or 'low').upper())}</span>
                            <span class=\"badge\">Risk {html_module.escape(str(finding.get('risk_score', 0)))}/100</span>
                            <span class=\"badge\">{html_module.escape(finding.get('confidence', 'unknown'))}</span>
                            <span class=\"badge\">{html_module.escape(finding.get('status', 'unknown'))}</span>
        </div>
        <div class="exploit-summary" style="font-size:12px; color:#374151; margin-top:6px;">
            Exploit: {html_module.escape(finding.get('exploitability', {}).get('impact', 'Unknown'))} | PoC: {('Yes' if finding.get('exploitability', {}).get('poc') else 'No')} | Exploit Score: {finding.get('exploitability', {}).get('exploitability_score', 0.0):.2f}
        </div>
            <div class="mitigation-controls" style="margin-left:8px;">
                <button onclick="toggleMitigation('{mit_id}')">Show Mitigation</button>
                <button onclick="copyText('{mit_id}-pre')">Copy Mitigation</button>
                <pre id="{mit_id}-pre" style="display:none; background:#f8fafc; padding:8px; border-radius:6px; overflow:auto; max-height:240px;">{html_module.escape(json.dumps(finding.get('ai_mitigation', {}) or {}, indent=2))}</pre>
            </div>
        <button onclick=\"toggleCard(this)\">Hide</button>
    </div>
    <div class=\"finding-details\">
        <div class=\"grid\">
            <div class=\"kv\"><div class=\"label\">Package</div><div class=\"value mono\">{html_module.escape(finding.get('package', ''))}</div></div>
            <div class=\"kv\"><div class=\"label\">Ecosystem</div><div class=\"value\">{html_module.escape(finding.get('ecosystem', ''))}</div></div>
            <div class=\"kv\"><div class=\"label\">Current Version</div><div class=\"value mono\">{html_module.escape(finding.get('version', ''))}</div></div>
            <div class=\"kv\"><div class=\"label\">Fixed Version</div><div class=\"value mono\">{html_module.escape(str(finding.get('fixed_version') or 'N/A'))}</div></div>
            <div class=\"kv\"><div class=\"label\">Vulnerability ID</div><div class=\"value mono\">{html_module.escape(cve_id)}</div></div>
            <div class=\"kv\"><div class=\"label\">Vulnerability Type</div><div class=\"value\">{html_module.escape(finding.get('vulnerability_type', ''))}</div></div>
            <div class=\"kv\"><div class=\"label\">Confidence Score</div><div class=\"value\">{finding.get('confidence_score', 0):.2f}</div></div>
            <div class=\"kv\"><div class=\"label\">Dependency Path</div><div class=\"value mono\">{html_module.escape(path)}</div></div>
            <div class=\"kv\"><div class=\"label\">Patch Availability</div><div class=\"value\">{'Yes' if finding.get('patch_available') else 'No'}</div></div>
            <div class=\"kv\"><div class=\"label\">Mitigation Availability</div><div class=\"value\">{'Yes' if finding.get('mitigation_available') else 'No'}</div></div>
            <div class=\"kv\"><div class=\"label\">Provenance</div><div class=\"value\">{html_module.escape(source_list)}</div></div>
            <div class=\"kv\"><div class=\"label\">Recommendation</div><div class=\"value\">{html_module.escape(finding.get('remediation_recommendation', ''))}</div></div>
        </div>

        <div class=\"kv\"><div class=\"label\">Root Cause Explanation</div><div class=\"value\">{html_module.escape(finding.get('root_cause', finding.get('description', '')))}</div></div>
        <div class=\"kv\"><div class=\"label\">Evidence</div><ul>{evidence_html or '<li>No direct evidence provided</li>'}</ul></div>
        
        <div class=\"kv\"><div class=\"label\">AI Risk Analysis</div>
            <div class=\"value\">
                <div style=\"margin-bottom: 8px;\"><strong>Impact Analysis:</strong> {html_module.escape(finding.get('ai_analysis', {}).get('impact_analysis', 'Not available'))}</div>
                <div style=\"margin-bottom: 8px;\"><strong>Attack Scenario:</strong> {html_module.escape(finding.get('ai_analysis', {}).get('attack_scenario', 'Not available'))}</div>
                <div style=\"margin-bottom: 8px;\"><strong>Mitigation Strategy:</strong> {html_module.escape(finding.get('ai_analysis', {}).get('mitigation_strategy', 'Not available'))}</div>
                <div><strong>Risk Assessment:</strong> {html_module.escape(finding.get('ai_analysis', {}).get('risk_assessment', 'Not available'))}</div>
            </div>
        </div>
        
        <div class=\"kv\"><div class=\"label\">References</div><ul>{refs_html or '<li>No references</li>'}</ul>
            <div class=\"value\">Additional Reference</div>
            <div class=\"value\"><a href=\"{nvd_link}\" target=\"_blank\">NVD</a> | <a href=\"{mitre_link}\" target=\"_blank\">MITRE</a></div>
        </div>
    </div>
</div>
"""

    def generate_sarif_report(self) -> str:
        rules = []
        results = []
        seen_rules = set()

        for finding in self.scan_result.get("findings", []):
            vuln_id = finding.get("vulnerability_id", finding.get("cve", "UNKNOWN"))
            if vuln_id not in seen_rules:
                seen_rules.add(vuln_id)
                rules.append(
                    {
                        "id": vuln_id,
                        "name": finding.get("title", vuln_id),
                        "shortDescription": {"text": finding.get("vulnerability_type", "Dependency Vulnerability")},
                        "fullDescription": {"text": finding.get("root_cause", finding.get("description", ""))},
                        "properties": {
                            "tags": [finding.get("ecosystem", "unknown"), finding.get("severity", "unknown")],
                            "precision": "high" if finding.get("confidence_score", 0) >= 0.8 else "medium",
                        },
                    }
                )

            results.append(
                {
                    "ruleId": vuln_id,
                    "level": self._map_severity_to_sarif_level(finding.get("severity", "unknown")),
                    "message": {
                        "text": f"{finding.get('package')}@{finding.get('version')} {vuln_id}: {finding.get('root_cause', finding.get('description', ''))}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.get("source", "manifest")},
                            }
                        }
                    ],
                    "properties": {
                        "package": finding.get("package"),
                        "installed_version": finding.get("version"),
                        "fixed_version": finding.get("fixed_version"),
                        "dependency_path": finding.get("dependency_path", []),
                        "confidence": finding.get("confidence"),
                        "confidence_score": finding.get("confidence_score"),
                        "status": finding.get("status"),
                        "mitigation_available": finding.get("mitigation_available"),
                        "advisory_sources": finding.get("advisory_sources", []),
                    },
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sec Mapper",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/sec-mapper",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "scan_date": self.timestamp,
                        "project_name": self.scan_result.get("project_name"),
                        "total_dependencies": self.scan_result.get("total_dependencies"),
                        "overall_risk_score": self.scan_result.get("risk_score"),
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _map_severity_to_sarif_level(self, severity: str) -> str:
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }
        return mapping.get((severity or "unknown").lower(), "warning")

    def _severity_counts(self, findings: List[Dict]) -> Dict[str, int]:
        return {
            "critical": len([f for f in findings if (f.get("severity") or "").lower() == "critical"]),
            "high": len([f for f in findings if (f.get("severity") or "").lower() == "high"]),
            "medium": len([f for f in findings if (f.get("severity") or "").lower() == "medium"]),
            "low": len([f for f in findings if (f.get("severity") or "").lower() == "low"]),
        }

    def _summary(self) -> Dict:
        findings = self.scan_result.get("findings", [])
        return {
            "total_dependencies": self.scan_result.get("total_dependencies"),
            "direct_dependencies": self.scan_result.get("direct_dependencies"),
            "transitive_dependencies": self.scan_result.get("transitive_dependencies"),
            "vulnerabilities": self._severity_counts(findings),
            "overall_risk_score": self.scan_result.get("risk_score"),
            "confidence": {
                "exact_version_match": len([f for f in findings if f.get("confidence") == "exact version match"]),
                "advisory_backed": len([f for f in findings if f.get("confidence") == "advisory-backed match"]),
                "heuristic": len([f for f in findings if f.get("confidence") == "heuristic match"]),
                "uncertain": len([f for f in findings if f.get("confidence") == "uncertain match requiring review"]),
            },
        }

    def _generate_remediation_plan(self) -> List[Dict]:
        findings = sorted(
            self.scan_result.get("findings", []),
            key=lambda x: {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
            }.get((x.get("severity") or "unknown").lower(), 4),
        )
        plan = []
        for i, finding in enumerate(findings, 1):
            plan.append(
                {
                    "priority": i,
                    "package": finding.get("package"),
                    "current_version": finding.get("version"),
                    "recommended_version": finding.get("fixed_version"),
                    "severity": finding.get("severity"),
                    "vulnerability_id": finding.get("vulnerability_id", finding.get("cve")),
                    "status": finding.get("status"),
                    "recommendation": finding.get("remediation_recommendation"),
                    "dependency_path": finding.get("dependency_path", []),
                }
            )
        return plan
