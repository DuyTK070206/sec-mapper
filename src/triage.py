from collections import defaultdict
from typing import Dict, List


class AITriageEngine:
    """Deterministic-first triage with AI-ready hooks for future RAG models."""

    def cluster_duplicates(self, findings: List[Dict]) -> List[Dict]:
        grouped = defaultdict(list)
        for finding in findings:
            key = finding.get("package", "").lower()
            grouped[key].append(finding)

        deduped: List[Dict] = []
        for _, items in grouped.items():
            if len(items) == 1:
                deduped.append(items[0])
                continue
            # Sort by severity and risk_score
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            items.sort(key=lambda f: (severity_order.get(f.get("severity", "unknown").lower(), 4), -f.get("risk_score", 0)))
            base = dict(items[0])
            # Collect all vulnerabilities
            all_vulns = []
            sources = set(base.get("advisory_sources", []))
            evidences = list(base.get("evidence", []))
            max_risk = 0
            for item in items:
                vuln_info = {
                    "id": item.get("vulnerability_id", item.get("cve", "unknown")),
                    "severity": item.get("severity", "unknown"),
                    "fixed_version": item.get("fixed_version"),
                    "description": item.get("root_cause", "")[:100] + "..." if len(item.get("root_cause", "")) > 100 else item.get("root_cause", ""),
                }
                all_vulns.append(vuln_info)
                max_risk = max(max_risk, item.get("risk_score", 0))
                for src in item.get("advisory_sources", []):
                    sources.add(src)
                evidences.extend(item.get("evidence", []))
            base["vulnerabilities"] = all_vulns[:5]  # Limit to top 5
            base["advisory_sources"] = sorted(sources)
            base["evidence"] = sorted(set(evidences))
            base["risk_score"] = max_risk  # Use highest risk
            base["triage_summary"] = f"Grouped {len(items)} vulnerabilities for {base.get('package')}"
            deduped.append(base)
        return deduped

    def enrich(self, finding: Dict) -> Dict:
        out = dict(finding)
        out["triage_summary"] = self._explain(out)
        if out.get("confidence_score", 0.0) < 0.45:
            out["status"] = "low confidence / unverifiable"
        elif out.get("patch_available"):
            out["status"] = "fixed available"
        elif out.get("mitigation_available"):
            out["status"] = "mitigation recommended"
        else:
            out["status"] = "needs manual review"
        return out

    def _explain(self, finding: Dict) -> str:
        score = finding.get("confidence_score", 0.0)
        path = finding.get("dependency_path") or []
        sources = ", ".join(finding.get("advisory_sources", [])) or "single-source"
        if score >= 0.8:
            confidence = "likely real"
        elif score >= 0.55:
            confidence = "probable"
        elif score >= 0.35:
            confidence = "uncertain"
        else:
            confidence = "likely false positive"
        return f"Triage: {confidence}; confidence={score:.2f}; path_depth={len(path)}; provenance={sources}."
