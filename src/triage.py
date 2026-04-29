from collections import defaultdict
from typing import Dict, List


class AITriageEngine:
    """Deterministic-first triage with AI-ready hooks for future RAG models."""

    def cluster_duplicates(self, findings: List[Dict]) -> List[Dict]:
        grouped = defaultdict(list)
        for finding in findings:
            key = (
                finding.get("package", "").lower(),
                finding.get("vulnerability_id", finding.get("cve", "")),
                finding.get("fixed_version", ""),
            )
            grouped[key].append(finding)

        deduped: List[Dict] = []
        for _, items in grouped.items():
            if len(items) == 1:
                deduped.append(items[0])
                continue
            base = dict(items[0])
            all_paths: List[List[str]] = []
            sources = set(base.get("advisory_sources", []))
            evidences = list(base.get("evidence", []))
            for item in items:
                if item.get("dependency_path"):
                    all_paths.append(item["dependency_path"])
                for src in item.get("advisory_sources", []):
                    sources.add(src)
                evidences.extend(item.get("evidence", []))
            base["dependency_paths"] = all_paths or [base.get("dependency_path", [])]
            base["advisory_sources"] = sorted(sources)
            base["evidence"] = sorted(set(evidences))
            base["triage_summary"] = self._explain(base)
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
