from typing import Dict, List, Optional


class RemediationEngine:
    def recommend(self, finding: Dict) -> Dict:
        fixed = finding.get("fixed_version")
        patch_available = bool(fixed)
        mitigation = self._mitigation_for(finding)

        if patch_available:
            recommendation = f"Upgrade {finding.get('package')} to {fixed}."
            status = "fixed available"
        elif mitigation:
            recommendation = mitigation
            status = "mitigation recommended"
        else:
            recommendation = "No patch currently available. Isolate component, monitor advisories, and review compensating controls."
            status = "no patch available"

        return {
            "patch_available": patch_available,
            "mitigation_available": bool(mitigation),
            "recommendation": recommendation,
            "status": status,
        }

    def _mitigation_for(self, finding: Dict) -> Optional[str]:
        vuln_type = (finding.get("vulnerability_type") or "").lower()
        if "injection" in vuln_type:
            return "Apply input validation, disable vulnerable feature paths, and deploy WAF signatures as a virtual patch."
        if "deserialization" in vuln_type:
            return "Disable unsafe deserialization paths and enforce strict type allowlists."
        if "rce" in vuln_type or "code execution" in vuln_type:
            return "Restrict runtime execution permissions and isolate service with least-privilege profiles."
        return "Pin dependency to a safer constrained version and disable optional vulnerable feature toggles if available."

    def system_state(self, findings: List[Dict]) -> Dict:
        state = {
            "vulnerable_now": 0,
            "known_fix_available": 0,
            "immediate_upgrade": 0,
            "temporary_mitigation": 0,
            "uncertain": 0,
        }
        for finding in findings:
            state["vulnerable_now"] += 1
            if finding.get("patch_available"):
                state["known_fix_available"] += 1
            if finding.get("severity") in {"critical", "high"} and finding.get("patch_available"):
                state["immediate_upgrade"] += 1
            if finding.get("mitigation_available") and not finding.get("patch_available"):
                state["temporary_mitigation"] += 1
            if finding.get("confidence") in {"uncertain", "heuristic"}:
                state["uncertain"] += 1
        return state
