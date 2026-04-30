import os
import json
import logging
import requests
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

AI_ANALYSIS_CACHE_FILE = Path(__file__).resolve().parent.parent / "scan_cache" / "ai_analysis_cache.json"
AI_ANALYSIS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

def _load_analysis_cache() -> Dict[str, Any]:
    try:
        if AI_ANALYSIS_CACHE_FILE.exists():
            return json.loads(AI_ANALYSIS_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"[AI-ANALYSIS-CACHE-LOAD-ERROR] {e}")
    return {}

def _save_analysis_cache(cache: Dict[str, Any]) -> None:
    try:
        AI_ANALYSIS_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug(f"[AI-ANALYSIS-CACHE-SAVE-ERROR] {e}")

def _sanitize_for_prompt(v: Optional[str]) -> str:
    if not v:
        return "(not provided)"
    # keep reasonably short for analysis
    s = str(v).strip()
    if len(s) > 2000:
        return s[:2000] + "..."
    return s

def _extract_json_from_text(text: str) -> Optional[Dict]:
    """Try to extract a JSON object from text response."""
    import re

    # Look for a JSON object block
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def generate_ai_analysis(finding: Dict) -> Dict:
    """Generate comprehensive AI analysis for a vulnerability finding.

    Returns a dict with keys: impact_analysis, attack_scenario, mitigation_strategy, risk_assessment
    """
    # Use vulnerability_id as primary cache key
    vuln_id = finding.get("vulnerability_id") or finding.get("cve")
    if not vuln_id:
        return {
            "impact_analysis": "Unable to analyze - no vulnerability ID provided",
            "attack_scenario": "Unknown attack vectors",
            "mitigation_strategy": "Review vulnerability details manually",
            "risk_assessment": "Unable to assess without vulnerability identifier"
        }

    cache = _load_analysis_cache()
    if vuln_id in cache:
        logger.debug(f"[AI-ANALYSIS-CACHE-HIT] {vuln_id}")
        return cache[vuln_id]

    # Check if AI mode is enabled
    ai_mode = os.getenv("AI_MODE", "false").lower() in ("true", "1", "yes", "on")
    if not ai_mode:
        logger.debug("[AI-ANALYSIS-SKIP] AI_MODE not enabled")
        return {
            "impact_analysis": "AI analysis disabled",
            "attack_scenario": "AI analysis disabled",
            "mitigation_strategy": "AI analysis disabled",
            "risk_assessment": "AI analysis disabled"
        }

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.debug("[AI-ANALYSIS-SKIP] OPENAI_API_KEY not set")
        return {
            "impact_analysis": "OpenAI API key not configured",
            "attack_scenario": "OpenAI API key not configured",
            "mitigation_strategy": "OpenAI API key not configured",
            "risk_assessment": "OpenAI API key not configured"
        }

    # Build comprehensive prompt for analysis
    package = _sanitize_for_prompt(finding.get("package"))
    version = _sanitize_for_prompt(finding.get("version"))
    ecosystem = _sanitize_for_prompt(finding.get("ecosystem"))
    severity = _sanitize_for_prompt(finding.get("severity"))
    description = _sanitize_for_prompt(finding.get("root_cause") or finding.get("description"))
    vuln_type = _sanitize_for_prompt(finding.get("vulnerability_type"))
    cwe = finding.get("cwe", [])
    cwe_text = ", ".join(cwe) if cwe else "(none)"
    fixed_version = _sanitize_for_prompt(finding.get("fixed_version"))
    exploit_info = finding.get("exploitability", {})
    exploit_text = json.dumps(exploit_info) if exploit_info else "(none)"

    has_fixed_version = bool(fixed_version and fixed_version != "N/A")

    messages = [
        {"role": "system", "content": "You are a cybersecurity expert analyzing software vulnerabilities. Provide detailed, actionable analysis in JSON format only. Respond with a JSON object containing exactly these keys: impact_analysis (string), attack_scenario (string), mitigation_strategy (string), risk_assessment (string). Be specific, technical, and practical."},
        {"role": "user", "content": f"""
Vulnerability Analysis Request:

Package: {package}
Ecosystem: {ecosystem}
Current Version: {version}
Vulnerability ID: {vuln_id}
Severity: {severity}
Vulnerability Type: {vuln_type}
CWE IDs: {cwe_text}
Description: {description}
Exploitability Info: {exploit_text}
Fixed Version Available: {"Yes - " + fixed_version if has_fixed_version else "No"}

Provide comprehensive analysis covering:
1. Impact Analysis: Explain the potential impact on systems, data, and users
2. Attack Scenario: Describe realistic attack vectors and exploitation methods
3. Mitigation Strategy: Provide specific steps to mitigate the risk
4. Risk Assessment: Evaluate overall risk level and urgency

{"IMPORTANT: Since no fixed version exists, focus mitigation on temporary workarounds, configuration changes, and containment strategies." if not has_fixed_version else "Include both short-term mitigation and long-term fix planning."}

Respond ONLY with JSON object, no additional text.
"""},
    ]

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1200,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        content = ""
        try:
            content = data["choices"][0]["message"]["content"]
        except Exception:
            content = data.get("choices", [{}])[0].get("text", "")

        result = _extract_json_from_text(content) or json.loads(content)

        # Validate required keys
        required_keys = ["impact_analysis", "attack_scenario", "mitigation_strategy", "risk_assessment"]
        if not isinstance(result, dict) or not all(k in result for k in required_keys):
            raise ValueError("AI returned invalid JSON structure")

        # Ensure all values are strings
        for key in required_keys:
            if not isinstance(result[key], str):
                result[key] = str(result[key])

        cache[vuln_id] = result
        _save_analysis_cache(cache)
        logger.info(f"[AI-ANALYSIS] Cached analysis for {vuln_id}")
        return result

    except Exception as e:
        logger.warning(f"[AI-ANALYSIS-ERROR] Failed to generate analysis for {vuln_id}: {e}")
        # Return safe fallback
        severity = finding.get("severity", "unknown")
        fallback = {
            "impact_analysis": f"Unable to generate AI analysis due to error: {str(e)}",
            "attack_scenario": "Analysis unavailable - review vulnerability description manually",
            "mitigation_strategy": "Follow standard security practices and vendor guidance",
            "risk_assessment": f"Risk level: {severity.upper() if severity else 'UNKNOWN'} - manual review required"
        }
        cache[vuln_id] = fallback
        _save_analysis_cache(cache)
        return fallback