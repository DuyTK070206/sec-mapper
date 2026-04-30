import os
import json
import logging
import requests
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


AI_CACHE_FILE = Path(__file__).resolve().parent.parent / "scan_cache" / "ai_cache.json"
AI_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load_cache() -> Dict[str, Any]:
    try:
        if AI_CACHE_FILE.exists():
            return json.loads(AI_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"[AI-CACHE-LOAD-ERROR] {e}")
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        AI_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug(f"[AI-CACHE-SAVE-ERROR] {e}")


DEFAULT_MITIGATION = {
    "summary": "No automated mitigation available; apply default containment.",
    "mitigation_steps": [
        "Sanitize and validate inputs to reduce exploit surface",
        "Disable or restrict the vulnerable feature if configurable",
        "Restrict network access and apply least-privilege ACLs",
    ],
    "config_example": "# Example: restrict access via firewall or feature flag\nfirewall_rule: deny from untrusted\nfeature_x_enabled: false",
    "risk_if_not_fixed": "Continued exposure may lead to compromise; prioritize investigation and temporary isolation.",
}


def _sanitize_for_prompt(v: Optional[str]) -> str:
    if not v:
        return "(not provided)"
    # keep short
    s = str(v).strip()
    if len(s) > 1000:
        return s[:1000] + "..."
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


def generate_mitigation(vuln: Dict) -> Dict:
    """Generate mitigation advice using an AI API (cached).

    Returns a dict with keys: summary, mitigation_steps, config_example, risk_if_not_fixed
    """
    # Expect a CVE id as primary cache key
    cve = vuln.get("vulnerability_id") or vuln.get("vulnerability") or vuln.get("cve")
    if not cve:
        # No CVE id - return default mitigation
        return DEFAULT_MITIGATION

    cache = _load_cache()
    if cve in cache:
        logger.debug(f"[AI-CACHE-HIT] {cve}")
        return cache[cve]

    # Only call AI for unfixed vulnerabilities - caller should check but enforce here too
    if vuln.get("patch_available") or vuln.get("fixed_version"):
        return DEFAULT_MITIGATION

    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Build prompt
    package = _sanitize_for_prompt(vuln.get("package"))
    version = _sanitize_for_prompt(vuln.get("version"))
    description = _sanitize_for_prompt(vuln.get("root_cause") or vuln.get("description") or vuln.get("summary"))
    exploit = vuln.get("exploitability") or {}
    exploit_text = json.dumps(exploit) if exploit else "(none)"

    messages = [
        {"role": "system", "content": "You are a security engineer that provides safe, practical mitigation steps for software vulnerabilities. Respond ONLY with a JSON object with the following keys: summary (string), mitigation_steps (array of short strings), config_example (string), risk_if_not_fixed (string). Do not include any commentary or markdown."},
        {"role": "user", "content": (
            f"Package: {package}\nVersion: {version}\nCVE: {cve}\nDescription: {description}\nExploitability: {exploit_text}\n\nProvide concise mitigation guidance in JSON as requested."
        )},
    ]

    if not api_key:
        logger.debug("[AI-SKIP] OPENAI_API_KEY not set; returning default mitigation")
        cache[cve] = DEFAULT_MITIGATION
        _save_cache(cache)
        return DEFAULT_MITIGATION

    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 800,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        content = ""
        try:
            content = data["choices"][0]["message"]["content"]
        except Exception:
            content = data.get("choices", [{}])[0].get("text", "")

        result = _extract_json_from_text(content) or json.loads(content)
        # Ensure required keys
        if not isinstance(result, dict) or not all(k in result for k in ("summary", "mitigation_steps", "config_example", "risk_if_not_fixed")):
            raise ValueError("AI returned invalid JSON structure")

        cache[cve] = result
        _save_cache(cache)
        logger.info(f"[AI-MITIGATION] Cached mitigation for {cve}")
        return result

    except Exception as e:
        logger.warning(f"[AI-ERROR] Failed to generate mitigation for {cve}: {e}")
        # Fallback to default mitigation
        cache[cve] = DEFAULT_MITIGATION
        _save_cache(cache)
        return DEFAULT_MITIGATION
