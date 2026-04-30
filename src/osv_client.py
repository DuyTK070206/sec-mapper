"""
OSV (Open Source Vulnerabilities) API Client
Provides secure vulnerability data directly from the OSV database
https://api.osv.dev/v1/query
"""

import json
import requests
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class OSVClient:
    """Client for querying the OSV API for vulnerability information."""

    BASE_URL = "https://api.osv.dev/v1/query"
    CACHE_DURATION = 24 * 3600  # 24 hours in seconds
    REQUEST_TIMEOUT = 15  # seconds
    MAX_RETRIES = 2

    # Map ecosystems to OSV-compatible names
    ECOSYSTEM_MAP = {
        'npm': 'npm',
        'pip': 'PyPI',
        'pypi': 'PyPI',
        'maven': 'Maven',
    }

    def __init__(self, cache_dir: Optional[Path] = None, use_cache: bool = True):
        """
        Initialize OSV Client.
        
        Args:
            cache_dir: Directory to store cached responses. If None, uses scan_cache/
            use_cache: Whether to use caching for API responses
        """
        if cache_dir is None:
            cache_dir = Path(__file__).resolve().parent.parent / "scan_cache"
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.use_cache = use_cache
        self._cache = {}  # In-memory cache for current session

    def query(self, package_name: str, ecosystem: str, version: str) -> List[Dict]:
        """
        Query OSV API for vulnerabilities affecting a specific package version.
        
        Args:
            package_name: Package name (e.g., 'lodash', 'qs')
            ecosystem: Package ecosystem (npm, pip, maven, etc.)
            version: Package version (e.g., '4.17.19')
        
        Returns:
            List of vulnerability dictionaries from OSV API, or empty list on error
        """
        # Normalize inputs
        package_name = package_name.strip().lower()
        ecosystem = ecosystem.strip().lower()
        version = version.strip()

        # Create cache key
        cache_key = f"{package_name}:{version}"

        # Check in-memory cache first (fast, within session)
        if cache_key in self._cache:
            logger.debug(f"[CACHE-HIT] {package_name}@{version}")
            return self._cache[cache_key]

        # Check file-based cache (persistent across sessions)
        if self.use_cache:
            cached_result = self._load_from_cache(cache_key)
            if cached_result is not None:
                logger.debug(f"[CACHE-FILE] {package_name}@{version}")
                self._cache[cache_key] = cached_result
                return cached_result

        # Query OSV API
        logger.debug(f"[QUERY] Querying OSV API for {package_name}@{version} ({ecosystem})")
        vulns = self._query_osv_api(package_name, ecosystem, version)

        # Cache the result (even if empty, to avoid repeated queries)
        self._cache[cache_key] = vulns
        if self.use_cache:
            self._save_to_cache(cache_key, vulns)

        return vulns

    def _query_osv_api(self, package_name: str, ecosystem: str, version: str) -> List[Dict]:
        """
        Make the actual HTTP request to OSV API with retries.
        
        Returns:
            List of vulnerability dictionaries, or empty list on error
        """
        # Map to OSV ecosystem name
        osv_ecosystem = self.ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            },
            "version": version,
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                logger.debug(f"[ATTEMPT {attempt + 1}/{self.MAX_RETRIES}] Querying OSV API...")
                response = requests.post(
                    self.BASE_URL,
                    json=payload,
                    timeout=self.REQUEST_TIMEOUT,
                    headers={"Content-Type": "application/json"},
                )

                response.raise_for_status()
                data = response.json()

                vulns = data.get("vulns", [])
                
                # Log findings
                if vulns:
                    for vuln in vulns:
                        cve_id = self._extract_cve_id(vuln)
                        logger.info(f"[FOUND] {package_name}@{version} → {cve_id}")
                
                return vulns

            except requests.exceptions.Timeout:
                logger.warning(f"[TIMEOUT] OSV API request timed out for {package_name}@{version} (attempt {attempt + 1})")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"[CONNECTION-ERROR] Failed to connect to OSV API for {package_name}@{version}: {e}")
            except requests.exceptions.HTTPError as e:
                if response.status_code == 404:
                    logger.debug(f"[NOT-FOUND] {package_name}@{version} not in OSV database")
                else:
                    logger.warning(f"[HTTP-ERROR] OSV API returned {response.status_code} for {package_name}@{version}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"[PARSE-ERROR] Failed to parse OSV API response: {e}")
            except Exception as e:
                logger.warning(f"[ERROR] Unexpected error querying OSV API: {type(e).__name__}: {e}")

        logger.warning(f"[FAILED] Failed to get vulnerabilities for {package_name}@{version} after {self.MAX_RETRIES} attempts")
        return []

    @staticmethod
    def _extract_cve_id(vuln: Dict) -> str:
        """Extract CVE ID from vulnerability record."""
        # Try to find CVE in aliases first (most common)
        if "aliases" in vuln:
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    return alias
        
        # Fall back to ID field
        return vuln.get("id", "UNKNOWN")

    def _load_from_cache(self, cache_key: str) -> Optional[List[Dict]]:
        """Load cached vulnerability data from file."""
        cache_file = self.cache_dir / f"{cache_key.replace(':', '_')}.json"
        
        if not cache_file.exists():
            return None

        try:
            stat = cache_file.stat()
            age = (datetime.now().timestamp() - stat.st_mtime)
            
            # Check if cache is still valid
            if age > self.CACHE_DURATION:
                logger.debug(f"[CACHE-EXPIRED] {cache_key}")
                return None
            
            with cache_file.open() as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"[CACHE-ERROR] Failed to read cache for {cache_key}: {e}")
            return None

    def _save_to_cache(self, cache_key: str, vulns: List[Dict]) -> None:
        """Save vulnerability data to cache file."""
        cache_file = self.cache_dir / f"{cache_key.replace(':', '_')}.json"
        
        try:
            with cache_file.open('w') as f:
                json.dump(vulns, f, indent=2)
        except Exception as e:
            logger.warning(f"[CACHE-WRITE-ERROR] Failed to write cache for {cache_key}: {e}")

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            logger.info("[CACHE-CLEARED] All OSV cache cleared")
        except Exception as e:
            logger.warning(f"[CACHE-CLEAR-ERROR] Failed to clear cache: {e}")

    def get_cache_stats(self) -> Dict:
        """Get statistics about cached items."""
        return {
            "in_memory_cache_size": len(self._cache),
            "cache_directory": str(self.cache_dir),
            "cache_enabled": self.use_cache,
        }


class OSVVulnerabilityConverter:
    """Convert OSV API responses to internal vulnerability format."""

    @staticmethod
    def convert(osv_vuln: Dict, package_name: str, ecosystem: str, version: str) -> Dict:
        """
        Convert OSV vulnerability record to internal format.
        
        Args:
            osv_vuln: Vulnerability record from OSV API
            package_name: Package name
            ecosystem: Package ecosystem
            version: Package version
        
        Returns:
            Normalized vulnerability dictionary
        """
        cve_id = OSVClient._extract_cve_id(osv_vuln)
        
        # Extract affected versions
        affected_versions = OSVVulnerabilityConverter._extract_affected_versions(osv_vuln)
        
        # Determine fixed version
        fixed_version = OSVVulnerabilityConverter._extract_fixed_version(osv_vuln)
        
        # Map severity
        severity = OSVVulnerabilityConverter._map_severity(osv_vuln)
        
        # Normalize references to a list of URL strings when possible
        raw_refs = osv_vuln.get("references", []) or []
        references = []
        for ref in raw_refs:
            if isinstance(ref, dict):
                url = ref.get("url") or ref.get("reference")
                if url:
                    references.append(url)
                else:
                    references.append(json.dumps(ref))
            else:
                references.append(str(ref))

        return {
            "vulnerability_id": cve_id,
            "aliases": osv_vuln.get("aliases", []),
            "package": package_name,
            "ecosystem": ecosystem,
            "version": version,
            "affected_versions": affected_versions,
            "fixed_version": fixed_version,
            "severity": severity,
            "description": osv_vuln.get("summary", osv_vuln.get("details", "")),
            "title": osv_vuln.get("summary", cve_id),
            "cwe": OSVVulnerabilityConverter._extract_cwe(osv_vuln),
            "references": references,
            "published": osv_vuln.get("published", ""),
            "modified": osv_vuln.get("modified", ""),
            "withdrawn": osv_vuln.get("withdrawn"),
            "source": "OSV",
            "has_patch": bool(fixed_version),
        }

    @staticmethod
    def _extract_affected_versions(vuln: Dict) -> List[str]:
        """Extract affected version ranges from OSV record."""
        affected_versions = []
        
        for affected in vuln.get("affected", []):
            ranges = affected.get("ranges", [])
            for range_info in ranges:
                events = range_info.get("events", [])
                for event in events:
                    if "introduced" in event:
                        ver = event["introduced"]
                        if ver:
                            affected_versions.append(f">={ver}")
                    elif "fixed" in event:
                        ver = event["fixed"]
                        if ver:
                            affected_versions.append(f"<{ver}")
            
            # Fallback to versions if ranges not available
            if not affected_versions:
                affected_versions.extend(affected.get("versions", []))
        
        return affected_versions or ["*"]

    @staticmethod
    def _extract_fixed_version(vuln: Dict) -> Optional[str]:
        """Extract fixed version from OSV record."""
        for affected in vuln.get("affected", []):
            ranges = affected.get("ranges", [])
            for range_info in ranges:
                events = range_info.get("events", [])
                for event in events:
                    if "fixed" in event:
                        return event["fixed"]
        
        return None

    @staticmethod
    def _map_severity(vuln: Dict) -> str:
        """Map OSV severity score to text severity."""
        # OSV uses severity object with type and score
        severity_obj = vuln.get("severity")
        
        if not severity_obj:
            # Try database_specific or metrics for CVSS scores
            db_specific = vuln.get("database_specific") or {}
            # common places where OSV may include scores
            for key in ("cvss_v3", "cvss", "cvss_v2", "cvssv3"):
                sv = db_specific.get(key) if isinstance(db_specific, dict) else None
                if sv:
                    try:
                        # sv might be a dict with 'score' or a string number
                        score = sv.get("score") if isinstance(sv, dict) else float(sv)
                        numeric_score = float(score)
                        if numeric_score >= 9.0:
                            return "critical"
                        if numeric_score >= 7.0:
                            return "high"
                        if numeric_score >= 4.0:
                            return "medium"
                        return "low"
                    except Exception:
                        pass
            return "unknown"
        
        if isinstance(severity_obj, list):
            severity_obj = severity_obj[0] if severity_obj else {}

        # severity_obj may be dict or string
        score = None
        if isinstance(severity_obj, dict):
            score = severity_obj.get("score") or severity_obj.get("value")
        else:
            score = severity_obj

        # Handle CVSS vector strings or numeric values
        try:
            if isinstance(score, str) and score.upper().startswith("CVSS"):
                # Heuristic: look for CVSS severity keywords
                s = score.upper()
                if "CRITICAL" in s:
                    return "critical"
                if "HIGH" in s:
                    return "high"
                if "MEDIUM" in s:
                    return "medium"
                if "LOW" in s:
                    return "low"
                # Try to extract numeric after '/' patterns (rare)
                import re
                m = re.search(r"(\d+\.\d+)", s)
                if m:
                    numeric_score = float(m.group(1))
                    if numeric_score >= 9.0:
                        return "critical"
                    if numeric_score >= 7.0:
                        return "high"
                    if numeric_score >= 4.0:
                        return "medium"
                    return "low"

            numeric_score = float(score)
            if numeric_score >= 9.0:
                return "critical"
            if numeric_score >= 7.0:
                return "high"
            if numeric_score >= 4.0:
                return "medium"
            return "low"
        except Exception:
            return "unknown"

    @staticmethod
    def _extract_cwe(vuln: Dict) -> List[str]:
        """Extract CWE identifiers from OSV record."""
        cwe_list = []
        
        # Check in references
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if "cwe.mitre.org" in url:
                # Extract CWE-XXXX
                import re
                match = re.search(r'CWE-\d+', url)
                if match:
                    cwe_list.append(match.group())
        
        return cwe_list
