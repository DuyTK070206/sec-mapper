import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import requests

from .models import NormalizedAdvisory


@dataclass
class SourceDiscrepancy:
    package: str
    ecosystem: str
    advisory_id: str
    field: str
    values: Dict[str, str]


class VulnerabilitySourceAdapter:
    source_name = "base"

    def fetch(self, package: str, ecosystem: str, version: str) -> List[NormalizedAdvisory]:
        raise NotImplementedError


class LocalJsonAdapter(VulnerabilitySourceAdapter):
    source_name = "local-db"

    def __init__(self, path: Path) -> None:
        self.path = path

    def fetch(self, package: str, ecosystem: str, version: str) -> List[NormalizedAdvisory]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        out: List[NormalizedAdvisory] = []
        for item in data:
            if item.get("package", "").lower() != package.lower():
                continue
            if item.get("ecosystem") != ecosystem:
                continue
            out.append(
                NormalizedAdvisory(
                    advisory_id=item.get("cve_id", "unknown"),
                    aliases=[item.get("cve_id", "unknown")],
                    package=package,
                    ecosystem=ecosystem,
                    vulnerable_ranges=item.get("affected_versions", []),
                    fixed_version=item.get("fixed_version"),
                    severity=(item.get("severity") or "unknown").lower(),
                    cwe=item.get("cwe_ids", []),
                    references=[item.get("reference", "")],
                    exploitability="unknown",
                    patch_status="available" if item.get("has_patch") else "unavailable",
                    mitigation_status="unknown",
                    source_provenance=self.source_name,
                    title=item.get("cve_id", "Vulnerability"),
                    description=item.get("description", ""),
                )
            )
        return out


class OsvAdapter(VulnerabilitySourceAdapter):
    source_name = "osv"
    BASE_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    def fetch(self, package: str, ecosystem: str, version: str) -> List[NormalizedAdvisory]:
        osv_ecosystem = {"npm": "npm", "pip": "PyPI", "maven": "Maven"}.get(ecosystem)
        if not osv_ecosystem:
            return []

        payload = {
            "package": {
                "name": package,
                "ecosystem": osv_ecosystem,
            },
            "version": version.lstrip("=<>~^"),
        }
        response = requests.post(self.BASE_URL, json=payload, timeout=self.timeout)
        response.raise_for_status()
        vulns = response.json().get("vulns", [])

        normalized: List[NormalizedAdvisory] = []
        for vuln in vulns:
            ranges: List[str] = []
            fixed = None
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    events = rng.get("events", [])
                    introduced = None
                    fixed_event = None
                    for ev in events:
                        if "introduced" in ev:
                            introduced = ev["introduced"]
                        if "fixed" in ev:
                            fixed_event = ev["fixed"]
                    if introduced and fixed_event:
                        ranges.append(f">={introduced},<{fixed_event}")
                    elif introduced:
                        ranges.append(f">={introduced}")
                    if fixed_event and not fixed:
                        fixed = fixed_event
            aliases = vuln.get("aliases", [])
            advisory_id = vuln.get("id") or (aliases[0] if aliases else "unknown")
            normalized.append(
                NormalizedAdvisory(
                    advisory_id=advisory_id,
                    aliases=aliases or [advisory_id],
                    package=package,
                    ecosystem=ecosystem,
                    vulnerable_ranges=ranges or ["*"],
                    fixed_version=fixed,
                    severity=self._map_severity(vuln),
                    cwe=[x for x in aliases if x.startswith("CWE-")],
                    references=[ref.get("url", "") for ref in vuln.get("references", [])],
                    exploitability="unknown",
                    patch_status="available" if fixed else "unknown",
                    mitigation_status="unknown",
                    source_provenance=self.source_name,
                    title=vuln.get("summary", advisory_id),
                    description=vuln.get("details", vuln.get("summary", "")),
                )
            )
        return normalized

    def _map_severity(self, vuln: Dict) -> str:
        sev = vuln.get("database_specific", {}).get("severity")
        if sev:
            return sev.lower()
        for sev_obj in vuln.get("severity", []):
            score = sev_obj.get("score", "")
            if "CRITICAL" in score.upper():
                return "critical"
            if "HIGH" in score.upper():
                return "high"
            if "MEDIUM" in score.upper():
                return "medium"
            if "LOW" in score.upper():
                return "low"
        return "unknown"


class NvdKeywordAdapter(VulnerabilitySourceAdapter):
    source_name = "nvd"
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def fetch(self, package: str, ecosystem: str, version: str) -> List[NormalizedAdvisory]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = {"keywordSearch": package, "resultsPerPage": 25}
        response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        items = response.json().get("vulnerabilities", [])
        out: List[NormalizedAdvisory] = []
        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "unknown")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if package.lower() not in desc.lower() and package.lower() not in cve_id.lower():
                continue
            refs = [r.get("url", "") for r in cve.get("references", [])]
            cwes: List[str] = []
            for weak in cve.get("weaknesses", []):
                for cw in weak.get("description", []):
                    val = cw.get("value", "")
                    if val.startswith("CWE-"):
                        cwes.append(val)
            out.append(
                NormalizedAdvisory(
                    advisory_id=cve_id,
                    aliases=[cve_id],
                    package=package,
                    ecosystem=ecosystem,
                    vulnerable_ranges=["*"],
                    fixed_version=None,
                    severity=self._severity(cve),
                    cwe=cwes,
                    references=refs,
                    exploitability="unknown",
                    patch_status="unknown",
                    mitigation_status="unknown",
                    source_provenance=self.source_name,
                    title=cve_id,
                    description=desc,
                )
            )
        return out

    def _severity(self, cve: Dict) -> str:
        metrics = cve.get("metrics", {})
        keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
        for key in keys:
            vals = metrics.get(key)
            if vals:
                sev = vals[0].get("cvssData", {}).get("baseSeverity", "unknown")
                return sev.lower()
        return "unknown"


class IntelligencePipeline:
    def __init__(
        self,
        adapters: List[VulnerabilitySourceAdapter],
        cache_path: Path,
        rate_limit_seconds: float = 0.5,
        retries: int = 2,
    ) -> None:
        self.adapters = adapters
        self.cache_path = cache_path
        self.rate_limit_seconds = rate_limit_seconds
        self.retries = retries
        self._last_call_ts = 0.0
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.cache_path.exists():
            self.cache_path.write_text("{}", encoding="utf-8")

    def fetch(self, package: str, ecosystem: str, version: str) -> Dict[str, List[NormalizedAdvisory]]:
        cache_key = f"{ecosystem}:{package}:{version}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return {k: [self._from_dict(x) for x in v] for k, v in cached.items()}

        per_source: Dict[str, List[NormalizedAdvisory]] = {}
        for adapter in self.adapters:
            per_source[adapter.source_name] = self._safe_fetch(adapter, package, ecosystem, version)

        self._cache_put(
            cache_key,
            {k: [self._to_dict(x) for x in v] for k, v in per_source.items()},
        )
        return per_source

    def find_discrepancies(self, per_source: Dict[str, List[NormalizedAdvisory]]) -> List[SourceDiscrepancy]:
        discrepancies: List[SourceDiscrepancy] = []
        by_id: Dict[str, Dict[str, NormalizedAdvisory]] = {}
        for source, advisories in per_source.items():
            for adv in advisories:
                by_id.setdefault(adv.advisory_id, {})[source] = adv

        for advisory_id, source_map in by_id.items():
            severities = {src: adv.severity for src, adv in source_map.items()}
            fixed_versions = {src: str(adv.fixed_version or "") for src, adv in source_map.items()}
            if len(set(severities.values())) > 1:
                any_adv = next(iter(source_map.values()))
                discrepancies.append(
                    SourceDiscrepancy(
                        package=any_adv.package,
                        ecosystem=any_adv.ecosystem,
                        advisory_id=advisory_id,
                        field="severity",
                        values=severities,
                    )
                )
            if len(set(fixed_versions.values())) > 1:
                any_adv = next(iter(source_map.values()))
                discrepancies.append(
                    SourceDiscrepancy(
                        package=any_adv.package,
                        ecosystem=any_adv.ecosystem,
                        advisory_id=advisory_id,
                        field="fixed_version",
                        values=fixed_versions,
                    )
                )
        return discrepancies

    def _safe_fetch(self, adapter: VulnerabilitySourceAdapter, package: str, ecosystem: str, version: str) -> List[NormalizedAdvisory]:
        attempts = 0
        while attempts <= self.retries:
            attempts += 1
            try:
                self._throttle()
                return adapter.fetch(package, ecosystem, version)
            except Exception:
                if attempts > self.retries:
                    return []
        return []

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_call_ts
        if elapsed < self.rate_limit_seconds:
            time.sleep(self.rate_limit_seconds - elapsed)
        self._last_call_ts = time.time()

    def _cache_get(self, key: str) -> Optional[Dict]:
        data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        return data.get(key)

    def _cache_put(self, key: str, value: Dict) -> None:
        data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        data[key] = value
        self.cache_path.write_text(json.dumps(data), encoding="utf-8")

    def _to_dict(self, advisory: NormalizedAdvisory) -> Dict:
        return advisory.__dict__

    def _from_dict(self, data: Dict) -> NormalizedAdvisory:
        return NormalizedAdvisory(**data)
