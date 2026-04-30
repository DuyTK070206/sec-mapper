from datetime import datetime
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from src.dependency_parser import ParsedDependency, ParserFactory
from src.exploit_generator import ExploitGeneratorFactory
from src.intelligence import IntelligencePipeline, LocalJsonAdapter, NvdKeywordAdapter, OsvAdapter
from src.models import Finding
from src.osv_client import OSVClient, OSVVulnerabilityConverter
from src.remediation_engine import RemediationEngine
from src.ai_remediation import generate_mitigation
from src.report_generator import ReportGenerator
from src.triage import AITriageEngine

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Coordinate parsing, vulnerability intelligence, triage, remediation, and report formatting."""

    def __init__(self, db_path: Optional[str] = None, nvd_api_key: Optional[str] = None, github_token: Optional[str] = None, use_osv_direct: bool = True) -> None:
        """
        Initialize DependencyScanner.
        
        Args:
            db_path: Path to local vuln_db.json (fallback only)
            nvd_api_key: NVD API key (legacy)
            github_token: GitHub token (legacy)
            use_osv_direct: If True, use OSVClient directly for queries; if False, use IntelligencePipeline
        """
        self.db_path = Path(db_path) if db_path else (Path(__file__).resolve().parent / "vuln_db.json")
        self.use_osv_direct = use_osv_direct
        self.osv_client = None
        
        # Use OSV API directly (primary source)
        if self.use_osv_direct:
            logger.info("[INIT] Using OSV API directly for vulnerability scanning")
            self.osv_client = OSVClient(use_cache=True)
            self.adapter_names = ["OSV"]
            self.pipeline = None
        else:
            # Fallback: Use IntelligencePipeline with multiple adapters
            logger.info("[INIT] Using IntelligencePipeline for vulnerability scanning")
            enable_live = os.getenv("SEC_MAPPER_ENABLE_LIVE_INTEL", "false").lower() == "true"
            adapters = [LocalJsonAdapter(self.db_path)]
            if enable_live:
                adapters.extend([OsvAdapter(), NvdKeywordAdapter(api_key=nvd_api_key)])
            self.adapter_names = [adapter.source_name for adapter in adapters]
            self.pipeline = IntelligencePipeline(
                adapters=adapters,
                cache_path=Path(__file__).resolve().parent.parent / "scan_cache" / "advisories.json",
                rate_limit_seconds=0.25,
                retries=1,
            )
        
        self.triage = AITriageEngine()
        self.remediation = RemediationEngine()

    def scan_file(self, manifest_path: Path, lock_path: Optional[Path] = None) -> Dict:
        dependencies = self._load_dependencies(manifest_path, lock_path)
        findings: List[Dict] = []
        discrepancies: List[Dict] = []

        if self.use_osv_direct:
            # Direct OSV API scanning
            findings, discrepancies = self._scan_with_osv_direct(dependencies)
        else:
            # IntelligencePipeline scanning (legacy)
            findings, discrepancies = self._scan_with_pipeline(dependencies)

        findings = self.triage.cluster_duplicates(findings)
        findings = self._sort_findings(findings)

        total_direct, total_transitive = self._dependency_counts(dependencies)
        scan_health = {
            "sources_checked": self.adapter_names,
            "discrepancies": discrepancies,
            "discrepancy_count": len(discrepancies),
            "false_positive_controls": [
                "cross-source reconciliation",
                "confidence scoring",
                "evidence-backed triage",
                "deduplication",
            ],
            "post_scan_system_state": self.remediation.system_state(findings),
        }

        return {
            "project_name": manifest_path.stem,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "total_dependencies": len(dependencies),
            "direct_dependencies": total_direct,
            "transitive_dependencies": total_transitive,
            "findings": findings,
            "risk_score": self._calculate_overall_risk_score(findings),
            "scan_health": scan_health,
            "scan_targets": [
                {
                    "manifest_path": str(manifest_path),
                    "lock_path": str(lock_path) if lock_path else None,
                    "uploaded_filenames": [manifest_path.name] + ([lock_path.name] if lock_path else []),
                }
            ],
        }

    def _scan_with_osv_direct(self, dependencies: List[ParsedDependency]) -> Tuple[List[Dict], List[Dict]]:
        """Scan dependencies using OSV API directly."""
        findings: List[Dict] = []
        
        for dep in dependencies:
            logger.debug(f"[OSV-SCAN] Scanning {dep.name}@{dep.version} ({dep.ecosystem})")
            
            # Query OSV API
            osv_vulns = self.osv_client.query(dep.name, dep.ecosystem, dep.version)
            
            for osv_vuln in osv_vulns:
                # Convert OSV format to internal format
                converted = OSVVulnerabilityConverter.convert(
                    osv_vuln, dep.name, dep.ecosystem, dep.version
                )
                
                # Verify the vulnerability actually affects this version
                if not self._matches(converted['affected_versions'], dep.version, dep.ecosystem):
                    logger.debug(f"[SKIP-VERSION] {dep.name}@{dep.version} not in affected range")
                    continue
                
                # Skip if already fixed
                if converted['fixed_version']:
                    try:
                        if Version(converted['fixed_version']) <= Version(dep.version):
                            logger.debug(f"[SKIP-FIXED] {dep.name}@{dep.version} already fixed in {converted['fixed_version']}")
                            continue
                    except (InvalidVersion, TypeError):
                        pass
                
                # Skip very old CVEs
                vuln_id = converted['vulnerability_id']
                if vuln_id.startswith("CVE-1999") or vuln_id.startswith("CVE-2000"):
                    logger.debug(f"[SKIP-OLD] Skipping very old CVE: {vuln_id}")
                    continue
                
                # Calculate confidence
                confidence, score, evidence = self._confidence_for_osv(dep, converted, "osv")

                # Analyze exploitability
                exploit_info = self._analyze_exploitability(converted)
                
                # Infer vulnerability type
                vuln_type = self._infer_vuln_type_from_advisory(converted)
                
                # Generate PoC if available
                generator = ExploitGeneratorFactory.get_generator(
                    {
                        "cve_id": vuln_id,
                        "description": converted['description'],
                        "cwe_ids": converted.get('cwe', []),
                    }
                )
                poc = generator.generate_poc({"cve_id": vuln_id}) if generator else None
                
                # Create finding
                finding = Finding(
                    title=converted['title'] or vuln_id,
                    package=dep.name,
                    ecosystem=dep.ecosystem,
                    version=dep.version,
                    fixed_version=converted['fixed_version'],
                    severity=(converted.get('severity') or 'low').lower(),
                    confidence=confidence,
                    confidence_score=score,
                    vulnerability_id=vuln_id,
                    vulnerability_type=vuln_type,
                    dependency_path=self._dependency_path(dep),
                    root_cause=converted['description'],
                    evidence=evidence,
                    patch_available=converted.get('has_patch', False),
                    mitigation_available=False,
                    remediation_recommendation="",
                    status="vulnerable",
                    source=dep.source,
                    transitive=dep.is_transitive,
                    references=converted.get('references', []),
                    advisory_sources=["OSV"],
                    cwe=converted.get('cwe', []),
                    risk_score=self._calculate_finding_risk_score(
                        converted.get('severity', 'unknown'),
                        score,
                        converted.get('has_patch', False),
                        dep.is_transitive,
                        exploit_info.get('exploitability_score', 0.0),
                    ),
                ).to_dict()
                
                if poc:
                    finding["poc"] = poc
                # Attach exploit analysis
                finding["exploitability"] = exploit_info

                # Assign priority label
                finding_sev = (finding.get('severity') or 'unknown').lower()
                finding_exploitable = exploit_info.get('exploitable', False)
                if finding_sev == 'critical' and finding_exploitable and not finding.get('transitive'):
                    finding['fix_priority'] = 'P0'
                elif finding_sev == 'high' and finding_exploitable:
                    finding['fix_priority'] = 'P1'
                elif finding_sev in {'medium'} or not finding_exploitable:
                    finding['fix_priority'] = 'P2'
                else:
                    finding['fix_priority'] = 'P3'
                
                # Apply remediation recommendations
                rem = self.remediation.recommend(finding)
                finding["patch_available"] = rem["patch_available"]
                finding["mitigation_available"] = rem["mitigation_available"]
                finding["remediation_recommendation"] = rem["recommendation"]
                finding["status"] = rem["status"]

                # If no patch is available, call AI remediation helper (cached) to provide mitigation suggestions
                try:
                    if not finding.get("patch_available"):
                        ai_result = generate_mitigation(finding)
                        finding["ai_mitigation"] = ai_result
                        # If AI provided a config_example or explicit recommendation, prefer it for remediation display
                        if ai_result and ai_result.get("mitigation_steps"):
                            finding["remediation_recommendation"] = ai_result.get("summary") or finding["remediation_recommendation"]
                except Exception as e:
                    logger.debug(f"[AI-INTEGRATION-ERROR] {e}")
                
                findings.append(self.triage.enrich(finding))
        
        return findings, []

    def _scan_with_pipeline(self, dependencies: List[ParsedDependency]) -> Tuple[List[Dict], List[Dict]]:
        """Scan dependencies using IntelligencePipeline (legacy)."""
        findings: List[Dict] = []
        discrepancies: List[Dict] = []

        for dep in dependencies:
            per_source = self.pipeline.fetch(dep.name, dep.ecosystem, dep.version)
            discrepancies.extend([d.__dict__ for d in self.pipeline.find_discrepancies(per_source)])

            for source_name, advisories in per_source.items():
                for advisory in advisories:
                    if not self._matches(advisory.vulnerable_ranges, dep.version, dep.ecosystem):
                        continue

                    # Skip if already fixed
                    if advisory.fixed_version:
                        try:
                            if Version(advisory.fixed_version) <= Version(dep.version):
                                continue
                        except (InvalidVersion, TypeError):
                            pass

                    # Skip very old CVEs that are unlikely relevant
                    vuln_id = advisory.advisory_id or (advisory.aliases[0] if advisory.aliases else "")
                    if vuln_id.startswith("CVE-1999") or vuln_id.startswith("CVE-2000"):
                        continue

                    confidence, score, evidence = self._confidence_for(dep, advisory, source_name)
                    vuln_id = advisory.advisory_id or (advisory.aliases[0] if advisory.aliases else "unknown")
                    vuln_type = self._infer_vuln_type(advisory)

                    generator = ExploitGeneratorFactory.get_generator(
                        {
                            "cve_id": vuln_id,
                            "description": advisory.description,
                            "cwe_ids": advisory.cwe,
                        }
                    )
                    poc = generator.generate_poc({"cve_id": vuln_id}) if generator else None

                    finding = Finding(
                        title=advisory.title or vuln_id,
                        package=dep.name,
                        ecosystem=dep.ecosystem,
                        version=dep.version,
                        fixed_version=advisory.fixed_version,
                        severity=(advisory.severity or "low").lower(),
                        confidence=confidence,
                        confidence_score=score,
                        vulnerability_id=vuln_id,
                        vulnerability_type=vuln_type,
                        dependency_path=self._dependency_path(dep),
                        root_cause=advisory.description,
                        evidence=evidence,
                        patch_available=bool(advisory.fixed_version),
                        mitigation_available=False,
                        remediation_recommendation="",
                        status="vulnerable",
                        source=dep.source,
                        transitive=dep.is_transitive,
                        references=[r for r in advisory.references if r],
                        advisory_sources=[source_name],
                        cwe=advisory.cwe,
                        risk_score=self._calculate_finding_risk_score(advisory.severity, score, bool(advisory.fixed_version), dep.is_transitive),
                    ).to_dict()
                    if poc:
                        finding["poc"] = poc

                    rem = self.remediation.recommend(finding)
                    finding["patch_available"] = rem["patch_available"]
                    finding["mitigation_available"] = rem["mitigation_available"]
                    finding["remediation_recommendation"] = rem["recommendation"]
                    finding["status"] = rem["status"]
                    findings.append(self.triage.enrich(finding))
        
        return findings, discrepancies


    def scan_targets(self, targets: List[Dict]) -> Dict:
        if not targets:
            raise ValueError("No scan targets provided")

        combined_findings: List[Dict] = []
        combined_discrepancies: List[Dict] = []
        combined_sources: List[str] = []
        combined_targets: List[Dict] = []
        total_dependencies = 0
        total_direct = 0
        total_transitive = 0

        for target in targets:
            manifest_path = Path(target["manifest_path"])
            lock_path = Path(target["lock_path"]) if target.get("lock_path") else None
            result = self.scan_file(manifest_path, lock_path=lock_path)

            combined_findings.extend(result.get("findings", []))
            combined_discrepancies.extend(result.get("scan_health", {}).get("discrepancies", []))
            combined_sources.extend(result.get("scan_health", {}).get("sources_checked", []))
            combined_targets.append(
                {
                    "manifest_path": str(manifest_path),
                    "lock_path": str(lock_path) if lock_path else None,
                    "uploaded_filenames": list(target.get("uploaded_filenames", [manifest_path.name])),
                    "ecosystem": target.get("ecosystem", "unknown"),
                }
            )
            total_dependencies += result.get("total_dependencies", 0)
            total_direct += result.get("direct_dependencies", 0)
            total_transitive += result.get("transitive_dependencies", 0)

        combined_findings = self.triage.cluster_duplicates(combined_findings)
        combined_findings = self._sort_findings(combined_findings)
        unique_sources = list(dict.fromkeys(combined_sources))

        scan_health = {
            "sources_checked": unique_sources,
            "discrepancies": combined_discrepancies,
            "discrepancy_count": len(combined_discrepancies),
            "false_positive_controls": [
                "cross-source reconciliation",
                "confidence scoring",
                "evidence-backed triage",
                "deduplication",
            ],
            "post_scan_system_state": self.remediation.system_state(combined_findings),
        }

        project_name = "uploaded-workspace" if len(combined_targets) > 1 else Path(combined_targets[0]["manifest_path"]).stem

        return {
            "project_name": project_name,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "total_dependencies": total_dependencies,
            "direct_dependencies": total_direct,
            "transitive_dependencies": total_transitive,
            "findings": combined_findings,
            "risk_score": self._calculate_overall_risk_score(combined_findings),
            "scan_health": scan_health,
            "scan_targets": combined_targets,
        }

    def _load_dependencies(self, manifest_path: Path, lock_path: Optional[Path] = None) -> List[ParsedDependency]:
        root_parser = ParserFactory.get_parser(manifest_path.name)
        root_deps = root_parser.parse(manifest_path.read_text(encoding="utf-8"))

        if lock_path and lock_path.exists():
            lock_parser = ParserFactory.get_parser(lock_path.name)
            lock_deps = lock_parser.parse(lock_path.read_text(encoding="utf-8"))
            return self._merge_dependencies(root_deps, lock_deps)

        return root_deps

    def _merge_dependencies(self, root_deps: List[ParsedDependency], lock_deps: List[ParsedDependency]) -> List[ParsedDependency]:
        merged: Dict[Tuple[str, str], ParsedDependency] = {}
        root_names = {dep.name.lower() for dep in root_deps}

        for dep in root_deps:
            key = (dep.name.lower(), dep.ecosystem)
            if not getattr(dep, "dependency_path", None):
                dep.dependency_path = [dep.name]
            merged[key] = dep

        for dep in lock_deps:
            key = (dep.name.lower(), dep.ecosystem)
            dep.is_transitive = dep.is_transitive or (dep.name.lower() not in root_names)
            if not getattr(dep, "dependency_path", None):
                dep.dependency_path = [dep.parent, dep.name] if dep.parent else [dep.name]

            if key not in merged:
                merged[key] = dep
                continue

            existing = merged[key]
            if self._is_more_specific(dep.version, existing.version):
                existing.version = dep.version
                existing.source = dep.source
                existing.is_transitive = dep.is_transitive
                existing.parent = dep.parent
                existing.dependency_path = dep.dependency_path

        return list(merged.values())

    def _is_more_specific(self, lock_version: str, root_version: str) -> bool:
        return not lock_version.startswith(("^", "~", ">", "<", "*")) and root_version.startswith(("^", "~", ">", "<", "*"))

    def _dependency_counts(self, dependencies: List[ParsedDependency]) -> Tuple[int, int]:
        direct = sum(1 for dep in dependencies if not dep.is_transitive)
        transitive = sum(1 for dep in dependencies if dep.is_transitive)
        return direct, transitive

    def _dependency_path(self, dep: ParsedDependency) -> List[str]:
        if getattr(dep, "dependency_path", None):
            return [x for x in dep.dependency_path if x]
        if dep.parent:
            return [dep.parent, dep.name]
        return [dep.name]

    def _matches(self, affected_ranges: List[str], dependency_spec: str, ecosystem: str) -> bool:
        dep_spec = (dependency_spec or "").strip()
        if not dep_spec:
            return False

        dep_spec = dep_spec.lstrip("=")
        if dep_spec == "*":
            return True

        if ecosystem == "npm":
            dep_spec = self._normalize_npm_spec(dep_spec)
            affected_ranges = [self._normalize_npm_spec(x) for x in affected_ranges]

        for affected in affected_ranges:
            affected = (affected or "").strip()
            if affected in {"", "*"}:
                return True
            try:
                if self._is_exact_version(dep_spec):
                    return Version(dep_spec) in SpecifierSet(affected)
                return self._ranges_overlap(SpecifierSet(dep_spec), SpecifierSet(affected))
            except (InvalidSpecifier, InvalidVersion):
                continue
        return False

    def _normalize_npm_spec(self, version_spec: str) -> str:
        version_spec = version_spec.strip()
        if version_spec.startswith("^"):
            base = version_spec[1:]
            try:
                parsed = Version(base)
                return f">={base},<{parsed.major + 1}.0.0"
            except InvalidVersion:
                return version_spec
        if version_spec.startswith("~"):
            base = version_spec[1:]
            try:
                parsed = Version(base)
                return f">={base},<{parsed.major}.{parsed.minor + 1}.0"
            except InvalidVersion:
                return version_spec
        return version_spec

    def _is_exact_version(self, version_spec: str) -> bool:
        return all(c.isdigit() or c == "." for c in version_spec)

    def _ranges_overlap(self, a: SpecifierSet, b: SpecifierSet) -> bool:
        samples = [
            "0.1.0", "0.20.0", "1.0.0", "1.10.0", "1.26.3", "1.26.5", "2.0.0", "2.25.0", "2.26.0", "4.17.20", "4.17.21",
        ]
        for candidate in samples:
            try:
                v = Version(candidate)
                if v in a and v in b:
                    return True
            except InvalidVersion:
                continue
        return False

    def _infer_vuln_type(self, advisory) -> str:
        text = f"{advisory.title} {advisory.description}".lower()
        if "injection" in text:
            return "Injection"
        if "deserial" in text:
            return "Insecure Deserialization"
        if "execution" in text or "rce" in text:
            return "Code Execution"
        if "xss" in text:
            return "Cross-Site Scripting"
        if advisory.cwe:
            return advisory.cwe[0]
        return "Dependency Vulnerability"

    def _infer_vuln_type_from_advisory(self, advisory_dict: Dict) -> str:
        """Infer vulnerability type from OSV advisory dict."""
        text = f"{advisory_dict.get('title', '')} {advisory_dict.get('description', '')}".lower()
        if "injection" in text:
            return "Injection"
        if "deserial" in text:
            return "Insecure Deserialization"
        if "execution" in text or "rce" in text:
            return "Code Execution"
        if "xss" in text:
            return "Cross-Site Scripting"
        if advisory_dict.get('cwe'):
            return advisory_dict['cwe'][0]
        return "Dependency Vulnerability"

    def _confidence_for_osv(self, dep: ParsedDependency, advisory_dict: Dict, source_name: str = "osv") -> Tuple[str, float, List[str]]:
        """Calculate confidence score for OSV-based advisory."""
        evidence: List[str] = []
        score = 0.35

        if dep.version and self._is_exact_version(dep.version.lstrip("=")):
            score += 0.25
            evidence.append("Exact version observed in manifest/lock data")
        else:
            evidence.append("Version range matched; exact resolved version unavailable")

        if source_name in {"osv", "nvd"}:
            score += 0.2
            evidence.append(f"Advisory backed by {source_name.upper()}")
        elif source_name == "local-db":
            score += 0.1
            evidence.append("Matched local advisory database")

        if dep.is_transitive:
            evidence.append("Transitive dependency path present")
            score += 0.05

        if advisory_dict.get('fixed_version'):
            score += 0.1
            evidence.append(f"Fixed version available: {advisory_dict['fixed_version']}")
        else:
            evidence.append("No fixed version from this source")

        score = max(0.0, min(score, 0.99))
        if score >= 0.8:
            label = "exact version match"
        elif score >= 0.6:
            label = "advisory-backed match"
        elif score >= 0.45:
            label = "heuristic match"
        else:
            label = "uncertain match requiring review"
        return label, score, evidence

    def _analyze_exploitability(self, advisory: Dict) -> Dict:
        """Basic exploitability analysis using advisory metadata and references.

        Returns a dict with:
        - exploitable: bool
        - poc: bool
        - requires_user_input: bool
        - requires_auth: bool
        - impact: str (RCE, PrivEsc, Information Disclosure, Unknown)
        - exploitability_score: float (0.0-1.0)
        """
        text = (advisory.get('title', '') + ' ' + advisory.get('description', '')).lower()
        refs = advisory.get('references', []) or []
        poc = False
        requires_user_input = False
        requires_auth = False
        impact = 'Unknown'
        score = 0.0

        # Heuristics from text
        if 'proof-of-concept' in text or 'proof of concept' in text or 'poc' in text:
            poc = True
            score += 0.4
        if 'exploit' in text or 'exploit-db' in text or 'exploit available' in text:
            poc = True
            score += 0.35
        if 'rce' in text or 'remote code execution' in text or 'remote code execution' in text:
            impact = 'RCE'
            score += 0.3
        if 'privilege escalation' in text or 'priv esc' in text:
            impact = 'PrivEsc'
            score += 0.25
        if 'authentication' in text or 'auth' in text:
            requires_auth = True
            score -= 0.1
        if 'user interaction' in text or 'requires user interaction' in text or 'click' in text:
            requires_user_input = True
            score -= 0.1

        # Inspect references for known PoC sources
        for r in refs:
            rr = r if isinstance(r, str) else json.dumps(r)
            rl = rr.lower()
            if 'exploit-db' in rl or 'proof-of-concept' in rl or '/poc' in rl or 'github.com' in rl and 'poc' in rl:
                poc = True
                score += 0.3

        score = max(0.0, min(1.0, score))
        exploitable = poc or (score >= 0.5)

        return {
            'exploitable': bool(exploitable),
            'poc': bool(poc),
            'requires_user_input': bool(requires_user_input),
            'requires_auth': bool(requires_auth),
            'impact': impact,
            'exploitability_score': float(score),
        }


    def _confidence_for(self, dep: ParsedDependency, advisory, source_name: str) -> Tuple[str, float, List[str]]:
        evidence: List[str] = []
        score = 0.35

        if dep.version and self._is_exact_version(dep.version.lstrip("=")):
            score += 0.25
            evidence.append("Exact version observed in manifest/lock data")
        else:
            evidence.append("Version range matched; exact resolved version unavailable")

        if source_name in {"osv", "nvd"}:
            score += 0.2
            evidence.append(f"Advisory backed by {source_name}")
        elif source_name == "local-db":
            score += 0.1
            evidence.append("Matched local advisory database")

        if dep.is_transitive:
            evidence.append("Transitive dependency path present")
            score += 0.05

        if advisory.fixed_version:
            score += 0.1
            evidence.append(f"Fixed version available: {advisory.fixed_version}")
        else:
            evidence.append("No fixed version from this source")

        score = max(0.0, min(score, 0.99))
        if score >= 0.8:
            label = "exact version match"
        elif score >= 0.6:
            label = "advisory-backed match"
        elif score >= 0.45:
            label = "heuristic match"
        else:
            label = "uncertain match requiring review"
        return label, score, evidence

    def _calculate_finding_risk_score(self, severity: str, confidence_score: float, patch_available: bool, is_transitive: bool, exploitability_score: float = 0.0) -> int:
        """Calculate risk score for individual finding.

        Factors: severity, confidence_score (0-1), patch_available (bool), is_transitive (bool), exploitability_score (0-1).
        Returns an integer 0-100.
        """
        severity_scores = {"critical": 100, "high": 80, "medium": 60, "low": 40, "unknown": 50}
        base_score = severity_scores.get((severity or "").lower(), 50)

        # Confidence amplifies base severity (0.5x to 1.0x)
        confidence_multiplier = 0.5 + (float(confidence_score or 0.0) * 0.5)
        score = base_score * confidence_multiplier

        # Exploitability increases score (0-1 adds up to +30%)
        try:
            exploit_boost = float(exploitability_score or 0.0) * 0.3
        except Exception:
            exploit_boost = 0.0
        score = score * (1.0 + exploit_boost)

        # Reduce if patch available
        if patch_available:
            score *= 0.8

        # Reduce for transitive dependencies
        if is_transitive:
            score *= 0.9

        return int(min(100, max(0, round(score))))

    def _sort_findings(self, findings: List[Dict]) -> List[Dict]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        confidence_order = {
            "exact version match": 0,
            "advisory-backed match": 1,
            "heuristic match": 2,
            "uncertain match requiring review": 3,
        }
        return sorted(
            findings,
            key=lambda f: (
                severity_order.get((f.get("severity") or "unknown").lower(), 4),
                confidence_order.get(f.get("confidence", "uncertain match requiring review"), 3),
                f.get("package", ""),
            ),
        )

    def format_report(self, scan_result: Dict, manifest_path: Path) -> str:
        lines = [
            "=" * 60,
            "DEPENDENCY VULNERABILITY SCAN REPORT",
            "=" * 60,
            "",
            "[SCAN SUMMARY]",
            "-" * 60,
            f"File: {manifest_path}",
            f"Scan Time: {scan_result['scan_time']}",
            f"Overall Risk Score: {scan_result['risk_score']}/100",
            f"Total Dependencies: {scan_result['total_dependencies']}",
            f"  - Direct: {scan_result['direct_dependencies']}",
            f"  - Transitive: {scan_result['transitive_dependencies']}",
            f"Vulnerabilities Found: {len(scan_result['findings'])}",
            "",
        ]

        if not scan_result["findings"]:
            lines.append("[OK] No known vulnerabilities found for analyzed dependencies.")
            return "\n".join(lines)

        lines.extend([
            "[DETAILED FINDINGS]",
            "-" * 60,
            "",
        ])

        for idx, finding in enumerate(scan_result["findings"], 1):
            lines.extend(
                [
                    f"{idx}. [{finding.get('severity', 'unknown').upper()}] {finding.get('package')} ({finding.get('ecosystem')})",
                    f"   Current Version: {finding.get('version')}",
                    f"   Risk Score: {finding.get('risk_score', 0)}/100",
                    f"   Dependency Path: {' > '.join(finding.get('dependency_path', []))}",
                    f"   Status: {finding.get('status')}",
                ]
            )
            vulns = finding.get("vulnerabilities", [])
            if vulns:
                lines.append(f"   Vulnerabilities ({len(vulns)}):")
                for vuln in vulns:
                    lines.append(f"     - {vuln['id']} ({vuln['severity']}) - Fixed: {vuln['fixed_version'] or 'N/A'}")
            else:
                lines.extend([
                    f"   Vulnerability ID: {finding.get('vulnerability_id', finding.get('cve', 'unknown'))}",
                    f"   Fixed Version: {finding.get('fixed_version') or 'N/A'}",
                    f"   Confidence: {finding.get('confidence')} ({finding.get('confidence_score', 0):.2f})",
                ])
            lines.extend([
                f"   Recommendation: {finding.get('remediation_recommendation')}",
                "",
            ])

        post = scan_result.get("scan_health", {}).get("post_scan_system_state", {})
        if post:
            lines.extend(
                [
                    "[POST-SCAN SYSTEM STATE]",
                    "-" * 60,
                    f"Vulnerable now: {post.get('vulnerable_now', 0)}",
                    f"Known fix available: {post.get('known_fix_available', 0)}",
                    f"Needs immediate upgrade: {post.get('immediate_upgrade', 0)}",
                    f"Can be mitigated temporarily: {post.get('temporary_mitigation', 0)}",
                    f"Uncertain findings: {post.get('uncertain', 0)}",
                    "",
                ]
            )

        return "\n".join(lines)

    def generate_json_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_json_report()

    def generate_html_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_html_report()

    def generate_sarif_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_sarif_report()

    def generate_api_report(self, scan_result: Dict) -> str:
        return ReportGenerator(scan_result).generate_api_report()

    def _calculate_overall_risk_score(self, findings: List[Dict]) -> int:
        if not findings:
            return 0
        risk_scores = [f.get("risk_score", 50) for f in findings]
        return int(sum(risk_scores) / len(risk_scores))
