from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ParsedDependencyModel:
    name: str
    version: str
    ecosystem: str
    source: str
    is_transitive: bool = False
    parent: Optional[str] = None
    dependency_path: List[str] = field(default_factory=list)
    dev_only: bool = False


@dataclass
class NormalizedAdvisory:
    advisory_id: str
    aliases: List[str]
    package: str
    ecosystem: str
    vulnerable_ranges: List[str]
    fixed_version: Optional[str]
    severity: str
    cwe: List[str]
    references: List[str]
    exploitability: str
    patch_status: str
    mitigation_status: str
    source_provenance: str
    title: str
    description: str


@dataclass
class Finding:
    title: str
    package: str
    ecosystem: str
    version: str
    fixed_version: Optional[str]
    severity: str
    confidence: str
    confidence_score: float
    vulnerability_id: str
    vulnerability_type: str
    dependency_path: List[str]
    root_cause: str
    evidence: List[str]
    patch_available: bool
    mitigation_available: bool
    remediation_recommendation: str
    status: str
    source: str
    transitive: bool
    references: List[str] = field(default_factory=list)
    advisory_sources: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    triage_summary: str = ""
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "fixed_version": self.fixed_version,
            "recommended_version": self.fixed_version,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "vulnerability_id": self.vulnerability_id,
            "cve": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "dependency_path": self.dependency_path,
            "root_cause": self.root_cause,
            "evidence": self.evidence,
            "patch_available": self.patch_available,
            "has_patch": self.patch_available,
            "mitigation_available": self.mitigation_available,
            "remediation_recommendation": self.remediation_recommendation,
            "status": self.status,
            "source": self.source,
            "transitive": self.transitive,
            "references": self.references,
            "advisory_sources": self.advisory_sources,
            "cwe": self.cwe,
            "triage_summary": self.triage_summary,
            "description": self.root_cause,
            "reference": self.references[0] if self.references else "",
            "effort": "medium",
            "poc": "Safe reproduction steps only. Set lab mode explicitly for exploit PoC generation.",
            "risk_score": self.risk_score,
        }


@dataclass
class ScanSummary:
    project_name: str
    scan_time: str
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    findings: List[Dict[str, Any]]
    risk_score: int
    scan_health: Dict[str, Any]

    @staticmethod
    def now() -> str:
        return datetime.utcnow().isoformat() + "Z"
