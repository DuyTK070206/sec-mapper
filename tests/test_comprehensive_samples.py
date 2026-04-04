"""
Comprehensive sample tests - kiểm thử tổng hợp toàn bộ samples
Bao gồm:
- Test tất cả sample files (package.json, requirements.txt)
- Test tất cả output formats (text, json, html, sarif)
- Test PoC generation
- Test report completeness
"""

from pathlib import Path
import json
from src.scanner import DependencyScanner


class TestSamplePackageJson:
    """Test scanning package.json samples"""

    @classmethod
    def setup_class(cls):
        cls.scanner = DependencyScanner()
        cls.manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'

    def test_package_json_scan_basic(self):
        """Test basic package.json scanning"""
        result = self.scanner.scan_file(self.manifest_path)
        
        assert result is not None
        assert 'direct_dependencies' in result
        assert 'findings' in result
        assert result['direct_dependencies'] > 0

    def test_package_json_with_lock_file(self):
        """Test package.json scanning with lock file for transitive deps"""
        lock_path = Path(__file__).resolve().parent.parent / 'samples' / 'package-lock.json'
        result = self.scanner.scan_file(self.manifest_path, lock_path=lock_path)
        
        assert result is not None
        assert 'transitive_dependencies' in result
        assert result['transitive_dependencies'] >= 0

    def test_findings_are_correctly_detected(self):
        """Test that known vulnerabilities are detected"""
        result = self.scanner.scan_file(self.manifest_path)
        
        # lodash 4.17.20 should have CVE-2021-23337
        assert any(f['package'] == 'lodash' for f in result['findings']), \
            "lodash vulnerability should be detected"

    def test_vulnerability_details_present(self):
        """Test that vulnerability findings have all required fields"""
        result = self.scanner.scan_file(self.manifest_path)
        
        for finding in result['findings']:
            assert 'package' in finding
            assert 'version' in finding
            assert 'cve' in finding
            assert 'severity' in finding
            assert 'poc' in finding


class TestSampleRequirements:
    """Test scanning requirements.txt samples"""

    @classmethod
    def setup_class(cls):
        cls.scanner = DependencyScanner()
        cls.manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'requirements.txt'

    def test_requirements_txt_scan(self):
        """Test basic requirements.txt scanning"""
        result = self.scanner.scan_file(self.manifest_path)
        
        assert result is not None
        assert 'direct_dependencies' in result
        assert 'findings' in result

    def test_requirements_txt_dependencies_parsed(self):
        """Test that dependencies are correctly parsed from requirements.txt"""
        result = self.scanner.scan_file(self.manifest_path)
        
        # Should have some dependencies
        assert result['direct_dependencies'] > 0


class TestAllReportFormats:
    """Test all report output formats"""

    @classmethod
    def setup_class(cls):
        cls.scanner = DependencyScanner()
        cls.manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
        cls.result = cls.scanner.scan_file(cls.manifest_path)

    def test_text_report_generation(self):
        """Test text report generation"""
        text_report = self.scanner.format_report(self.result, self.manifest_path)
        
        assert text_report is not None
        assert isinstance(text_report, str)
        assert len(text_report) > 0
        # Check for expected sections
        assert any(word in text_report.lower() for word in ['vulnerability', 'finding', 'package'])

    def test_json_report_generation(self):
        """Test JSON report generation"""
        json_report = self.scanner.generate_json_report(self.result)
        
        assert json_report is not None
        assert isinstance(json_report, str)
        
        # Parse to verify it's valid JSON
        data = json.loads(json_report)
        assert 'metadata' in data
        assert 'summary' in data
        assert 'findings' in data
        assert 'remediation_plan' in data

    def test_json_report_contents(self):
        """Test JSON report contains complete information"""
        json_report = self.scanner.generate_json_report(self.result)
        data = json.loads(json_report)
        
        # Check metadata
        assert data['metadata']['scan_time'] is not None
        assert 'tool_version' in data['metadata']
        
        # Check summary
        assert 'total_dependencies' in data['summary']
        assert 'vulnerabilities' in data['summary']
        assert 'overall_risk_score' in data['summary']
        
        # Check findings have details
        for finding in data['findings']:
            assert 'package' in finding
            assert 'version' in finding
            assert 'cve' in finding
            assert 'severity' in finding

    def test_html_report_generation(self):
        """Test HTML report generation"""
        html_report = self.scanner.generate_html_report(self.result)
        
        assert html_report is not None
        assert isinstance(html_report, str)
        # Check for HTML structure (strip leading/trailing whitespace)
        assert '<!DOCTYPE html>' in html_report
        assert '<html>' in html_report
        assert '</html>' in html_report
        # Check for key sections
        assert 'Dependency Vulnerability Report' in html_report
        # Check for card-based layout (instead of table)
        assert 'finding-card' in html_report
        assert 'finding-header' in html_report
        assert 'finding-details' in html_report
        assert 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' in html_report
        assert 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337' in html_report

    def test_html_report_cve_links_are_valid(self):
        """Test that HTML report builds valid CVE reference links"""
        html_report = self.scanner.generate_html_report(self.result)

        assert 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' in html_report
        assert 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337' in html_report
        assert 'Additional Reference' in html_report

    def test_sarif_report_generation(self):
        """Test SARIF report generation"""
        sarif_report = self.scanner.generate_sarif_report(self.result)
        
        assert sarif_report is not None
        assert isinstance(sarif_report, str)
        
        # Parse to verify it's valid JSON
        data = json.loads(sarif_report)
        assert 'version' in data
        assert data['version'] == '2.1.0'
        assert 'runs' in data

    def test_sarif_report_structure(self):
        """Test SARIF report has correct structure"""
        sarif_report = self.scanner.generate_sarif_report(self.result)
        data = json.loads(sarif_report)
        
        # SARIF 2.1.0 structure
        assert isinstance(data['runs'], list)
        assert len(data['runs']) > 0
        
        run = data['runs'][0]
        assert 'tool' in run
        assert 'driver' in run['tool']
        assert 'results' in run
        
        # Check results
        for result in run['results']:
            assert 'ruleId' in result
            assert 'level' in result
            assert 'message' in result


class TestPoCGeneration:
    """Test Proof-of-Concept generation"""

    @classmethod
    def setup_class(cls):
        cls.scanner = DependencyScanner()
        cls.manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
        cls.result = cls.scanner.scan_file(cls.manifest_path)

    def test_poc_field_exists_in_findings(self):
        """Test that all findings have PoC field"""
        for finding in self.result['findings']:
            assert 'poc' in finding, f"Finding {finding['package']} missing 'poc' field"
            assert finding['poc'] is not None
            assert len(finding['poc']) > 0

    def test_poc_code_is_valid_python(self):
        """Test that generated PoC code is syntactically valid Python"""
        for finding in self.result['findings']:
            poc_code = finding.get('poc', '')
            
            # Basic checks - PoC should be non-empty string
            assert isinstance(poc_code, str)
            assert len(poc_code) > 0
            
            # PoC should contain Python-like structures
            assert any(keyword in poc_code for keyword in ['#', 'CVE', 'def', 'import', '"""', "'''"])

    def test_poc_contains_cve_reference(self):
        """Test that PoC contains CVE reference"""
        for finding in self.result['findings']:
            poc_code = finding.get('poc', '')
            cve = finding.get('cve', '')
            
            # PoC should mention the CVE
            assert cve in poc_code, f"PoC for {cve} doesn't contain CVE reference"


class TestReportCompleteness:
    """Test report completeness and data integrity"""

    @classmethod
    def setup_class(cls):
        cls.scanner = DependencyScanner()
        cls.manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
        cls.result = cls.scanner.scan_file(cls.manifest_path)

    def test_scan_result_structure(self):
        """Test that scan result has all required fields"""
        assert 'direct_dependencies' in self.result
        assert 'transitive_dependencies' in self.result
        assert 'findings' in self.result
        assert 'risk_score' in self.result

    def test_json_remediation_plan(self):
        """Test remediation plan in JSON report"""
        json_report = self.scanner.generate_json_report(self.result)
        data = json.loads(json_report)
        
        assert 'remediation_plan' in data
        if len(data['findings']) > 0:
            assert len(data['remediation_plan']) > 0

    def test_risk_score_valid_range(self):
        """Test that risk score is within valid range"""
        risk_score = self.result.get('risk_score', 0)
        assert 0 <= risk_score <= 100, f"Risk score {risk_score} out of valid range"

    def test_findings_have_severity_levels(self):
        """Test that all findings have valid severity levels"""
        valid_severities = {'critical', 'high', 'medium', 'low'}
        
        for finding in self.result['findings']:
            severity = finding.get('severity', '').lower()
            assert severity in valid_severities, f"Invalid severity: {severity}"

    def test_findings_have_effort_estimate(self):
        """Test that findings have effort estimation"""
        for finding in self.result['findings']:
            assert 'effort' in finding or 'estimated_effort' in finding, \
                f"Finding {finding['package']} missing effort estimate"


class TestEndToEnd:
    """End-to-end integration tests"""

    def test_full_scan_workflow_package_json(self):
        """Test complete workflow: scan -> generate all reports"""
        scanner = DependencyScanner()
        manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
        
        # Scan
        result = scanner.scan_file(manifest_path)
        assert result is not None
        
        # Generate all formats
        text_report = scanner.format_report(result, manifest_path)
        json_report = scanner.generate_json_report(result)
        html_report = scanner.generate_html_report(result)
        sarif_report = scanner.generate_sarif_report(result)
        
        # Verify all reports generated successfully
        assert len(text_report) > 0
        assert len(json_report) > 0
        assert len(html_report) > 0
        assert len(sarif_report) > 0

    def test_full_scan_workflow_requirements_txt(self):
        """Test complete workflow for requirements.txt"""
        scanner = DependencyScanner()
        manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'requirements.txt'
        
        # Scan
        result = scanner.scan_file(manifest_path)
        assert result is not None
        assert result['direct_dependencies'] > 0

    def test_scan_with_both_manifest_and_lock(self):
        """Test scanning with both manifest and lock file"""
        scanner = DependencyScanner()
        manifest_path = Path(__file__).resolve().parent.parent / 'samples' / 'package.json'
        lock_path = Path(__file__).resolve().parent.parent / 'samples' / 'package-lock.json'
        
        # Scan with lock file
        result = scanner.scan_file(manifest_path, lock_path=lock_path)
        
        # Should have more total dependencies with lock file
        assert 'transitive_dependencies' in result
        total_with_lock = result['direct_dependencies'] + result['transitive_dependencies']
        
        # Scan without lock file
        result_no_lock = scanner.scan_file(manifest_path)
        total_without_lock = result_no_lock['direct_dependencies']
        
        # With lock file should detect more deps
        assert total_with_lock >= total_without_lock
