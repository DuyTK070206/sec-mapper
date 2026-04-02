# Dependency Vulnerability Mapper - Project Documentation

## Mục tiêu

Tài liệu này mô tả ý nghĩa và nhiệm vụ của các file, class quan trọng trong dự án.

---

## 1. File chính: `main.py`

- CLI entrypoint.
- Nhận tham số:
  - `manifest` (package.json / requirements.txt / pom.xml ...)
  - `--lock` (package-lock.json)
  - `--vuln-db` (đường dẫn custom JSON DB)
  - `--format` (text/json/html/sarif)
  - `--sync` (đồng bộ NVD)
- Khởi tạo `DependencyScanner` và gọi scan
- Xuất báo cáo loại theo format

## 2. `src/dependency_parser.py`

### Classes

- `DependencyParser` (ABC): abstract base parser.
- `ParsedDependency`: model dependency (name, version, ecosystem, is_transitive, children).
- `NpmPackageJsonParser`: parser package.json.
- `PackageLockParser`: parser package-lock.json (transitive deps).
- `PythonRequirementsParser`: parser requirements.txt.
- `MavenPomXmlParser`: parser pom.xml.
- `ParserFactory`: factory select parser theo filename tạo.

## 3. `src/dependency_tree_builder.py`

- Xây dựng dependency tree từ môi trường (npm / pip / maven) bằng công cụ hệ thống.
- `build_npm_tree`: chạy `npm ls --json`.
- `build_python_tree`: chạy `pipdeptree`.
- `build_maven_tree`: chạy `mvn dependency:tree`.

## 4. `src/version_resolver.py`

- `VersionResolver`: logic resolve version specifiers.
- Methods: `resolve_npm_version`, `_resolve_range`, `_apply_constraint`.
- Đọc `^`, `~`, range, exact, latest.

## 5. `src/vulnerability_manager.py`

- `VulnerabilityManager`: load vulnerabilities từ JSON (`src/vuln_db.json`) hoặc custom.
- `find_vulnerabilities(name, version, ecosystem)`: trả danh sách vulns phù hợp.
- Chuyển conversion NPM spec và so sánh range.
- Cơ chế offline fallback.

## 6. `src/vulnerability_matcher.py`

- `VulnerabilityMatcher`: mapping dependencies -> vulnerabilities.
- `match_dependencies(dependencies, ecosystem)`.
- `calculate_risk_score(dependency, vulnerabilities, project_context)`.
- `estimating effort`: low/medium/high.

## 7. `src/nvd_database.py`

- `NVDDatabase`: integration NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0).
- SQLite local cache `nvd_cache.db`.
- `fetch_vulnerability(cve_id)`, `sync_recent(days)`.
- Parse API response, lưu cache.

## 8. `src/github_advisories.py`

- `GitHubAdvisories`: fetch GitHub Security advisories.
- `fetch_advisories(ecosystem, severity)`.
- `search_package_advisories(ecosystem, package_name)`.

## 9. `src/exploit_generator.py`

- `ExploitGenerator` (ABC): interface generate PoC.
- Implementations:
  - `SQLInjectionExploit`
  - `CommandInjectionExploit`
  - `XXEExploit`
  - `PrototypePollutionExploit`
  - `RCEExploit`
- `ExploitGeneratorFactory`: chọn generator dựa trên CWE/description.

## 10. `src/scanner.py`

- `DependencyScanner`: orchestration chính.
- `scan_file(manifest_path, lock_path=None)`: parse -> match -> đánh giá -> thêm PoC.
- `format_report(scan_result, manifest_path)` (text).
- `generate_json_report(scan_result)`
- `generate_html_report(scan_result)`
- `generate_sarif_report(scan_result)`.
- `calculate_overall_risk_score`, `_estimate_effort`.

## 11. `src/report_generator.py`

- `ReportGenerator`: hỗ trợ report format khác nhau.
- `generate_json_report()`, `generate_html_report()`, `generate_sarif_report()`.
- ` _generate_remediation_plan()`, `_check_breaking_changes()`, `_get_testing_requirements()`.

## 12. `src/vuln_db.json`

- Sample vulnerability database (lodash, follow-redirects, urllib3, requests, log4j).
- Dùng cho lookup offline, demo.

## 13. tests/

- `test_dependency_parser.py`: unit tests parser.
- `test_integration.py`: integration scan + PoC + sarif/json.
- `test_performance.py`: speed tests.
- `test_comprehensive_samples.py`: end-to-end full coverage.

---

## Luồng dữ liệu chính

1. `main.py` gọi `DependencyScanner.scan_file`
2. Parser parse manifest -> list `ParsedDependency`
3. `VulnerabilityManager.find_vulnerabilities` (local + NVD/GitHub)
4. `ExploitGeneratorFactory` tạo PoC
5. `ReportGenerator` xuất báo cáo
6. Output: text/json/html/sarif

---

## Lưu ý mở rộng

- Thêm parser `go.mod`, `build.gradle`, `Gemfile` tại `dependency_parser.py`.
- Kết nối NVD/GitHub live với API key.
- Tạo GitHub Actions + Docker.
