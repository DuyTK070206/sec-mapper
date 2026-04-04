# Dependency Vulnerability Mapper - Tài liệu Dự án

**Phiên bản:** 1.0.0  
**Ngôn ngữ:** Python 3.8+  
**Trạng thái:** Sẵn sàng sử dụng ✅

---

## 📋 Mục lục

1. [Tổng quan dự án](#tổng-quan-dự-án)
2. [Kiến trúc & Luồng dữ liệu](#kiến-trúc--luồng-dữ-liệu)
3. [Cấu trúc dự án](#cấu-trúc-dự-án)
4. [Các thành phần chính](#các-thành-phần-chính)
5. [Quy trình thực thi](#quy-trình-thực-thi)
6. [Tham chiếu API](#tham-chiếu-api)
7. [Ví dụ](#ví-dụ)
8. [Kiểm thử](#kiểm-thử)
9. [Nâng cấp tương lai](#nâng-cấp-tương-lai)

---

## 🎯 Tổng quan dự án

### Mục đích
**Dependency Vulnerability Mapper** là một công cụ quét bảo mật sẵn sàng sản xuất, có khả năng:
- Tự động phát hiện dependency dễ bị tấn công trong dự án phần mềm
- Phân tích nhiều hệ sinh thái quản lý gói (npm, pip, Maven, v.v.)
- Tạo đề xuất khắc phục cụ thể với đánh giá mức độ nghiêm trọng
- Xuất báo cáo chi tiết ở nhiều định dạng (text, JSON, HTML, SARIF)
- Cung cấp PoC (proof-of-concept) để xác thực lỗ hổng

### Tính năng chính
- ✅ **Hỗ trợ đa hệ sinh thái**: npm, Python pip, Maven, Gradle (dự kiến), Go modules (dự kiến), Ruby Gems (dự kiến)
- ✅ **Phân tích dependency truyền thẳng**: Phát hiện lỗ hổng trong dependency lồng nhau
- ✅ **Đánh giá rủi ro thông minh**: Điểm rủi ro 0-100 dựa trên mức độ nghiêm trọng, độ khó và khả năng khai thác
- ✅ **Tích hợp NVD**: Đồng bộ thời gian thực với National Vulnerability Database v2.0
- ✅ **Sinh PoC tự động**: 5 loại khai thác (SQLi, Command Injection, XXE, Prototype Pollution, RCE)
- ✅ **Báo cáo đa định dạng**: Text (ASCII-safe), JSON (máy đọc được), HTML (tương tác), SARIF (tích hợp GitHub)
- ✅ **Hỗ trợ ngoại tuyến**: Hoạt động khi không có Internet bằng cơ sở dữ liệu cache
- ✅ **Độ phủ kiểm thử cao**: 33+ bài kiểm thử tự động cho các luồng chính

---

## 🏗️ Kiến trúc & Luồng dữ liệu

### Kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Entry Point                      │
│                    (main.py)                            │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Dependency Scanner                         │
│           (src/scanner.py)                              │
│  - Điều phối toàn bộ quy trình quét                    │
│  - Quản lý tạo báo cáo                                  │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┼────────────┬──────────────┐
        ▼            ▼            ▼              ▼
    ┌────────┐  ┌─────────┐ ┌──────────┐  ┌────────────┐
    │ Parser │  │ Vuln    │ │ Exploit  │  │ Report     │
    │        │  │ Manager │ │ Generator│  │ Generator  │
    │(Parse) │  │ (Match) │ │(PoC Gen) │  │(Format Out)│
    └────────┘  └─────────┘ └──────────┘  └────────────┘
        │            │            │              │
        └────────────┼────────────┼──────────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  Output Report  │
            │ (text/json/html/│
            │  sarif)         │
            └─────────────────┘
```

### Luồng dữ liệu

**Bước 1: Phân tích đầu vào**
- `ParserFactory` xác định loại manifest (package.json, requirements.txt, pom.xml)
- `DependencyParser` (cụ thể theo triển khai) trích xuất dependency và phiên bản
- Lock file (tùy chọn) cung cấp thông tin dependency truyền thẳng
- Kết quả: danh sách các đối tượng `ParsedDependency`

**Bước 2: Phát hiện lỗ hổng**
- Với mỗi dependency: tên, phiên bản, ecosystem
- `VulnerabilityManager` truy vấn ba nguồn theo ưu tiên:
  1. Cache cục bộ (`vuln_db.json`)
  2. NVD API (nếu bật `--sync`)
  3. GitHub Security Advisories (nếu bật)
- So khớp phiên bản: giải quyết spec (^, ~, range) thành các phiên bản thực tế
- Kết quả: danh sách CVE phù hợp với metadata

**Bước 3: Đánh giá rủi ro**
- Tính điểm rủi ro (0-100) cho mỗi phát hiện:
  - Trọng số severity: Critical(40) + High(20) + Medium(10) + Low(5)
  - Khả năng khai thác: PoC có sẵn (+20), exploit known (+15), lý thuyết (+5)
  - Độ khó vá: Low(-5), Medium(0), High(+10)
- Ước lượng effort vá: LOW/MEDIUM/HIGH
- Kiểm tra thay đổi phá vỡ khi gợi ý patch

**Bước 4: Sinh PoC** (Tùy chọn)
- `ExploitGeneratorFactory` xác định loại khai thác dựa trên metadata CVE
- Sinh mã PoC thực tế (Python/JavaScript)
- Hỗ trợ: SQLi, Command Injection, XXE, Prototype Pollution, RCE

**Bước 5: Tạo báo cáo**
- Định dạng theo flag `--format`
- Text: Dễ đọc với định dạng ASCII-safe
- JSON: Máy đọc được với metadata đầy đủ
- HTML: Dashboard tương tác với CVE có thể mở rộng
- SARIF: JSON tương thích GitHub CI/CD

---

## 📁 Cấu trúc dự án

```
d:\ASSIGNMENT_RAISE\
├── main.py                         # CLI entry point
├── requirements.txt                # Python dependencies
├── PROJECT_DOCUMENTATION.md        # Tài liệu này
├── README                          # Hướng dẫn nhanh
├── Sec_Mapper.md                   # Specification (5 phases)
│
├── src/
│   ├── __init__.py
│   ├── scanner.py                  # Điều phối chính
│   ├── dependency_parser.py        # Parse manifest
│   ├── dependency_tree_builder.py  # Xây cây dependency (npm/pip/maven CLI)
│   ├── version_resolver.py         # Giải quyết phiên bản
│   ├── vulnerability_manager.py    # Nạp & so khớp lỗ hổng
│   ├── vulnerability_matcher.py    # Đánh giá rủi ro (placeholder)
│   ├── nvd_database.py             # Tích hợp NVD API
│   ├── github_advisories.py        # Tích hợp GitHub Advisories
│   ├── exploit_generator.py        # Sinh PoC khai thác
│   ├── report_generator.py         # Tạo báo cáo đa định dạng
│   └── vuln_db.json                # Database lỗ hổng mẫu
│
├── samples/
│   ├── package.json                # npm manifest (mẫu)
│   ├── package-lock.json           # npm lock file
│   ├── requirements.txt            # Python manifest (mẫu)
│   ├── package.report.html         # Báo cáo HTML sinh ra
│   └── package.sarif.json          # Báo cáo SARIF sinh ra
│
└── tests/
    ├── test_dependency_parser.py   # Unit test parser
    ├── test_integration.py         # Kiểm thử end-to-end
    ├── test_performance.py         # Benchmark hiệu năng
    └── test_comprehensive_samples.py  # Kiểm thử toàn diện
```

---

## 🔧 Các thành phần chính

### 1. **main.py** - Điểm khởi chạy CLI

**Mục đích:** Giao diện dòng lệnh cho công cụ quét

**Hàm:**
- `build_parser()` → `ArgumentParser`
  - Xây dựng parser với các tùy chọn CLI
  - Trả về đối tượng argparse đã cấu hình
  
- `main()` → `None`
  - Điểm vào khi script chạy
  - Kiểm tra đầu vào, khởi tạo scanner, chạy quét, xuất kết quả

**Tham số CLI:**
```
positional:
  manifest              đường dẫn tới package.json, requirements.txt, pom.xml, v.v.

optional:
  --lock               đường dẫn lock file (package-lock.json, poetry.lock, v.v.)
  --vuln-db           đường dẫn database lỗ hổng JSON tùy chỉnh
  --format            định dạng đầu ra: text (mặc định), json, html, sarif
  --sync              đồng bộ dữ liệu CVE mới nhất từ NVD trước khi quét
```

**Ví dụ:**
```bash
# Quét cơ bản với đầu ra text
python main.py samples/package.json

# Quét với lock file để tìm transitive deps
python main.py samples/package.json --lock samples/package-lock.json

# Tạo báo cáo HTML
python main.py samples/package.json --format html

# Đồng bộ NVD trước khi quét và xuất JSON
python main.py samples/requirements.txt --sync --format json
```

---

### 2. **src/scanner.py** - Điều phối chính

**Mục đích:** Điều phối toàn bộ quy trình quét

**Lớp chính: `DependencyScanner`**

**Phương thức:**

| Phương thức | Đầu vào | Kết quả | Mục đích |
|------------|---------|---------|----------|
| `__init__(db_path)` | Đường dẫn DB tùy chọn | None | Khởi tạo scanner với vulnerability manager |
| `scan_file(manifest, lock_path)` | Path manifest, Path lock tùy chọn | Dict | Hàm quét chính, trả kết quả scan |
| `_load_dependencies()` | Paths | List[ParsedDependency] | Nạp deps từ manifest và lock file |
| `_merge_dependencies()` | Root deps, lock deps | List[ParsedDependency] | Gộp dependency truyền thẳng, tránh trùng |
| `_dependency_counts()` | Dependencies | Tuple[int, int] | Đếm direct và transitive deps |
| `format_report()` | Kết quả scan, path manifest | str | Tạo báo cáo text dễ đọc |
| `generate_json_report()` | Kết quả scan | str | Tạo báo cáo JSON |
| `generate_html_report()` | Kết quả scan | str | Tạo báo cáo HTML tương tác |
| `generate_sarif_report()` | Kết quả scan | str | Tạo báo cáo SARIF tương thích GitHub |
| `_estimate_effort()` | Phiên bản hiện tại, fixed version, has_patch | str | Phân loại độ khó vá |
| `_calculate_overall_risk_score()` | Danh sách findings | int | Tính điểm rủi ro 0-100 |

**Cấu trúc dữ liệu quan trọng:**

```python
# ParsedDependency trả về bởi parser
{
    'name': str,               # Tên package
    'version': str,            # Phiên bản hoặc version spec
    'ecosystem': str,          # 'npm', 'pip', 'maven', v.v.
    'is_transitive': bool,     # True nếu dependency lồng nhau
    'source': str,             # 'package.json', 'package-lock.json'
    'dev_only': bool,          # Có phải dev dependency?
}

# Kết quả scan trả về từ scan_file()
{
    'project_name': str,       # Tên dự án
    'scan_time': str,          # ISO 8601 datetime
    'total_dependencies': int, # Tổng số dependency tìm được
    'direct_dependencies': int,
    'transitive_dependencies': int,
    'findings': List[Dict],    # Xem mô tả bên dưới
    'risk_score': int,         # 0-100
}

# Đối tượng Finding trong danh sách findings
{
    'package': str,            # Tên package
    'version': str,            # Phiên bản đang cài
    'ecosystem': str,          # 'npm', 'pip', v.v.
    'cve': str,                # CVE-YYYY-NNNN
    'severity': str,           # 'critical', 'high', 'medium', 'low'
    'description': str,        # Mô tả lỗ hổng
    'reference': str,          # Link tham chiếu
    'fixed_version': str,      # Phiên bản đã vá
    'has_patch': bool,         # Có patch không?
    'effort': str,             # 'low', 'medium', 'high'
    'recommended_version': str,# Phiên bản khuyến nghị
    'poc': str,                # Mã PoC khai thác
    'transitive': bool,        # Có phải dependency lồng nhau?
}
```

---

### 3. **src/dependency_parser.py** - Phân tích manifest

**Mục đích:** Trích xuất dependency từ các định dạng manifest khác nhau

**Lớp chính:**

| Lớp | Phân tích | Định dạng | Tính năng |
|-----|----------|----------|----------|
| `ParsedDependency` | N/A | Data model | Đại diện một dependency |
| `DependencyParser` (ABC) | N/A | Abstract | Giao diện cơ sở cho parser |
| `NpmPackageJsonParser` | package.json | JSON | Trích dependencies & devDependencies |
| `PackageLockParser` | package-lock.json / package-lock.json v3 | JSON | Trích transitive deps có lồng nhau |
| `PythonRequirementsParser` | requirements.txt | Text | Parse pip requirements với pinned/range versions |
| `MavenPomXmlParser` | pom.xml | XML | Trích dependency Maven theo scope |
| `ParserFactory` | Mọi manifest | Factory | Chọn parser theo tên file |

**Tham chiếu phương thức:**

```python
class ParsedDependency:
    def __init__(name, version, ecosystem, is_transitive=False, 
                 source='manifest', parent=None)
    # Thuộc tính:
    # - children: List[ParsedDependency]  # Dependency con
    # - dev_only: bool                     # Có phải dev dependency?

class DependencyParser(ABC):
    @abstractmethod
    def parse(manifest_content: str) -> List[ParsedDependency]
        """Phân tích manifest và trả về danh sách dependency"""

class ParserFactory:
    @staticmethod
    def get_parser(manifest_filename: str) -> DependencyParser
        """Chọn parser phù hợp theo tên file"""
        # package.json → NpmPackageJsonParser
        # package-lock.json → PackageLockParser
        # requirements.txt → PythonRequirementsParser
        # pom.xml → MavenPomXmlParser
```

**Manifest được hỗ trợ:**
- `package.json` (npm dependencies)
- `package-lock.json` (npm transitive)
- `requirements.txt` (Python pip)
- `pom.xml` (Maven Java)

**Hỗ trợ phiên bản:**
- **npm**: `^1.2.3`, `~1.2.3`, `1.2.3`, `>=1.0 <2.0`, `*`, `latest`
- **Python**: `==1.2.3`, `>=1.0,<2.0`, `~=1.2.3`
- **Maven**: Phiên bản chính xác, range `[1.0,2.0)`, `(,2.0)`

---

### 4. **src/vulnerability_manager.py** - Phát hiện lỗ hổng

**Mục đích:** Nạp lỗ hổng và so khớp với dependency

**Lớp chính: `VulnerabilityManager`**

**Phương thức:**

```python
class VulnerabilityManager:
    def __init__(db_path: Optional[str] = None)
        """Khởi tạo với database lỗ hổng mặc định hoặc tùy chỉnh"""
    
    def find_vulnerabilities(name: str, version_spec: str, 
                            ecosystem: str) -> List[Dict]
        """Tìm CVE phù hợp với package"""
        # Trả về list dict lỗ hổng phù hợp
    
    def _hits(affected_ranges: List[str], dependency_spec: str,
                ecosystem: str) -> bool
        """Kiểm tra nếu phiên bản dependency nằm trong range bị ảnh hưởng"""
        # Hỗ trợ so khớp range cho tất cả ecosystem
    
    def _normalize_npm_spec(version_spec: str) -> str
        """Chuyển spec npm ^ và ~ thành range so sánh được"""
        # ^1.2.3 → >=1.2.3,<2.0.0
        # ~1.2.3 → >=1.2.3,<1.3.0
```

**Định dạng database lỗ hổng:**

```json
{
  "cve_id": "CVE-2021-23337",
  "package": "lodash",
  "ecosystem": "npm",
  "severity": "high",
  "description": "Prototype pollution vulnerability",
  "affected_versions": ["<4.17.21"],
  "fixed_version": "4.17.21",
  "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
  "has_patch": true,
  "cwe": ["CWE-1321"]
}
```

**Luật so khớp phiên bản:**
1. Chuẩn hóa spec phiên bản (npm ^/~ → range)
2. Parse dependency spec thành `SpecifierSet`
3. Kiểm tra dependency có phù hợp với range bị ảnh hưởng
4. Trả về nếu có chồng lắp

---

### 5. **src/nvd_database.py** - Tích hợp NVD API

**Mục đích:** Lấy dữ liệu lỗ hổng thời gian thực từ NVD

**Lớp chính: `NVDDatabase`**

```python
class NVDDatabase:
    def __init__(api_key: Optional[str] = None, 
                 db_path: Optional[str] = None)
        """Khởi tạo client NVD với API key tùy chọn"""
        # Tạo cache SQLite tại nvd_cache.db
    
    def fetch_vulnerability(cve_id: str) -> Optional[Dict]
        """Lấy một CVE từ NVD API hoặc cache"""
        # Xử lý cache, gọi API, xử lý lỗi
        # Trả về dict lỗ hổng hoặc None
    
    def sync_recent(days: int = 7) -> int
        """Đồng bộ CVE đã chỉnh sửa trong N ngày gần nhất"""
        # Lấy từ NVD 2.0 API
        # Lưu cache cục bộ trong SQLite
        # Trả về số CVE mới được đồng bộ
```

**Tính năng:**
- ✅ Cache SQLite cục bộ (`nvd_cache.db`) để sử dụng ngoại tuyến
- ✅ Xử lý phân trang API (NVD trả tối đa 2000 bản ghi mỗi lần)
- ✅ Tự động làm mới cache (7+ ngày cũ)
- ✅ Tuân thủ giới hạn tần suất (120 req/phút nếu không có key, không giới hạn nếu có key)
- ✅ Fallback mềm dẻo về cache khi API không hoạt động

**Phân tích dữ liệu NVD:**
- Trích xuất CVE ID, mức độ nghiêm trọng (điểm CVSS), mô tả, mã CWE
- Ánh xạ sang định dạng lỗ hổng chung
- Cache kết quả phân tích trong 7 ngày tiếp theo

---

### 6. **src/exploit_generator.py** - Sinh PoC

**Mục đích:** Sinh mã PoC để xác thực lỗ hổng

**Các lớp chính:**

| Lớp | Loại khai thác | CWE | Ví dụ |
|-----|----------------|-----|-------|
| `SQLInjectionExploit` | SQL Injection | CWE-89 | Phát hiện truy vấn dễ bị tấn công |
| `CommandInjectionExploit` | OS Command Injection | CWE-78 | Thực thi lệnh shell |
| `XXEExploit` | XML External Entity | CWE-611 | Payload XXE với DTD |
| `PrototypePollutionExploit` | Prototype Pollution | CWE-1321 | Thao tác prototype JavaScript |
| `RCEExploit` | Remote Code Execution | CWE-94 | Khai thác Log4j JNDI |

**Tham chiếu phương thức:**

```python
class ExploitGenerator(ABC):
    @abstractmethod
    def generate_poc(vulnerability: Dict) -> Optional[str]
        """Sinh mã PoC cho loại lỗ hổng này"""
        # Trả về mã Python/JavaScript hoặc None

class ExploitGeneratorFactory:
    @staticmethod
    def get_generator(vulnerability: Dict) -> Optional[ExploitGenerator]
        """Tự động chọn generator dựa trên metadata CVE"""
        # Phân tích CWE và mô tả
        # Trả về generator phù hợp
```

**Đặc điểm PoC:**
- ✅ Mã hoạt động, có thể kiểm thử
- ✅ Trigger lỗ hổng rõ ràng kèm chú thích
- ✅ Target/payload dễ cấu hình
- ✅ Có logic xác minh
- ✅ An toàn chạy trong môi trường sandbox

**Ví dụ PoC:**
```python
# Prototype Pollution PoC - CVE-2021-23337 (lodash)
import requests
import json

target = "http://vulnerable-app.local/api/config"
payload = {
    "admin": {
        "__proto__": {
            "isAdmin": True
        }
    }
}

response = requests.post(
    target,
    json=payload,
    headers={"Content-Type": "application/json"}
)

verify_response = requests.get(target)
if verify_response.json().get("isAdmin"):
    print("[+] Prototype Pollution successful!")
```

---

### 7. **src/report_generator.py** - Báo cáo đa định dạng

**Mục đích:** Tạo báo cáo cho nhiều đối tượng khác nhau

**Lớp chính: `ReportGenerator`**

**Phương thức:**

```python
class ReportGenerator:
    def __init__(scan_result: Dict)
        """Khởi tạo generator báo cáo với dữ liệu scan"""
    
    def generate_json_report() -> str
        """Tạo báo cáo JSON máy đọc được"""
        # Bao gồm thời gian scan, thông tin dự án, tất cả findings
    
    def generate_html_report() -> str
        """Tạo dashboard tương tác với CVE có thể mở rộng"""
        # Click để mở rộng, nhiều liên kết tham chiếu
        # PoC trong khối mã có tô màu
    
    def generate_sarif_report() -> str
        """Tạo định dạng SARIF 2.1.0 tương thích GitHub"""
        # Tích hợp với tab GitHub Security
```

**Định dạng đầu ra:**

| Định dạng | Đối tượng | Mục đích | Tính năng |
|----------|-----------|----------|----------|
| **text** | Developer | Terminal | ASCII-safe, chi tiết |
| **json** | Công cụ/CI | Xử lý máy | Metadata đầy đủ |
| **html** | Quản lý | Duyệt web | Tương tác, trực quan |
| **sarif** | GitHub Actions | CI/CD | Chuẩn GitHub |

---

## 🔄 Quy trình thực thi

### Luồng thực thi đầy đủ

```
1. USER INPUT
   └─> python main.py samples/package.json --format html --sync

2. ARGUMENT PARSING (main.py)
   └─> Xác thực đường dẫn, parse CLI arguments

3. SCANNER INITIALIZATION (scanner.py)
   └─> Tạo DependencyScanner, nạp vulnerability manager
   
4. NVD SYNC (optional --sync flag)
   └─> NVDDatabase.sync_recent(days=7)
   └─> Lấy CVE mới nhất, cập nhật cache

5. DEPENDENCY LOADING (scanner._load_dependencies)
   ├─> ParserFactory xác định loại manifest
   ├─> NpmPackageJsonParser.parse(package.json)
   │   └─> Trả về List[ParsedDependency]
   ├─> PackageLockParser.parse(package-lock.json) [nếu có]
   │   └─> Trả về dependency truyền thẳng
   └─> scanner._merge_dependencies() gộp cả hai

6. VULNERABILITY MATCHING (scanner.scan_file loop)
   Với mỗi ParsedDependency:
   ├─> VulnerabilityManager.find_vulnerabilities(name, version, ecosystem)
   │   ├─> Query vuln_db.json cục bộ
   │   ├─> Query cache NVD nếu đã sync
   │   └─> Trả về CVE phù hợp
   │
   ├─> Với mỗi CVE tìm được:
   │   ├─> ExploitGeneratorFactory.get_generator(cve)
   │   ├─> Sinh mã PoC (hoặc None)
   │   ├─> Ước lượng effort vá (LOW/MEDIUM/HIGH)
   │   └─> Tạo dict Finding
   │
   └─> Thêm Finding vào kết quả

7. RISK SCORING (scanner._calculate_overall_risk_score)
   ├─> Trọng số mỗi finding theo severity
   ├─> Thêm bonus exploitability
   └─> Tính điểm rủi ro 0-100

8. REPORT GENERATION (scanner.generate_*_report)
   └─> Định dạng findings theo flag --format
       ├─> text: Dễ đọc, ASCII-safe
       ├─> json: Máy đọc được, metadata đầy đủ
       ├─> html: Dashboard tương tác
       └─> sarif: Tích hợp GitHub

9. OUTPUT
   ├─> text: In ra stdout
   ├─> json: In ra stdout
   ├─> html: Ghi file package.report.html
   └─> sarif: Ghi file package.sarif.json
```

### Ví dụ chạy nhanh

**Ví dụ 1: Quét npm cơ bản**
```bash
$ python main.py samples/package.json
# Output: Text report to stdout
```

**Ví dụ 2: Quét với transitive deps**
```bash
$ python main.py samples/package.json --lock samples/package-lock.json
# Output: Text report including transitive vulnerabilities
```

**Ví dụ 3: Tạo dashboard HTML**
```bash
$ python main.py samples/package.json --format html
# Output: samples/package.report.html
# → Mở trong trình duyệt, click CVE để xem chi tiết
```

**Ví dụ 4: Đồng bộ NVD và xuất JSON**
```bash
$ python main.py samples/requirements.txt --sync --format json
# Output: JSON với dữ liệu NVD mới nhất
```

---

## 📚 Tham chiếu API

### Chữ ký hàm đầy đủ & tham số

#### DependencyScanner

```python
class DependencyScanner:
    def scan_file(
        self,
        manifest_path: Path,
        lock_path: Optional[Path] = None
    ) -> Dict:
        """
        Hàm quét chính. Thực hiện toàn bộ workflow.
        
        Args:
            manifest_path: Đường dẫn đến manifest (package.json, ...)
            lock_path: Đường dẫn lock file tùy chọn
        
        Returns:
            dict: {
                'project_name': str,
                'scan_time': str (ISO 8601),
                'total_dependencies': int,
                'direct_dependencies': int,
                'transitive_dependencies': int,
                'findings': list of finding dicts,
                'risk_score': int (0-100)
            }
        
        Raises:
            FileNotFoundError: Nếu manifest/lock không tồn tại
            json.JSONDecodeError: Nếu manifest không hợp lệ
        """
```

#### VulnerabilityManager

```python
class VulnerabilityManager:
    def find_vulnerabilities(
        self,
        name: str,
        version_spec: str,
        ecosystem: str
    ) -> List[Dict]:
        """
        Tìm CVE phù hợp với package.
        
        Args:
            name: Tên package (ví dụ: 'lodash', 'requests')
            version_spec: Phiên bản hoặc range (ví dụ: '4.17.20', '^1.0', '>=1.0,<2.0')
            ecosystem: 'npm' | 'pip' | 'maven' | 'gradle' | 'gems'
        
        Returns:
            list: Dict lỗ hổng phù hợp
        
        Example:
            vulns = mgr.find_vulnerabilities('lodash', '4.17.20', 'npm')
            # Trả về: [{cve_id: CVE-2021-23337, severity: high, ...}]
        """
```

#### NVDDatabase

```python
class NVDDatabase:
    def sync_recent(
        self,
        days: int = 7
    ) -> int:
        """
        Đồng bộ CVE đã chỉnh sửa trong N ngày gần nhất.
        
        Args:
            days: Số ngày để đồng bộ (mặc định: 7)
        
        Returns:
            int: Số CVE mới được đồng bộ
        
        Raises:
            requests.RequestException: Nếu API không khả dụng
            sqlite3.Error: Nếu ghi cache thất bại
        """
    
    def fetch_vulnerability(
        self,
        cve_id: str
    ) -> Optional[Dict]:
        """
        Lấy một CVE từ cache hoặc API.
        
        Args:
            cve_id: Mã CVE (ví dụ: 'CVE-2021-23337')
        
        Returns:
            dict hoặc None: Dữ liệu lỗ hổng nếu tìm thấy
        """
```

---

## 💡 Ví dụ

### Ví dụ 1: Phân tích dự án npm

```bash
# 1. Quét package.json
$ python main.py samples/package.json --lock samples/package-lock.json

# Output:
# ============================================================
# DEPENDENCY VULNERABILITY SCAN REPORT
# ...
# [HIGH] lodash @ 4.17.20
#   CVE-2021-23337: Prototype pollution in lodash before 4.17.21.
#   Recommended: Update to 4.17.21 (LOW effort)
# ...
```

### Ví dụ 2: Dự án Python với NVD Sync

```bash
# 1. Đồng bộ CVE mới nhất từ NVD
$ python main.py samples/requirements.txt --sync

# 2. Tạo báo cáo JSON
$ python main.py samples/requirements.txt --format json > report.json

# 3. Phân tích JSON bằng công cụ
$ cat report.json | jq '.findings[] | select(.severity == "critical")'
```

### Ví dụ 3: Tích hợp CI/CD GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install scanner
        run: |
          pip install -r requirements.txt
      
      - name: Run vulnerability scan
        run: python main.py package.json --format sarif --sync
      
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: package.sarif.json
```

### Ví dụ 4: Database lỗ hổng tùy chỉnh

```bash
# Dùng database lỗ hổng tùy chỉnh
$ python main.py samples/package.json --vuln-db custom_vulns.json
```

---

## 🧪 Kiểm thử

### Độ phủ kiểm thử

**Tổng cộng: 33+ bài kiểm thử tự động**

```
tests/
├── test_dependency_parser.py       (3 tests)
│   └─ Parser functionality for JSON, text, XML
│
├── test_integration.py              (8 tests)
│   └─ End-to-end workflows, NVD integration
│
├── test_performance.py              (2 tests)
│   └─ Scan time benchmarks
└── test_comprehensive_samples.py   (20 tests)
    ├─ All 4 report formats
    ├─ PoC generation verification
    ├─ Risk scoring accuracy
    ├─ Transitive dependency detection
    └─ NVD caching behavior
```

### Chạy kiểm thử

```bash
# Chạy tất cả kiểm thử
python -m pytest tests -q

# Chạy file kiểm thử cụ thể
python -m pytest tests/test_dependency_parser.py -v

# Chạy với báo cáo coverage
python -m pytest tests --cov=src --cov-report=html

# Chạy kiểm thử cụ thể
python -m pytest tests/test_comprehensive_samples.py::TestAllReportFormats::test_html_report_generation -v
```

### Kết quả hiện tại

```
✅ 33/33 tests passing
✅ All report formats validated
✅ PoC generation verified
✅ Version resolution tested
✅ NVD caching tested
```

---

## 🚀 Nâng cấp tương lai

### Giai đoạn 1: Thêm package manager

**Gradle** (Java)
```gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:2.5.0'
}
```
- [ ] Parser: Trích dependencies Gradle
- [ ] Test: 3+ trường hợp kiểm thử
- [ ] Integration: Xác thực toàn bộ workflow

**Go modules** (Go)
```go
require github.com/pkg/errors v0.9.1
```
- [ ] Parser: Đọc go.mod
- [ ] Giải quyết phiên bản semantic
- [ ] Phủ kiểm thử

**Ruby Gems** (Ruby)
```ruby
gem 'rails', '~> 6.0.0'
```
- [ ] Parser: Gemfile và Gemfile.lock
- [ ] Tích hợp Bundler
- [ ] Hỗ trợ định nghĩa phiên bản

### Giai đoạn 2: Tính năng nâng cao

**Auto-Fix CLI (`--autofix` flag)**
```bash
python main.py package.json --autofix
# Tự động cập nhật dependency lên phiên bản đã vá
# Xác thực bằng npm install trước khi commit
```
- [ ] Phát hiện ràng buộc phiên bản
- [ ] Phân tích breaking change
- [ ] Tự động kiểm thử
- [ ] Tích hợp Git (tuỳ chọn)

**Tối ưu hiệu năng**
- [ ] Song song hóa việc so khớp lỗ hổng (đa luồng)
- [ ] Cache kết quả theo manifest
- [ ] Quét tăng dần (chỉ phần thay đổi)
- [ ] Xuất báo cáo dạng streaming

**Báo cáo nâng cao**
- [ ] Xuất PDF với biểu đồ
- [ ] Tích hợp email (gửi báo cáo qua SMTP)
- [ ] Phân tích xu hướng (lịch sử scan)
- [ ] Tạo báo cáo tuân thủ (CIS/PCI/HIPAA)

### Giai đoạn 3: Tính năng doanh nghiệp

**Tích hợp GitHub/GitLab**
- [ ] Tự động tạo issue bảo mật
- [ ] Comment PR với findings
- [ ] Quy tắc bảo vệ nhánh
- [ ] Tích hợp webhook

**CI/CD Integration**
- [ ] Jenkins plugin
- [ ] GitLab CI template
- [ ] AWS CodePipeline
- [ ] Azure Pipelines

**Lưu trữ đám mây**
- [ ] AWS S3 report storage
- [ ] Azure Blob Storage
- [ ] GCP Cloud Storage
- [ ] Lịch sử và phiên bản báo cáo

### Giai đoạn 4: Machine Learning (ML-Powered)

**Đánh giá rủi ro thông minh**
- [ ] Mô hình ML dự đoán mức độ khai thác
- [ ] Đánh giá tác động CVE
- [ ] Lọc false positive

**Threat Intelligence**
- [ ] Phát hiện exploit đang hoạt động
- [ ] Liên kết ransomware
- [ ] Dự đoán zero-day

---

## 📊 Ma trận trách nhiệm file

| File | Trách nhiệm | Trạng thái | Việc cần nâng cấp |
|------|------------|-----------|-------------------|
| main.py | Giao diện CLI | ✅ Hoàn chỉnh | Thêm verbose/logging |
| scanner.py | Điều phối | ✅ Hoàn chỉnh | Thêm progress indicator |
| dependency_parser.py | Parse manifests | ✅ 4 parser | Thêm gradle, go.mod, Gemfile |
| vulnerability_manager.py | So khớp lỗ hổng | ✅ Hoàn chỉnh | Hỗ trợ thêm kiểu so khớp |
| nvd_database.py | Tích hợp NVD | ✅ Hoàn chỉnh | Thêm rate limiting |
| exploit_generator.py | Sinh PoC | ✅ 5 loại | Thêm 3+ loại PoC |
| report_generator.py | Báo cáo đa định dạng | ✅ Hoàn chỉnh | Thêm PDF, email export |
| vuln_db.json | Database mẫu | ✅ 5 CVEs | Cơ chế tự động cập nhật |

---

## 🔐 Bảo mật

Công cụ này được thiết kế chỉ dành cho **phân tích bảo mật**:

- ✅ Không rò rỉ dữ liệu: Chỉ đọc file manifest cục bộ
- ✅ Không tự động thực thi PoC
- ✅ Hỗ trợ ngoại tuyến: Dùng cache khi không có mạng
- ✅ Kết quả có thể tái lập
- ✅ Có thể audit: Ghi lại đầy đủ findings và quyết định

**Dùng cho:**
- ✅ Đánh giá bảo mật
- ✅ Quản lý lỗ hổng
- ✅ Báo cáo tuân thủ
- ✅ Giảm thiểu rủi ro

**Không dùng cho:**
- ❌ Kiểm thử mạng trái phép
- ❌ Khai thác production
- [ ] Vượt qua cơ chế bảo mật

---

## 📝 Cộng tác

Để đóng góp cải tiến:

1. Fork repository
2. Tạo branch tính năng: `git checkout -b feature/name`
3. Thêm kiểm thử cho tính năng mới
4. Đảm bảo 33 tests chạy qua: `pytest tests -q`
5. Mở pull request với mô tả rõ ràng

---

## 📞 Hỗ trợ & Tài liệu

- **Báo lỗi**: Tạo issue với tiền tố [BUG]
- **Yêu cầu tính năng**: Tạo issue với tiền tố [FEATURE]
- **Câu hỏi**: Tạo discussion hoặc issue với tiền tố [QUESTION]

---

**Cập nhật lần cuối:** April 4, 2026  
**Phiên bản:** 1.0.0  
**Người quản lý:** Security Team