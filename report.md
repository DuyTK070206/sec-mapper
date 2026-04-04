# Sec Mapper Progress Report

## 1. Mục tiêu
- Hoàn thành prototype `Dependency Vulnerability Mapper`.
- Quét dependencies từ `package.json` và `requirements.txt`.
- Phát hiện vulnerabilities ở cả direct và transitive dependencies.
- Xuất báo cáo text, JSON, HTML và SARIF.
- Có test đảm bảo chức năng cơ bản.

## 2. Tiến độ hiện tại

### 2.1. Chức năng đã hoàn thành
- `main.py`
  - CLI quét `package.json` hoặc `requirements.txt`.
  - Hỗ trợ `--lock` để quét `package-lock.json`.
  - Hỗ trợ `--vuln-db` dùng database JSON tùy chỉnh.
  - Hỗ trợ xuất báo cáo `text`, `json`, `html`, `sarif`.
- `src/dependency_parser.py`
  - Parser cho `package.json`.
  - Parser cho `requirements.txt`.
  - Parser cho `package-lock.json`.
  - Parser cơ bản cho `pom.xml`.
- `src/vulnerability_manager.py`
  - Đọc database lỗ hổng từ `src/vuln_db.json`.
  - Match package/version với affected version ranges.
  - Có fallback query GitHub và NVD nếu cần.
- `src/scanner.py`
  - Tích hợp parser, vulnerability manager và exploit generator.
  - Tạo báo cáo scan với tổng number direct/transitive.
  - Tính risk score và ước tính effort fix.
- `src/report_generator.py`
  - Xuất báo cáo JSON, HTML và SARIF.

### 2.2. Dữ liệu mẫu và test
- `samples/package.json`
- `samples/requirements.txt`
- `samples/package-lock.json`
- `src/vuln_db.json` chứa database lỗ hổng mẫu.
- `tests/test_dependency_parser.py` kiểm tra parser.
- `tests/test_integration.py` kiểm tra luồng scan.

## 3. Kết quả chạy demo

### 3.1. Quét direct dependency
- `python main.py samples\package.json`
- Phát hiện `lodash@4.17.20` có CVE-2021-23337.

### 3.2. Quét transitive dependency
- `python main.py samples\package.json --lock samples\package-lock.json`
- Phát hiện `follow-redirects@1.10.0` là transitive dependency có CVE-2021-33901.

### 3.3. Xuất báo cáo
- `python main.py samples\package.json --format json`
- `python main.py samples\package.json --format html`
- `python main.py samples\package.json --format sarif`

## 4. Cấu trúc thư mục chính
- `README` — hướng dẫn sử dụng.
- `report.md` — báo cáo tiến độ.
- `design.md` — kế hoạch mở rộng.
- `main.py` — CLI chính.
- `generate_full_reports.py` — script tạo report mẫu.
- `debug_matching.py` — script debug matching.
- `src/` — logic chính.
  - `dependency_parser.py`
  - `vulnerability_manager.py`
  - `scanner.py`
  - `report_generator.py`
  - `vuln_db.json`
- `samples/` — dữ liệu mẫu.
- `tests/` — test chức năng.

## 5. Cách chạy nhanh

```powershell
cd c:\RAISE\sec-mapper\sec-mapper
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

```powershell
python main.py samples\package.json
python main.py samples\package.json --lock samples\package-lock.json
python main.py samples\package.json --format json
python main.py samples\package.json --format html
python main.py samples\package.json --format sarif
python -m pytest tests -q
```

## 6. Ghi chú quan trọng
- Tool hiện tại phù hợp để demo ý tưởng quét vulnerability dependency.
- Database mẫu `src/vuln_db.json` cần mở rộng để dùng thực tế.
- `pom.xml` parser đã có trong code nhưng chưa test đầy đủ.
- `--sync` có thể đồng bộ dữ liệu NVD/GitHub nếu cấu hình token.

## 7. Next steps
- Hoàn thiện parser cho nhiều system: `Pipfile.lock`, `poetry.lock`, `go.mod`, `Cargo.toml`.
- Tăng cường dữ liệu thật từ GitHub Advisory/NVD.
- Cải thiện chuyển đổi version range và dependency tree analysis.
- Chuẩn hóa SARIF và dashboard HTML cho môi trường CI.
