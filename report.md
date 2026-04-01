# Sec Mapper Progress Report

## 1. Mục tiêu
- Hiện thực một công cụ `Dependency Vulnerability Mapper` theo proposal trong `Sec_Mapper.md`.
- Demo được với `package.json` và `requirements.txt`.
- Hỗ trợ quét transitive dependency bằng `package-lock.json`.
- Có báo cáo text, JSON và HTML.
- Có test để xác nhận chức năng.

## 2. Tiến độ hiện tại
### 2.1. Chức năng đã hoàn thành
- `main.py`
  - CLI quét `package.json` hoặc `requirements.txt`.
  - Hỗ trợ tuỳ chọn `--lock` để quét `package-lock.json`.
  - Hỗ trợ `--vuln-db` để dùng database lỗ hổng JSON tùy chỉnh.
  - Hỗ trợ xuất báo cáo `text`, `json`, `html`.
- `src/dependency_parser.py`
  - Parser cho `package.json`.
  - Parser cho `requirements.txt`.
  - Parser cho `package-lock.json`.
  - Parser cơ bản cho `pom.xml`.
- `src/vulnerability_manager.py`
  - Đọc database lỗ hổng từ `src/vuln_db.json`.
  - Match package/version với affected range.
- `src/scanner.py`
  - Tích hợp parser và vulnerability manager.
  - Cộng tổng direct/transitive dependencies.
  - Trả về danh sách findings và risk score.
- `src/report_generator.py`
  - Xuất báo cáo JSON.
  - Xuất báo cáo HTML.

### 2.2. Nội dung mẫu và test
- `samples/package.json`
- `samples/requirements.txt`
- `samples/package-lock.json`
- `src/vuln_db.json` chứa database lỗ hổng mẫu.
- `tests/test_dependency_parser.py` kiểm tra parser.
- `tests/test_integration.py` kiểm tra scanner với dữ liệu mẫu.
- Kết quả test: `7 passed`.

## 3. Kết quả chạy demo
### Quét direct dependency
- `python main.py samples\package.json`
- Phát hiện `lodash@4.17.20` có CVE-2021-23337.

### Quét transitive dependency
- `python main.py samples\package.json --lock samples\package-lock.json`
- Phát hiện `follow-redirects@1.10.0` là transitive dependency có CVE-2021-33901.

### Xuất báo cáo
- `python main.py samples\package.json --format json`
- `python main.py samples\package.json --format html`

## 4. Cấu trúc thư mục hiện tại
- `Sec_Mapper.md` — proposal / báo cáo đề tài.
- `main.py` — script CLI chính.
- `src/` — code logic chính.
  - `dependency_parser.py`
  - `vulnerability_manager.py`
  - `scanner.py`
  - `report_generator.py`
  - `vuln_db.json`
- `samples/` — file demo.
- `tests/` — test chức năng.
- `README` — hướng dẫn chạy.
- `report.md` — báo cáo tiến độ này.
- `design.md` — ý tưởng mở rộng.

## 5. Cách chạy nhanh
```powershell
cd c:\RAISE\sec-mapper\sec-mapper
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Chạy scan default
```powershell
python main.py samples\package.json
```

### Chạy scan với package-lock
```powershell
python main.py samples\package.json --lock samples\package-lock.json
```

### Xuất JSON
```powershell
python main.py samples\package.json --format json
```

### Xuất HTML
```powershell
python main.py samples\package.json --format html
```

### Chạy test
```powershell
python -m pytest tests -q
```

## 6. Ghi chú quan trọng
- Tool hiện tại phù hợp để demo ý tưởng quét vulnerability dependency.
- Database `src/vuln_db.json` có thể mở rộng bằng cách thêm CVE.
- Hiện tại vẫn còn có thể nâng cấp:
  - parse `poetry.lock` / `Pipfile.lock` / `go.mod`
  - lấy dữ liệu CVE thực từ GitHub Advisory hoặc NVD API
  - phân tích transitive dependency sâu hơn
  - xuất SARIF / dashboard

## 7. Next steps
- Nếu cần nộp buổi sau: chuẩn bị demo `package.json` + `package-lock.json`.
- Nếu muốn nâng cấp: bổ sung parser thêm và dữ liệu CVE sống.
- Nếu cần dùng thực tế: tích hợp API GitHub và xử lý nhiều hệ sinh thái.
