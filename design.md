# Sec Mapper - Future Design and Upgrade Plan

## 1. Hiện trạng thiết kế
Tool hiện tại đã xử lý được:
- Quét `package.json` và `requirements.txt`.
- Hợp nhất `package-lock.json` để phát hiện dependency transitive.
- So khớp với database mẫu `src/vuln_db.json`.
- Xuất báo cáo text, JSON, HTML và SARIF.

## 2. Mục tiêu nâng cấp
Mục tiêu tiếp theo là chuyển đổi prototype thành công cụ có thể dùng thực tế hơn bằng cách:
- Hỗ trợ nhiều hệ sinh thái hơn.
- Kết nối với nguồn dữ liệu CVE thực.
- Cải thiện độ chính xác version matching.
- Mở rộng báo cáo và tích hợp CI.

## 3. Lộ trình nâng cấp

### Giai đoạn 1: Ổn định và hoàn thiện
- Cải thiện parser hiện tại, thêm đọc được `Pipfile.lock`, `poetry.lock` và `go.mod`.
- Hoàn thiện parser `pom.xml` và thêm `build.gradle` nếu có thời gian.
- Kiểm tra lại `package-lock.json` nhiều dạng để đảm bảo merge transitive chính xác.
- Chuẩn hóa dữ liệu đầu ra: `findings`, `risk_score`, `recommended_version`.

### Giai đoạn 2: Dữ liệu CVE thật và cache
- Kết nối trực tiếp với GitHub Advisory API.
- Kết nối NVD API để bổ sung dữ liệu.
- Tạo cache SQLite cho CVE/NVD để giảm rate-limit và tăng tốc.
- Thêm `--sync` nâng cao với lịch đồng bộ định kỳ.

### Giai đoạn 3: Phân tích dependency tree
- Xây dựng cây dependency thật sự thay vì chỉ tập hợp package.
- Gắn nhãn rõ ràng direct vs transitive và đường dẫn dependency.
- Hiển thị dependency path trong báo cáo.
- Ưu tiên fix vulnerabilities nằm sâu nhất có ảnh hưởng lớn.

### Giai đoạn 4: Báo cáo và CI integration
- Hoàn thiện SARIF export để dùng với GitHub Actions/GitLab.
- Tạo dashboard HTML tương tác, filter theo severity/ecosystem.
- Xuất báo cáo Markdown hoặc PDF cho nộp báo cáo.
- Viết workflow GitHub Action demo auto scan khi push.

### Giai đoạn 5: Open source / sản phẩm
- Gói thành command-line tool và README hướng dẫn rõ ràng.
- Viết test cover parser, matcher, report generator.
- Tạo ví dụ `samples/` đa hệ sinh thái.
- Có thể mở rộng thành plugin VS Code hoặc web demo.

## 4. Phương án cải tiến kỹ thuật chi tiết

### Parsing và dependency resolution
- Dùng `pipdeptree`/`npm ls --json` cho dependency tree thực tế.
- Với Python, parse `requirements.txt` và lockfile để xác định version đã cài.
- Với npm, `package-lock.json` cần gộp đầy đủ dependencies và parent path.
- Với Maven/Gradle, thêm parser để đọc `pom.xml` và `build.gradle`.

### Vulnerability matching
- Rõ ràng tách local DB và external source.
- Tránh match quá rộng bằng cách dùng version range chính xác.
- Thêm cơ chế fallback: local DB → GitHub → NVD.
- Ghi nhận `patched_version` và `has_patch` thật sự từ advisory.

### Risk scoring
- Dùng CVSS, exploitability, patch availability, direct/transitive.
- Cân nhắc thêm độ nguy hiểm theo mức độ sử dụng package trong dự án.
- Xuất priority recommendation theo tiêu chí:
  - Critical first
  - Direct trước transitive
  - Patch sẵn trước

### Báo cáo
- HTML: interactive, tìm kiếm, filter, link CVE.
- JSON: cấu trúc machine-readable để dùng CI.
- SARIF: tích hợp IDE/GitHub.
- Markdown/PDF: dùng cho nộp báo cáo và chia sẻ.

## 5. Những điểm cần lưu ý
- Phiên bản hiện tại là prototype, không thay thế công cụ sản xuất.
- Dữ liệu CVE thực cần xác thực chứ không nên dựa hoàn toàn trên pattern matching.
- Version matching npm/pip có thể phức tạp với syntax `^`, `~`, `>=`, `<=`.
- Cần thêm quá trình test và validate với nhiều cấu trúc project.

## 6. Kết luận
Nâng cấp công cụ theo lộ trình này sẽ giúp biến ý tưởng demo thành một công cụ kiểm thử dependency thực tế, phù hợp với kỳ vọng đề bài và có khả năng trình diễn tốt khi báo cáo.
