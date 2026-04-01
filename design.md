# Sec Mapper - Future Design Ideas

## 1. Mở rộng hỗ trợ nhiều hệ sinh thái
- Thêm parser cho `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`, `Gemfile`.
- Hỗ trợ cả manifest trực tiếp và lockfile (ví dụ `package-lock.json`, `Pipfile.lock`, `poetry.lock`).

## 2. Quét phụ thuộc transitive
- Xây dựng dependency tree để xác định dependencies gián tiếp.
- Quét tất cả các nút trong cây để phát hiện lỗ hổng ẩn.
- Hiển thị đường đi dependency từ package gốc đến package bị lỗ hổng.

## 3. Kết nối với nguồn dữ liệu thực tế
- Tích hợp GitHub Advisory API hoặc NVD API.
- Tạo cache local để tránh gọi API quá nhiều.
- Cập nhật dữ liệu định kỳ và đồng bộ CVE mới.

## 4. Tự động tạo PoC / gợi ý khai thác
- Với mỗi vulnerability, lưu mẫu exploit hoặc payload đơn giản.
- Sinh báo cáo ghi rõ: có thể khai thác không, kiểu tấn công, và bước kiểm thử.
- Nếu không thể tạo PoC thực tế thì ít nhất lưu “exploitability” và “recommendation”.

## 5. Báo cáo nâng cao
- Xuất thêm SARIF để tích hợp với GitHub/GitLab.
- Tạo dashboard HTML tương tác với lọc severity, package, ecosystem.
- Xuất PDF summary cho giám sát và compliance.

## 6. Scoring và ưu tiên vá lỗi
- Tính điểm ưu tiên dựa trên:
  - severity/CVSS
  - exploitability
  - mức độ sử dụng trong dự án
  - direct vs transitive
- Gợi ý thứ tự fix: critical trước, direct trước, patch dễ hơn trước.

## 7. CI/CD integration
- Viết workflow GitHub Actions/ GitLab CI để tự động quét khi push.
- Tạo badge trạng thái scan.
- Tự động tạo issue khi phát hiện vulnerability mới.

## 8. Phân tích rủi ro theo ngữ cảnh dự án
- Xác định package nào đang được import/ dùng thật sự.
- Không chỉ dựa vào dependency tree mà còn phân tích code base.
- Giảm false positives bằng cách ưu tiên lỗ hổng trong gói được sử dụng trực tiếp.

## 9. Tối ưu UX cho báo cáo
- Thêm giao diện CLI trực quan hơn: bảng, màu sắc, summary ngắn.
- Xuất report theo định dạng markdown để dễ nộp và đọc.
- Thêm log chi tiết cho developer.

## 10. Mở rộng thành sản phẩm hoàn chỉnh
- Thiết kế plugin VS Code để quét trực tiếp trong editor.
- Xây dựng web app demo cho kết quả scan.
- Thêm chức năng so sánh hai scan (trước/sau patch).

## Lời kết
Những ý tưởng này giúp bài tập phát triển từ một đồ án demo thành một công cụ hữu ích hơn, phù hợp với yêu cầu thực tế và có thể show được tiến độ tốt khi thầy review.
