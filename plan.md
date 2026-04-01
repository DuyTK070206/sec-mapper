# Kế hoạch 2 tuần: Triển khai Sec Mapper

## Mục tiêu chính
Trong 2 tuần phải hiện thực một công cụ theo proposal `Sec_Mapper.md`:
- parse manifest (npm/pip) và lấy dependency
- match dependency với danh sách vulnerability
- produce report đơn giản
- có demo chạy được và test cơ bản

---

## Tuần 1: Xây dựng chức năng cơ bản

### Ngày 1-2: Chuẩn bị và phân tích
- Đọc kỹ `Sec_Mapper.md` để định nghĩa scope.
- Xác định input/output: `package.json`, `requirements.txt` → report text/json/html.
- Kiểm tra repo hiện có: `main.py`, `src/`, `tests/`.

### Ngày 3-5: Parser và dependency extractor
- Hoàn thiện parser cho:
  - `package.json`
  - `requirements.txt`
- Kiểm tra parser bằng unit test.
- Lưu dependency names và version specifier.

### Ngày 6-7: Vulnerability matcher
- Triển khai database mẫu chứa CVE.
- Viết logic so khớp version/affected range.
- Đảm bảo matcher trả về vulnerability list cho dependency.
- Làm test cho matcher.

---

## Tuần 2: Báo cáo, test và hoàn thiện demo

### Ngày 8-10: Scanner và báo cáo
- Kết hợp parser + matcher thành scanner.
- Viết `main.py` chạy được với `samples/package.json` và `samples/requirements.txt`.
- Thêm báo cáo text.
- Test nhanh chạy cục bộ.

### Ngày 11-12: Mở rộng báo cáo
- Thêm xuất JSON.
- Thêm xuất HTML đơn giản.
- Tạo ví dụ report mẫu.

### Ngày 13-14: Hoàn thiện và review
- Viết README hướng dẫn chạy.
- Chạy `pytest` để đảm bảo test pass.
- Chuẩn bị summary demo để trình bày buổi review.

---

## File cần có sau 2 tuần
- `Sec_Mapper.md` (proposal/report)
- `main.py`
- `src/` bao gồm parser, scanner, vulnerability matcher, report generator
- `samples/` ví dụ
- `requirements.txt`
- `tests/` test cơ bản
- `README` hướng dẫn sử dụng

---

## Ghi chú quan trọng
- Bắt đầu làm từ feature nhỏ nhất: parse + match.
- Nếu thiếu thời gian, ưu tiên làm xong scan đơn giản trước rồi mở rộng report.
- Chạy thử luôn mỗi khi hoàn thành 1 module.
- Nên comment rõ ràng và giữ code dễ hiểu.
