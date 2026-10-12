# Baseline — điền trong checkpoint 1

1. **Agent có identity mỗi run chưa? Dẫn file/hàm:**
Chưa có. Trong `agent/loop.py` tại hàm `_naive_loop(message, llm)` (dòng 27–56), agent thực thi mà không có định danh danh tính (`agent_id`), không có `run_id`, không có cơ chế OBO (`on_behalf_of` / principal) hay phân quyền phiên làm việc.

2. **Ai cho phép `http_post`? Dẫn file/hàm:**
Không có cơ chế ủy quyền hay Policy Enforcement Point (PEP) nào cho phép. Quyền gọi `http_post` do luồng điều khiển trong `agent/loop.py` tại `_naive_loop()` (dòng 34–44) tự động kích hoạt khi `llm.find_injection(combined_text)` trả về chỉ thị (bị điều khiển bởi untrusted prompt injection). Tại `agent/tools.py` hàm `http_post()` (dòng 68–86), chỉ có kiểm tra hard-coded allowlist IP/port (`127.0.0.1:10024`) chứ không có bất kỳ chính sách kiểm soát quyền truy cập hay kiểm tra dữ liệu egress nào.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:**
Bên trong agent không hề có audit ledger hay logging nội bộ để lưu vết. Bằng chứng duy nhất nằm ở phía server nhận (sink) tại file `reports/sink.log` do `sink/sink.py` hàm `make_handler.do_POST()` (dòng 42–51) ghi nhận lại toàn bộ body của HTTP request nhận được.
