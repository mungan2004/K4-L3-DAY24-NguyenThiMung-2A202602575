# DPIA-lite — điền trong checkpoint 5

1. **Loại dữ liệu và phân loại:**
   - **Public / Internal:** Nội dung văn bản ticket hỗ trợ (`corpus/*.md`), định danh file ticket.
   - **Restricted (Dữ liệu cá nhân nhạy cảm):** Số Căn cước công dân (VN_CCCD 12 chữ số), Số điện thoại (VN_PHONE 10 chữ số), Số tài khoản ngân hàng (VN_BANK_ACCOUNT 8–16 chữ số), Địa chỉ Email trong cơ sở dữ liệu khách hàng (`data/customers.json`).

2. **Mục đích xử lý và principal:**
   - **Mục đích xử lý:** Tổng hợp thông tin ticket hỗ trợ (`summarize-tickets`), trả lời hỗ trợ khách hàng (`support-reply`), đối soát kiểm toán tuân thủ quyền riêng tư (`privacy-audit`).
   - **Principal và vai trò:**
     - `support_l1`: Chỉ được phép tìm kiếm văn bản ticket (`search_docs`), bị cấm hoàn toàn quyền đọc thông tin khách hàng nhạy cảm (`read_customer`).
     - `dpo`: Được phép truy cập hồ sơ khách hàng (`read_customer`) khi ticket có liên kết hợp lệ trong hệ thống đối soát nội bộ.
     - `billing`: Được phép truy xuất cho mục đích đối soát thanh toán.

3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - **Run A:** Nhận yêu cầu người dùng, gọi `search_docs` để đọc dữ liệu không tin cậy từ `corpus/`. Run A chỉ trích xuất duy nhất `ticket_ids` kiểu số nguyên từ tên file và chuyển giao qua boundary sang Run B. Toàn bộ free text của attacker bị giữ lại ở Run A.
   - **Run B:** Tiếp nhận danh sách `ticket_ids`, đối chiếu với `related_tickets` từ nguồn tin cậy `data/customers.json` để xác định `customer_id`. Gọi `read_customer` nếu Policy Enforcement Point (PEP) cấp quyền.
   - **Endpoint / Tool `http_post`:** Đích đến là endpoint localhost `http://127.0.0.1:10024/reconcile`. Tool này bị PEP chặn hoàn toàn (deny) khi xử lý dữ liệu restricted hoặc khi egress bị vô hiệu hóa.

4. **Bằng chứng deny/allow và giới hạn của mock:**
   - **Bằng chứng allow/deny:**
     - `reports/ledger.jsonl`: Dòng 1 ghi nhận `search_docs` ALLOW; các dòng 2–22 ghi nhận `read_customer` ALLOW cho principal `dpo`; dòng 23 ghi nhận `http_post` DENY với lý do rõ ràng `DENY: tool 'http_post' not in effective scopes for principal dpo`.
     - `reports/attack-before.log` lưu vết PII của `KH-000999` bị lộ trước khi contain.
     - `reports/attack-after.log` rỗng hoàn toàn (0 bytes), chứng minh không còn PII nào rò rỉ ra sink.
   - **Giới hạn của mock:**
     - Môi trường lab sử dụng dữ liệu giả lập (synthetic data) và mock LLM kích hoạt theo bộ marker cụ thể.
     - Trong thực tế, các cuộc tấn công prompt injection có tính đa dạng ngôn ngữ và tiềm ẩn cao hơn, cần kết hợp giải pháp phòng thủ chuyên sâu (lớp phòng vệ ngữ nghĩa LLM Guard, phân tầng mạng cách ly VPC/Egress Proxy, xác thực OAuth2/mTLS có token ký số).
