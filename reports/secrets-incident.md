# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (Line 1)
  - Rule ID: `lab24-synthetic-token`
  - Kết quả quét lịch sử git (`gitleaks git --config .gitleaks.toml --redact --verbose .`): Phát hiện 1 leak finding khớp rule `lab24-synthetic-token` tại commit `1bdd849`.
- Kết quả quét file hiện tại:
  - Quét thư mục làm việc (`gitleaks dir --config .gitleaks.toml .`) và hook pre-commit: Sạch hoàn toàn (`no leaks found`, exit code 0).
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức thu hồi (revoke) và rotate credential/secret tại hệ thống xác thực (Identity Provider / API Provider).
  - Kiểm tra audit access log của token bị lộ để đánh giá phạm vi ảnh hưởng và xác định xem có hành vi truy cập trái phép nào xảy ra không.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi commit hiện tại (HEAD) không xoá dữ liệu khỏi lịch sử Git; commit `1bdd849` vẫn nằm trong git history và bất kỳ ai có quyền truy cập repo đều có thể checkout hoặc đọc nội dung commit cũ.
  - Pin dependency (hash lock) và pre-commit hook chỉ bảo vệ chuỗi cung ứng gói cài đặt và ngăn chặn các secret mới bị commit vào repo, chứ không có quyền hạn vô hiệu hoá credential đã bị lộ ở bên ngoài; chỉ có hành động rotate / thu hồi token mới làm secret trở nên vô hiệu.
