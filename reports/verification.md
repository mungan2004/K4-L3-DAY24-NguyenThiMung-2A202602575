# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Linux x86_64 (Ubuntu 22.04 LTS / WSL2)
  - Python: 3.10.12 (venv tại `/home/mung/AI_in_action_phase2/.venv`)
  - Gitleaks: v8.30.1 (`8.30.1` trong PATH)
- `python -m pytest tests/ -q`:
  - Kết quả: `33 passed in 0.57s` (100% test suites passed)
- `pre-commit run --all-files`:
  - Kết quả: `Detect hardcoded secrets.....Passed`
- Ledger verify:
  - Lệnh: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi hash chain sha256 tamper-evident hợp lệ, mọi entry đều có reason)
- Các lỗi còn lại:
  - Không có lỗi nào còn tồn đọng.
  - Cả 4 biến thể lure đều sẵn sàng (`4/4 lure sẵn sàng.`).
  - Hash lock `requirements.lock` đầy đủ hash sha256 cho toàn bộ packages (`pip install --require-hashes` hoạt động).
  - Kết quả sau containment: `reports/attack-after.log` rỗng (0 bytes).
- Commit SHA cuối cùng: xem commit mới nhất trên nhánh `main` khi nộp bài

