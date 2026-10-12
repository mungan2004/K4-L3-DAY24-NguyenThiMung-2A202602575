"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng với sha256 hash chain.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Ghi 1 dòng vào ledger có hash chain tamper-evident.
    Tự động thêm `prev_hash` và `hash`.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        content = path.read_text(encoding="utf-8").strip()
        if content:
            last_line = content.splitlines()[-1]
            last_entry = json.loads(last_line)
            prev_hash = last_entry["hash"]

    full_entry = dict(entry)
    full_entry["prev_hash"] = prev_hash

    # Hash tính từ nội dung entry bao gồm prev_hash, không bao gồm trường hash
    data_to_hash = json.dumps(full_entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    entry_hash = hashlib.sha256(data_to_hash).hexdigest()
    full_entry["hash"] = entry_hash

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(full_entry, ensure_ascii=False) + "\n")

    return full_entry


def verify(path: Path) -> bool:
    """Xác thực toàn bộ chuỗi ledger:
    - Mọi entry có reason không rỗng
    - prev_hash khớp với hash của dòng trước đó (dòng đầu là '0' * 64)
    - hash của mỗi dòng khớp khi tính lại
    """
    path = Path(path)
    if not path.exists():
        return False

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        if entry.get("prev_hash") != expected_prev:
            return False

        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
        data_to_hash = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False).encode("utf-8")
        calculated_hash = hashlib.sha256(data_to_hash).hexdigest()

        if calculated_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True
