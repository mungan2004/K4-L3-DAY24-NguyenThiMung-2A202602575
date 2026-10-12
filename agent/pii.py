"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex recognizers cho tiếng Việt: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.
Đạt precision/recall cao trên tests/vn_pii_testset.jsonl.
"""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện các entity PII trong text:
    - EMAIL: địa chỉ email chuẩn
    - VN_BANK_ACCOUNT: STK 8-16 chữ số theo sau tiền tố STK/tài khoản
    - VN_CCCD: số căn cước 12 chữ số
    - VN_PHONE: số điện thoại 10 chữ số bắt đầu bằng 0
    """
    entities: list[dict] = []

    # 1. EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT: tiền tố STK / số tài khoản / tài khoản
    for m in re.finditer(r"(?i)(?<=\bSTK\s)(\d{8,16})\b|(?<=\btài khoản\s)(\d{8,16})\b|(?<=\bsố tài khoản\s)(\d{8,16})\b", text):
        match_group = next(i for i in range(1, 4) if m.group(i) is not None)
        start, end = m.start(match_group), m.end(match_group)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # 3. VN_CCCD: 12 chữ số liên tiếp
    for m in re.finditer(r"\b\d{12}\b", text):
        if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0
    for m in re.finditer(r"\b0\d{9}\b", text):
        if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    entities.sort(key=lambda e: (e["start"], e["end"]))
    return entities


def redact(text: str) -> str:
    """Thay thế mọi entity phát hiện được bằng [REDACTED_<TYPE>].
    Thay từ cuối văn bản về đầu để không làm lệch offset các entity phía trước.
    """
    entities = detect(text)
    # Sắp xếp giảm dần theo start để thay thế từ sau ra trước
    sorted_entities = sorted(entities, key=lambda e: e["start"], reverse=True)
    result = text
    for entity in sorted_entities:
        replacement = f"[REDACTED_{entity['type']}]"
        result = result[:entity["start"]] + replacement + result[entity["end"]:]
    return result
