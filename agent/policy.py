"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b, §3c).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật cho tool call.
    Trả về (allow, reason) với reason luôn không rỗng.
    """
    # 1. Rule tối thiểu bắt buộc: dữ liệu restricted đi kèm egress network PHẢI bị deny
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: restricted data cannot be combined with network egress"

    # 2. Kiểm tra principal_id
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return False, f"DENY: unknown or unauthenticated principal {context.principal_id!r}"

    principal = principals[context.principal_id]

    # 3. Kiểm tra TTL / hạn dùng token
    if context.expires_at:
        try:
            exp_time = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if exp_time <= now:
                return False, f"DENY: delegation credential expired at {context.expires_at}"
        except Exception as e:
            return False, f"DENY: invalid expires_at format: {e}"

    # 4. Kiểm tra mục đích sử dụng (purpose)
    allowed_purposes = set(principal.get("purposes", []))
    if context.request_purpose and context.request_purpose not in allowed_purposes:
        return False, f"DENY: purpose {context.request_purpose!r} not permitted for principal {context.principal_id}"

    # 5. Tính quyền hiệu lực (effective scopes)
    effective_scopes = set(principal.get("allowed_tools", []))
    if context.agent_scopes:
        effective_scopes = effective_scopes & set(context.agent_scopes)

    # Nếu là sub-agent (delegation_depth > 0), không được vượt quyền cha (parent_scopes)
    if context.delegation_depth > 0:
        effective_scopes = effective_scopes & set(context.parent_scopes)

    # 6. Kiểm tra tool được yêu cầu
    if context.requested_tool:
        if context.requested_tool not in effective_scopes:
            return False, (
                f"DENY: tool {context.requested_tool!r} not in effective scopes for principal "
                f"{context.principal_id} (allowed: {sorted(effective_scopes)})"
            )

    return True, f"ALLOW: tool {context.requested_tool or 'operation'} authorized for principal {context.principal_id}"
