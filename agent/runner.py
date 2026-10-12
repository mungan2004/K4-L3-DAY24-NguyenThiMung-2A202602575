"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt:
- Run A: gọi search_docs (untrusted content). Không gọi read_customer, không http_post.
- Run B: gọi read_customer (private data) chỉ với ticket_id kiểu int trích từ tên file.
  Không nhận free text của attacker.
- Mọi tool call (allow hay deny) đều qua policy.check() và ghi ledger.append().
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Giữ nguyên class này cho test scaffold dispatch."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu an toàn theo kiến trúc Trifecta Split và OBO."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"
    run_id_a = f"run-a-{uuid.uuid4().hex[:8]}"
    run_id_b = f"run-b-{uuid.uuid4().hex[:8]}"
    expires_at = "2099-01-01T00:00:00+00:00"

    # ==========================================
    # RUN A: Tìm kiếm tài liệu (Untrusted Content)
    # ==========================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed_search, reason_search = policy.check(ctx_search)
    args_hash_search = hashlib.sha256(
        json.dumps({"query": message}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id_a,
        "tool": "search_docs",
        "args_hash": args_hash_search,
        "classification": "internal",
        "decision": "allow" if allowed_search else "deny",
        "reason": reason_search,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, ledger_path)

    if not allowed_search:
        return f"Truy cập search_docs bị từ chối: {reason_search}"

    docs = tools.search_docs(message)

    # Trích xuất ticket_id (kiểu int) strictly từ TÊN FILE (.id)
    # Tuyệt đối không lấy ID từ free text
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # ==========================================
    # RUN B: Truy xuất Private Data (Customer Store)
    # ==========================================
    # Map ticket_id sang customer_id thông qua field related_tickets trong customers.json
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    matched_customer_ids: list[str] = []
    for c in customers_data:
        cid = c.get("customer_id")
        rel = c.get("related_tickets", [])
        if any(tid in rel for tid in ticket_ids):
            if cid not in matched_customer_ids:
                matched_customer_ids.append(cid)

    collected_records: list[dict] = []
    for cid in matched_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed_read, reason_read = policy.check(ctx_read)
        args_hash_read = hashlib.sha256(
            json.dumps({"customer_id": cid}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id_b,
            "tool": "read_customer",
            "args_hash": args_hash_read,
            "classification": "restricted",
            "decision": "allow" if allowed_read else "deny",
            "reason": reason_read,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)

        if allowed_read:
            try:
                record = tools.read_customer(cid)
                collected_records.append(record)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection yêu cầu exfiltration:
    # Phải kiểm tra PEP policy cho http_post và ghi nhận vào ledger
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed_post, reason_post = policy.check(ctx_post)
        args_hash_post = hashlib.sha256(
            json.dumps({
                "target_url": injected.target_url,
                "customer_ids": injected.customer_ids,
            }, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id_b,
            "tool": "http_post",
            "args_hash": args_hash_post,
            "classification": "restricted",
            "decision": "allow" if allowed_post else "deny",
            "reason": reason_post,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)

        if allowed_post:
            tools.http_post(injected.target_url, {"records": collected_records})

    # Redact PII trước khi trả kết quả tổng hợp cho người dùng
    sanitized_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(sanitized_docs)
