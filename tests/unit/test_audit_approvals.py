from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel.security.approval_store import ApprovalStore
from sentinel.security.audit import AuditLog


def test_audit_chain_lists_filters_and_verifies(audit_log: AuditLog) -> None:
    audit_log.append("started", {"engagement_id": "one", "mode": "mock_only"})
    audit_log.append("completed", {"engagement_id": "one", "count": 1})
    audit_log.append("started", {"engagement_id": "two"})
    assert audit_log.verify()[0]
    assert len(audit_log.list_events()) == 3
    assert len(audit_log.list_events("one")) == 2


def test_audit_detects_row_tampering(tmp_path: Path) -> None:
    database = tmp_path / "audit.sqlite3"
    audit = AuditLog(database)
    audit.append("started", {"engagement_id": "tamper-me"})
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE audit_events SET event_type='changed' WHERE event_id=1")
    ok, message = audit.verify()
    assert not ok
    assert "record hash failed" in message


def test_approval_is_bound_to_engagement_reviewer_and_single_use(audit_log: AuditLog) -> None:
    approvals = ApprovalStore(audit_log)
    token, _ = approvals.issue("engagement-1", "reviewer-1")
    assert not approvals.consume(token, "engagement-2", "reviewer-1")
    assert not approvals.consume(token, "engagement-1", "reviewer-2")
    assert approvals.consume(token, "engagement-1", "reviewer-1")
    assert not approvals.consume(token, "engagement-1", "reviewer-1")


def test_expired_or_invalid_approval_is_denied(audit_log: AuditLog) -> None:
    approvals = ApprovalStore(audit_log)
    now = datetime.now(UTC)
    token, _ = approvals.issue("engagement-1", "reviewer-1", now=now)
    assert not approvals.consume(token, "engagement-1", "reviewer-1", now=now + timedelta(minutes=16))
    assert not approvals.consume("not-a-token", "engagement-1", "reviewer-1")
    assert not approvals.consume(token, "engagement-1", "reviewer-1", now=datetime(2026, 1, 1))
