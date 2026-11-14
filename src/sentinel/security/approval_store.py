from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sentinel.security.audit import AuditLog


class ApprovalStore:
    def __init__(self, audit: AuditLog, *, max_lifetime: timedelta = timedelta(minutes=15)) -> None:
        if max_lifetime <= timedelta(0) or max_lifetime > timedelta(minutes=15):
            raise ValueError("approval lifetime must be between 1 second and 15 minutes")
        self.audit = audit
        self.max_lifetime = max_lifetime

    def issue(self, engagement_id: str, reviewer_id: str, *, now: datetime | None = None) -> tuple[str, datetime]:
        reviewer = reviewer_id.strip()
        if not engagement_id or not reviewer or len(reviewer) > 128:
            raise ValueError("engagement and reviewer identifiers are required")
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("approval time must be timezone-aware")
        token = secrets.token_urlsafe(32)
        expires_at = current + self.max_lifetime
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.audit._connect() as db:
            db.execute(
                "INSERT INTO approval_tokens("
                "token_hash,engagement_id,reviewer_id,expires_at,consumed) VALUES(?,?,?,?,0)",
                (token_hash, engagement_id, reviewer, expires_at.isoformat()),
            )
        self.audit.append(
            "approval_token_issued",
            {
                "engagement_id": engagement_id,
                "reviewer_id": reviewer,
                "token_fingerprint": token_hash[:16],
                "expires_at": expires_at.isoformat(),
            },
        )
        return token, expires_at

    def consume(self, token: str, engagement_id: str, reviewer_id: str, *, now: datetime | None = None) -> bool:
        if not token or not engagement_id or not reviewer_id:
            return False
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            return False
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.audit._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT engagement_id,reviewer_id,expires_at,consumed FROM approval_tokens WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            if (
                row is None
                or row["consumed"]
                or row["engagement_id"] != engagement_id
                or row["reviewer_id"] != reviewer_id
            ):
                return False
            if current >= datetime.fromisoformat(row["expires_at"]):
                return False
            changed = db.execute(
                "UPDATE approval_tokens SET consumed=1 WHERE token_hash=? AND consumed=0", (token_hash,)
            ).rowcount
            if changed != 1:
                return False
        self.audit.append(
            "approval_token_consumed",
            {"engagement_id": engagement_id, "reviewer_id": reviewer_id, "token_fingerprint": token_hash[:16]},
        )
        return True
