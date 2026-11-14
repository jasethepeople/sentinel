from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ZERO_HASH = "0" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit_events ("
                "event_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
                "event_type TEXT NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, "
                "record_hash TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS approval_tokens ("
                "token_hash TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, reviewer_id TEXT NOT NULL, "
                "expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level="IMMEDIATE")
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT record_hash FROM audit_events ORDER BY event_id DESC LIMIT 1").fetchone()
            previous_hash = previous["record_hash"] if previous else _ZERO_HASH
            timestamp = datetime.now(UTC).isoformat()
            event_id = db.execute("SELECT COALESCE(MAX(event_id), 0) + 1 AS next_id FROM audit_events").fetchone()[
                "next_id"
            ]
            envelope = {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            digest = hashlib.sha256(_canonical(envelope)).hexdigest()
            db.execute(
                "INSERT INTO audit_events("
                "event_id,timestamp,event_type,payload,previous_hash,record_hash) VALUES(?,?,?,?,?,?)",
                (event_id, timestamp, event_type, json.dumps(payload, sort_keys=True), previous_hash, digest),
            )
        return {**envelope, "record_hash": digest}

    def list_events(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY event_id").fetchall()
        events = []
        for row in rows:
            payload = json.loads(row["payload"])
            if engagement_id is None or payload.get("engagement_id") == engagement_id:
                events.append(
                    {
                        "event_id": row["event_id"],
                        "timestamp": row["timestamp"],
                        "event_type": row["event_type"],
                        "payload": payload,
                        "previous_hash": row["previous_hash"],
                        "record_hash": row["record_hash"],
                    }
                )
        return events

    def verify(self) -> tuple[bool, str]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY event_id").fetchall()
        previous_hash = _ZERO_HASH
        for expected_id, row in enumerate(rows, start=1):
            if row["event_id"] != expected_id or row["previous_hash"] != previous_hash:
                return False, f"chain link failed at event {row['event_id']}"
            envelope = {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload"]),
                "previous_hash": row["previous_hash"],
            }
            actual_hash = hashlib.sha256(_canonical(envelope)).hexdigest()
            if actual_hash != row["record_hash"]:
                return False, f"record hash failed at event {row['event_id']}"
            previous_hash = actual_hash
        return True, f"verified {len(rows)} audit event(s)"
