from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class StreamEvent:
    engagement_id: str
    phase: str
    message: str
    timestamp: str
    data: dict[str, Any]

    @classmethod
    def create(cls, engagement_id: str, phase: str, message: str, **data: Any) -> StreamEvent:
        return cls(engagement_id, phase, message, datetime.now(UTC).isoformat(), data)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
