from __future__ import annotations

from typing import Any, TypedDict


class SentinelState(TypedDict, total=False):
    engagement_id: str
    scope: dict[str, Any]
    target: str
    phase: str
    fixtures: list[dict[str, Any]]
    analysis: dict[str, Any]
    approved: bool
    approval: dict[str, Any]
    report: dict[str, Any]
    report_paths: dict[str, str]
