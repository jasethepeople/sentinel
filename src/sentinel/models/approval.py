from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    engagement_id: str
    tool_name: str
    target: str
    reason: str
    expires_at: datetime


class ApprovalToken(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    token: str = Field(min_length=32)
    engagement_id: str
    reviewer_id: str
    expires_at: datetime
