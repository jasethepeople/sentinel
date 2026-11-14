from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(pattern=r"^simulate_[a-z0-9_]+$")
    category: Literal["recon", "scanning", "reporting"]
    backend: Literal["fixture"]
    fixture_id: str = Field(pattern=r"^fixture_[a-z0-9_]+$")
    description: str = Field(min_length=1)
    target_parameter: Literal["target"] = "target"
    parameters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    safety: dict[str, Any] = Field(default_factory=dict)


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tool_name: str = Field(pattern=r"^simulate_[a-z0-9_]+$")
    target: str = Field(min_length=1, max_length=2048)
    arguments: dict[str, Any] = Field(default_factory=dict)
    principal_id: str = Field(min_length=1)
    approval_token: str | None = None


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    target: str
    mode: Literal["mock_only"] = "mock_only"
    fixture: dict[str, Any]
