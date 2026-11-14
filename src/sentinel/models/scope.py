from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    type: Literal["ip", "cidr", "domain", "url"]
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def validate_target_value(cls, value: str, info: ValidationInfo) -> str:
        target_type = info.data.get("type")
        if value != value.strip() or any(char.isspace() for char in value):
            raise ValueError("scope target must not contain whitespace")
        try:
            if target_type == "ip":
                ipaddress.ip_address(value)
            elif target_type == "cidr":
                ipaddress.ip_network(value, strict=False)
            elif target_type == "domain":
                domain = value.rstrip(".").encode("idna").decode("ascii").lower()
                labels = domain.split(".")
                if len(labels) < 2 or any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels):
                    raise ValueError("invalid domain")
            elif target_type == "url":
                parsed = urlsplit(value)
                if (
                    parsed.scheme.lower() not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError("URL scope must be a clean http(s) URL")
                port = parsed.port
                if port is not None and not 1 <= port <= 65535:
                    raise ValueError("invalid URL port")
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid {target_type or 'target'} scope value") from exc
        return value


class ScopeManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engagement_id: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,126}[A-Za-z0-9]$")
    authorized_targets: list[TargetSpec] = Field(min_length=1)
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_tool_categories: list[Literal["recon", "scanning", "reporting"]] = Field(min_length=1)
    prohibited_actions: list[str] = Field(
        default_factory=lambda: [
            "dos",
            "credential_attack",
            "destructive_exploit",
            "exploitation",
            "shell_execution",
            "live_scanning",
        ]
    )
    valid_from: datetime
    valid_until: datetime
    signing_key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    mode: Literal["mock_only"] = "mock_only"

    @field_validator("valid_from", "valid_until")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scope timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> ScopeManifest:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        return self

    @field_validator("allowed_tool_categories")
    @classmethod
    def require_unique_categories(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed tool categories must be unique")
        return value

    @field_validator("prohibited_actions")
    @classmethod
    def require_prohibited_actions(cls, value: list[str]) -> list[str]:
        required = {
            "dos",
            "credential_attack",
            "destructive_exploit",
            "exploitation",
            "shell_execution",
            "live_scanning",
        }
        if not required.issubset(value):
            raise ValueError(
                "mock-only scope must explicitly prohibit live scanning, exploitation, shell execution, "
                "credential attacks, and DoS"
            )
        return value
