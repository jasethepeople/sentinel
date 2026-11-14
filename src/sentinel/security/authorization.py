from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


class AuthorizationDenied(PermissionError):
    pass


class AuthorizationService:
    def __init__(self) -> None:
        policy_path = files("sentinel.security").joinpath("policies/default.json")
        self.policy: dict[str, Any] = json.loads(policy_path.read_text(encoding="utf-8"))

    def authorize(self, role: str, category: str) -> None:
        if self.policy.get("default") != "deny":
            raise AuthorizationDenied("authorization policy must be default-deny")
        role_policy = self.policy.get("roles", {}).get(role)
        if role_policy is None or category not in role_policy.get("allow_categories", []):
            raise AuthorizationDenied("role is not authorized for this tool category")
