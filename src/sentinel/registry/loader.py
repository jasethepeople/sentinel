from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from sentinel.models.tools import ToolSpec

_ALLOWED_FIXTURES = {
    "fixture_asset_inventory",
    "fixture_service_inventory",
    "fixture_http_headers",
    "fixture_tls_posture",
    "fixture_dependency_advisories",
    "fixture_cwe_context",
    "fixture_cve_context",
    "fixture_misconfiguration",
    "fixture_attack_path",
    "fixture_verification",
}


class RegistryError(ValueError):
    pass


class ToolRegistry:
    def __init__(self, specs: Iterable[ToolSpec]) -> None:
        entries = list(specs)
        names = [spec.name for spec in entries]
        if len(names) != len(set(names)):
            raise RegistryError("duplicate tool names")
        if any(spec.backend != "fixture" or spec.fixture_id not in _ALLOWED_FIXTURES for spec in entries):
            raise RegistryError("only the built-in offline fixture backend is permitted")
        if any(
            spec.parameters
            or spec.safety != {"destructive": False, "requires_approval": False, "max_runtime_seconds": 1}
            for spec in entries
        ):
            raise RegistryError("tool safety metadata does not meet mock-only policy")
        self._specs = {spec.name: spec for spec in entries}

    @classmethod
    def load(cls, directory: Path | None = None) -> ToolRegistry:
        tools_dir = directory or Path(__file__).parent / "tools"
        specs = []
        for path in sorted(tools_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                spec = ToolSpec.model_validate(data)
            except Exception as exc:
                raise RegistryError(f"invalid tool definition: {path.name}") from exc
            if path.stem != spec.name:
                raise RegistryError(f"tool name does not match filename: {path.name}")
            specs.append(spec)
        if not specs:
            raise RegistryError("tool registry is empty")
        return cls(specs)

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def list(self) -> list[ToolSpec]:
        return [self._specs[name] for name in sorted(self._specs)]
