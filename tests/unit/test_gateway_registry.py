from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.mcp_gateway.backend import MockSandboxProvider
from sentinel.models.tools import ToolRequest, ToolSpec
from sentinel.registry.loader import RegistryError, ToolRegistry
from sentinel.security.authorization import AuthorizationDenied, AuthorizationService


def test_registry_exposes_only_fixed_fixture_tools() -> None:
    registry = ToolRegistry.load()
    assert len(registry.list()) == 10
    assert registry.get("simulate_http_headers").backend == "fixture"
    with pytest.raises(KeyError, match="unknown tool"):
        registry.get("run_command")


def test_registry_rejects_custom_backends_and_unsafe_metadata() -> None:
    with pytest.raises(ValidationError):
        ToolSpec.model_validate(
            {
                "name": "run_command",
                "category": "recon",
                "backend": "shell",
                "fixture_id": "fixture_asset_inventory",
                "description": "no",
            }
        )
    base = ToolRegistry.load().list()[0].model_dump()
    base["parameters"] = {"command": {"type": "string"}}
    with pytest.raises(RegistryError):
        ToolRegistry([ToolSpec.model_validate(base)])


def test_registry_rejects_invalid_yaml(tmp_path: Path) -> None:
    (tmp_path / "simulate_bad.yaml").write_text("name: [", encoding="utf-8")
    with pytest.raises(RegistryError, match="invalid tool definition"):
        ToolRegistry.load(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RegistryError, match="empty"):
        ToolRegistry.load(empty)


def test_role_policy_is_default_deny() -> None:
    policy = AuthorizationService()
    policy.authorize("operator", "recon")
    with pytest.raises(AuthorizationDenied):
        policy.authorize("unknown", "recon")
    with pytest.raises(AuthorizationDenied):
        policy.authorize("operator", "exploitation")


def test_backend_returns_static_fixture_and_refuses_unknown_fixture() -> None:
    backend = MockSandboxProvider()
    result = backend.execute(ToolRegistry.load().get("simulate_asset_inventory"), "example.org")
    assert result.mode == "mock_only"
    assert result.fixture["fixture_id"] == "fixture_asset_inventory"
    bad_spec = ToolSpec.model_validate(
        {
            "name": "simulate_unknown",
            "category": "recon",
            "backend": "fixture",
            "fixture_id": "fixture_unknown",
            "description": "not registered",
            "parameters": {},
            "safety": {"destructive": False, "requires_approval": False, "max_runtime_seconds": 1},
        }
    )
    with pytest.raises(RuntimeError, match="not built into"):
        backend.execute(bad_spec, "example.org")


def test_gateway_audits_allowed_and_denied_calls(gateway_bundle: tuple[object, object]) -> None:
    gateway, audit = gateway_bundle
    result = gateway.call(
        ToolRequest(tool_name="simulate_asset_inventory", target="example.org", principal_id="test-operator")
    )
    assert result.mode == "mock_only"
    assert [event["event_type"] for event in audit.list_events()] == ["tool_allowed", "tool_completed"]
    with pytest.raises(PermissionError):
        gateway.call(
            ToolRequest(tool_name="simulate_asset_inventory", target="outside.invalid", principal_id="test-operator")
        )
    assert audit.list_events()[-1]["event_type"] == "tool_denied"
    with pytest.raises(PermissionError):
        gateway.call(ToolRequest(tool_name="simulate_asset_inventory", target="example.org", principal_id="forged"))
    assert audit.verify()[0]
