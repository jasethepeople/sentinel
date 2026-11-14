from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.agents.base import TaskSpec
from sentinel.agents.exploit import ExploitAgent
from sentinel.agents.recon import ReconAgent
from sentinel.agents.scan import ScanAgent
from sentinel.agents.verify import VerifyAgent
from sentinel.models.tools import ToolRequest, ToolSpec


def test_worker_agents_only_create_gateway_requests() -> None:
    task = TaskSpec(target="example.org", principal_id="operator")
    plans = ReconAgent().plan(task) + ScanAgent().plan(task) + VerifyAgent().plan(task)
    assert {request.tool_name for request in plans} == {
        "simulate_asset_inventory",
        "simulate_service_inventory",
        "simulate_http_headers",
        "simulate_tls_posture",
        "simulate_verification",
    }
    assert all(request.target == task.target for request in plans)
    with pytest.raises(PermissionError, match="not implemented"):
        ExploitAgent().plan(task)


def test_request_and_tool_models_reject_unrecognized_fields() -> None:
    with pytest.raises(ValidationError):
        ToolRequest.model_validate(
            {"tool_name": "simulate_http_headers", "target": "example.org", "principal_id": "operator", "shell": "id"}
        )
    with pytest.raises(ValidationError):
        ToolSpec.model_validate(
            {
                "name": "run_shell",
                "category": "recon",
                "backend": "fixture",
                "fixture_id": "fixture_asset_inventory",
                "description": "bad",
            }
        )
