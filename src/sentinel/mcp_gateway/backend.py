from __future__ import annotations

from typing import Any

from sentinel.models.tools import ToolResult, ToolSpec

_FIXTURES: dict[str, dict[str, Any]] = {
    "fixture_asset_inventory": {
        "assets": [{"id": "demo-node-01", "kind": "synthetic-example"}],
        "source": "built-in fixture",
    },
    "fixture_service_inventory": {
        "services": [{"id": "demo-service-443", "port": 443, "protocol": "tcp", "synthetic": True}],
        "source": "built-in fixture",
    },
    "fixture_http_headers": {
        "headers": {"content-type": "text/html", "x-content-type-options": "nosniff"},
        "source": "built-in fixture",
    },
    "fixture_tls_posture": {"protocol": "TLSv1.3", "certificate_status": "sample-only", "source": "built-in fixture"},
    "fixture_dependency_advisories": {
        "advisories": [],
        "notice": "No package manifest was inspected.",
        "source": "built-in fixture",
    },
    "fixture_cwe_context": {"reference": "CWE sample context only", "source": "built-in fixture"},
    "fixture_cve_context": {"reference": "CVE sample context only", "source": "built-in fixture"},
    "fixture_misconfiguration": {"observations": [], "notice": "No checks were run.", "source": "built-in fixture"},
    "fixture_attack_path": {"paths": [], "notice": "No attack paths were analyzed.", "source": "built-in fixture"},
    "fixture_verification": {
        "status": "not_performed",
        "notice": "This fixture does not verify any real condition.",
        "source": "built-in fixture",
    },
}


class MockSandboxProvider:
    def execute(self, tool: ToolSpec, target: str) -> ToolResult:
        fixture = _FIXTURES.get(tool.fixture_id)
        if fixture is None:
            raise RuntimeError("fixture is not built into the mock-only provider")
        return ToolResult(tool_name=tool.name, target=target, fixture={"fixture_id": tool.fixture_id, **fixture})
