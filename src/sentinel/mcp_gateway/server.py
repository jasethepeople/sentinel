from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from sentinel.models.tools import ToolRequest
from sentinel.runtime import create_gateway


def create_server(scope_file: Path, public_key_file: Path, audit_db: Path) -> FastMCP:
    gateway, _ = create_gateway(
        scope_file, public_key_file, audit_db, principal_id="mcp-stdio-operator", role="operator"
    )
    server = FastMCP("SENTINEL offline fixture gateway")

    @server.tool()
    def list_mock_tools() -> list[dict[str, str]]:
        """List only fixed, offline SENTINEL simulation tools."""
        return [
            {"name": item.name, "category": item.category, "description": item.description}
            for item in gateway.registry.list()
        ]

    @server.tool()
    def simulate(tool_name: str, target: str) -> dict[str, Any]:
        """Return one built-in synthetic fixture after signed-scope and role checks; never contacts the target."""
        request = ToolRequest(tool_name=tool_name, target=target, principal_id="mcp-stdio-operator")
        return gateway.call(request).model_dump(mode="json")

    return server


def main() -> None:
    scope_file = Path(os.environ.get("SENTINEL_SCOPE_FILE", "scope.yaml"))
    public_key_file = Path(os.environ.get("SENTINEL_PUBLIC_KEY", "scope-signing-key.pub"))
    audit_db = Path(os.environ.get("SENTINEL_AUDIT_DB", "sentinel-audit.sqlite3"))
    create_server(scope_file, public_key_file, audit_db).run(transport="stdio")
