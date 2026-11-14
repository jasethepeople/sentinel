from __future__ import annotations

from pathlib import Path

from sentinel.mcp_gateway.server import create_server


def test_mcp_server_is_named_for_sentinel(signed_scope: object, tmp_path: Path) -> None:
    server = create_server(
        signed_scope.scope_file,
        signed_scope.public_key_file,
        tmp_path / "audit.sqlite3",
    )
    assert server.name == "SENTINEL offline fixture gateway"
