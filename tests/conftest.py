from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from sentinel.mcp_gateway.gateway import MCPGateway
from sentinel.models.scope import ScopeManifest
from sentinel.registry.loader import ToolRegistry
from sentinel.scope.enforcer import ScopeEnforcer
from sentinel.scope.signing import generate_keypair, write_signed_manifest
from sentinel.security.audit import AuditLog


@dataclass(frozen=True)
class SignedScope:
    manifest: ScopeManifest
    scope_file: Path
    private_key_file: Path
    public_key_file: Path


def make_signed_scope(directory: Path, overrides: dict | None = None) -> SignedScope:
    fixture = Path(__file__).parent / "fixtures" / "scope_template.yaml"
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    now = datetime.now(UTC)
    data["valid_from"] = (now - timedelta(minutes=1)).isoformat()
    data["valid_until"] = (now + timedelta(days=1)).isoformat()
    data.update(overrides or {})
    private_key = directory / "scope-signing-key.pem"
    public_key = directory / "scope-signing-key.pub"
    scope_file = directory / "scope.yaml"
    generate_keypair(private_key, public_key)
    manifest = write_signed_manifest(data, scope_file, private_key)
    return SignedScope(manifest, scope_file, private_key, public_key)


@pytest.fixture
def signed_scope(tmp_path: Path) -> SignedScope:
    return make_signed_scope(tmp_path)


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.sqlite3")


@pytest.fixture
def gateway_bundle(signed_scope: SignedScope, audit_log: AuditLog) -> tuple[MCPGateway, AuditLog]:
    gateway = MCPGateway(
        ToolRegistry.load(),
        ScopeEnforcer(signed_scope.manifest),
        audit_log,
        principal_id="test-operator",
        role="operator",
    )
    return gateway, audit_log
