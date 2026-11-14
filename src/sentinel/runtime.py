from pathlib import Path

from sentinel.mcp_gateway.gateway import MCPGateway
from sentinel.registry.loader import ToolRegistry
from sentinel.scope.enforcer import ScopeEnforcer
from sentinel.scope.signing import load_verified_manifest
from sentinel.security.audit import AuditLog


def create_gateway(
    scope_file: Path, public_key_file: Path, audit_db: Path, *, principal_id: str, role: str
) -> tuple[MCPGateway, AuditLog]:
    manifest = load_verified_manifest(scope_file, public_key_file)
    audit = AuditLog(audit_db)
    registry = ToolRegistry.load()
    gateway = MCPGateway(registry, ScopeEnforcer(manifest), audit, principal_id=principal_id, role=role)
    return gateway, audit
