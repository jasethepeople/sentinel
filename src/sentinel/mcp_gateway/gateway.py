from __future__ import annotations

from sentinel.mcp_gateway.backends import MockSandboxProvider
from sentinel.models.tools import ToolRequest, ToolResult
from sentinel.registry.loader import ToolRegistry
from sentinel.scope.enforcer import ScopeDenied, ScopeEnforcer
from sentinel.security.audit import AuditLog
from sentinel.security.authorization import AuthorizationDenied, AuthorizationService


class MCPGateway:
    def __init__(
        self, registry: ToolRegistry, scope: ScopeEnforcer, audit: AuditLog, *, principal_id: str, role: str
    ) -> None:
        self.registry = registry
        self.scope = scope
        self.audit = audit
        self.principal_id = principal_id
        self.role = role
        self.authorization = AuthorizationService()
        self.backend = MockSandboxProvider()

    def call(self, request: ToolRequest) -> ToolResult:
        audit_context = {
            "engagement_id": self.scope.manifest.engagement_id,
            "tool_name": request.tool_name,
            "principal_id": request.principal_id,
        }
        try:
            if request.principal_id != self.principal_id:
                raise AuthorizationDenied("principal identity does not match this gateway session")
            spec = self.registry.get(request.tool_name)
            if request.arguments:
                raise ScopeDenied("mock fixture tools do not accept additional arguments")
            self.authorization.authorize(self.role, spec.category)
            normalized_target = self.scope.authorize(request.target, spec.category)
        except (KeyError, ScopeDenied, AuthorizationDenied) as exc:
            self.audit.append("tool_denied", {**audit_context, "reason": str(exc)[:200]})
            raise PermissionError(str(exc)) from exc
        self.audit.append(
            "tool_allowed",
            {**audit_context, "category": spec.category, "target": normalized_target, "mode": "mock_only"},
        )
        try:
            result = self.backend.execute(spec, normalized_target)
        except Exception as exc:
            self.audit.append("tool_failed", {**audit_context, "reason": str(exc)[:200], "mode": "mock_only"})
            raise
        self.audit.append("tool_completed", {**audit_context, "fixture_id": spec.fixture_id, "mode": "mock_only"})
        return result
