from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import networkx as nx
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from sentinel.agents.base import TaskSpec
from sentinel.agents.recon import ReconAgent
from sentinel.agents.report import build_report, write_bundle
from sentinel.agents.scan import ScanAgent
from sentinel.agents.verify import VerifyAgent
from sentinel.mcp_gateway.gateway import MCPGateway
from sentinel.models.scope import ScopeManifest
from sentinel.models.state import SentinelState
from sentinel.scope.enforcer import ScopeDenied
from sentinel.security.approval_store import ApprovalStore
from sentinel.security.audit import AuditLog


def _default_target(manifest: ScopeManifest) -> str:
    first = manifest.authorized_targets[0]
    if first.type == "cidr":
        return str(ipaddress.ip_network(first.value, strict=False).network_address)
    if first.type == "url":
        return first.value
    return first.value


def _target(state: SentinelState, manifest: ScopeManifest) -> str:
    return str(state.get("target") or _default_target(manifest))


def build_graph(
    gateway: MCPGateway,
    audit: AuditLog,
    approvals: ApprovalStore,
    checkpointer: BaseCheckpointSaver[Any],
    reports_dir: Path,
) -> Any:
    recon_agent = ReconAgent()
    scan_agent = ScanAgent()
    verify_agent = VerifyAgent()

    def validate_scope(state: SentinelState) -> dict[str, Any]:
        engagement_id = str(state.get("engagement_id", "unknown"))
        try:
            manifest = ScopeManifest.model_validate(state["scope"])
            if manifest.model_dump(mode="json") != gateway.scope.manifest.model_dump(mode="json"):
                raise ScopeDenied("workflow scope does not match the verified gateway scope")
            if state.get("engagement_id") != manifest.engagement_id:
                raise ScopeDenied("workflow engagement ID does not match the signed scope")
            target = _target(state, manifest)
            for category in ("recon", "scanning"):
                gateway.scope.authorize(target, category)
        except Exception as exc:
            audit.append(
                "scope_validation_denied",
                {"engagement_id": engagement_id, "reason": str(exc)[:200], "mode": "mock_only"},
            )
            raise
        audit.append(
            "engagement_started", {"engagement_id": manifest.engagement_id, "target": target, "mode": manifest.mode}
        )
        return {"target": target, "phase": "scope_validated"}

    def collect_fixtures(state: SentinelState) -> dict[str, Any]:
        task = TaskSpec(target=state["target"], principal_id=gateway.principal_id)
        requests = recon_agent.plan(task) + scan_agent.plan(task)
        results = [gateway.call(request).model_dump(mode="json") for request in requests]
        audit.append(
            "fixture_collection_completed",
            {"engagement_id": state["engagement_id"], "fixture_count": len(results), "mode": "mock_only"},
        )
        return {"fixtures": results, "phase": "fixtures_collected"}

    def analyze_fixtures(state: SentinelState) -> dict[str, Any]:
        graph: nx.Graph[str, dict[str, Any], dict[str, Any]] = nx.Graph()
        graph.add_node(state["target"], kind="authorized_target")
        for item in state.get("fixtures", []):
            fixture_id = item.get("fixture", {}).get("fixture_id", "unknown")
            graph.add_node(fixture_id, kind="synthetic_fixture")
            graph.add_edge(state["target"], fixture_id, relation="fixture_for_demo_only")
        analysis = {
            "mode": "mock_only",
            "fixture_graph_nodes": graph.number_of_nodes(),
            "fixture_graph_edges": graph.number_of_edges(),
            "notice": "No real assets, vulnerabilities, or attack paths were assessed.",
        }
        return {"analysis": analysis, "phase": "synthetic_analysis_completed"}

    def approval_gate(state: SentinelState) -> dict[str, Any]:
        decision = interrupt(
            {
                "kind": "mock_verification_approval",
                "engagement_id": state["engagement_id"],
                "target": state["target"],
                "message": (
                    "Approve the next offline fixture-only demonstration step? "
                    "No target interaction will occur."
                ),
            }
        )
        approved = False
        reviewer_id = ""
        if isinstance(decision, dict) and decision.get("approved") is True:
            reviewer_id = str(decision.get("reviewer_id", ""))
            approved = approvals.consume(
                str(decision.get("approval_token", "")),
                state["engagement_id"],
                reviewer_id,
            )
        event_type = "simulation_approval_granted" if approved else "simulation_approval_denied"
        audit.append(
            event_type, {"engagement_id": state["engagement_id"], "reviewer_id": reviewer_id, "mode": "mock_only"}
        )
        return {"approved": approved, "phase": "simulation_approval_recorded"}

    def run_verification_fixture(state: SentinelState) -> dict[str, Any]:
        task = TaskSpec(target=state["target"], principal_id=gateway.principal_id)
        result = gateway.call(verify_agent.plan(task)[0]).model_dump(mode="json")
        fixtures = [*state.get("fixtures", []), result]
        return {"fixtures": fixtures, "phase": "verification_fixture_returned"}

    def render_report(state: SentinelState) -> dict[str, Any]:
        manifest = ScopeManifest.model_validate(state["scope"])
        report = build_report(
            manifest.engagement_id, state["target"], state.get("fixtures", []), state.get("analysis", {})
        )
        paths = write_bundle(report, reports_dir)
        audit.append("report_written", {"engagement_id": manifest.engagement_id, "paths": paths, "mode": "mock_only"})
        return {"report": report, "report_paths": paths, "phase": "completed"}

    builder = StateGraph(SentinelState)
    builder.add_node("validate_scope", validate_scope)
    builder.add_node("collect_fixtures", collect_fixtures)
    builder.add_node("analyze_fixtures", analyze_fixtures)
    builder.add_node("approval_gate", approval_gate)
    builder.add_node("run_verification_fixture", run_verification_fixture)
    builder.add_node("render_report", render_report)
    builder.add_edge(START, "validate_scope")
    builder.add_edge("validate_scope", "collect_fixtures")
    builder.add_edge("collect_fixtures", "analyze_fixtures")
    builder.add_edge("analyze_fixtures", "approval_gate")
    builder.add_conditional_edges(
        "approval_gate", lambda state: "run_verification_fixture" if state.get("approved") else "render_report"
    )
    builder.add_edge("run_verification_fixture", "render_report")
    builder.add_edge("render_report", END)
    return builder.compile(checkpointer=checkpointer)


def initial_state(manifest: ScopeManifest, target: str | None = None) -> SentinelState:
    return {
        "engagement_id": manifest.engagement_id,
        "scope": manifest.model_dump(mode="json"),
        "target": target or _default_target(manifest),
        "phase": "started",
        "fixtures": [],
        "analysis": {},
        "approved": False,
    }
