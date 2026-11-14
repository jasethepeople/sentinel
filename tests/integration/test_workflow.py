from __future__ import annotations

from pathlib import Path

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from sentinel.orchestration.graph import build_graph, initial_state
from sentinel.scope.enforcer import ScopeEnforcer
from sentinel.security.approval_store import ApprovalStore


def test_langgraph_workflow_pauses_then_completes_with_one_use_approval(
    signed_scope: object, gateway_bundle: tuple[object, object], tmp_path: Path
) -> None:
    gateway, audit = gateway_bundle
    approvals = ApprovalStore(audit)
    reports = tmp_path / "reports"
    with SqliteSaver.from_conn_string(":memory:") as saver:
        saver.setup()
        graph = build_graph(gateway, audit, approvals, saver, reports)
        config = {"configurable": {"thread_id": signed_scope.manifest.engagement_id}}
        paused = graph.invoke(initial_state(signed_scope.manifest), config=config)
        assert paused["__interrupt__"]
        assert len(paused["fixtures"]) == 4
        token, _ = approvals.issue(signed_scope.manifest.engagement_id, "reviewer-1")
        result = graph.invoke(
            Command(resume={"approved": True, "approval_token": token, "reviewer_id": "reviewer-1"}),
            config=config,
        )
    assert result["phase"] == "completed"
    assert len(result["fixtures"]) == 5
    assert result["report"]["mode"] == "mock_only"
    assert all(Path(path).is_file() for path in result["report_paths"].values())
    assert audit.verify()[0]


def test_workflow_denies_unapproved_simulation_and_writes_report(
    signed_scope: object, gateway_bundle: tuple[object, object], tmp_path: Path
) -> None:
    gateway, audit = gateway_bundle
    approvals = ApprovalStore(audit)
    with SqliteSaver.from_conn_string(":memory:") as saver:
        saver.setup()
        graph = build_graph(gateway, audit, approvals, saver, tmp_path / "reports")
        config = {"configurable": {"thread_id": "denied-thread"}}
        graph.invoke(initial_state(signed_scope.manifest), config=config)
        result = graph.invoke(Command(resume={"approved": False, "reviewer_id": "reviewer-1"}), config=config)
    assert result["phase"] == "completed"
    assert len(result["fixtures"]) == 4
    event_types = [event["event_type"] for event in audit.list_events()]
    assert "simulation_approval_denied" in event_types


def test_workflow_rejects_unverified_or_mismatched_scope(
    signed_scope: object, gateway_bundle: tuple[object, object], tmp_path: Path
) -> None:
    gateway, audit = gateway_bundle
    approvals = ApprovalStore(audit)
    with SqliteSaver.from_conn_string(":memory:") as saver:
        saver.setup()
        graph = build_graph(gateway, audit, approvals, saver, tmp_path / "reports")
        state = initial_state(signed_scope.manifest)
        state["scope"] = signed_scope.manifest.model_copy(update={"engagement_id": "forged-id"}).model_dump(mode="json")
        with pytest.raises(Exception, match="does not match"):
            graph.invoke(state, config={"configurable": {"thread_id": "bad-thread"}})
    assert ScopeEnforcer(signed_scope.manifest).authorize("example.org", "recon") == "example.org"
