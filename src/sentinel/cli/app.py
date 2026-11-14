from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import typer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command
from rich.table import Table

from sentinel import __version__
from sentinel.cli.ui import console, show_banner
from sentinel.mcp_gateway.gateway import MCPGateway
from sentinel.models.scope import ScopeManifest
from sentinel.orchestration.graph import build_graph, initial_state
from sentinel.runtime import create_gateway
from sentinel.scope.signing import generate_keypair, load_verified_manifest, write_signed_manifest
from sentinel.security.approval_store import ApprovalStore
from sentinel.security.audit import AuditLog

app = typer.Typer(
    name="sentinel",
    help="Offline, signed-scope security simulation. No live scanners or exploit tools are included.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
tools_app = typer.Typer(no_args_is_help=True)
audit_app = typer.Typer(no_args_is_help=True)
mcp_app = typer.Typer(no_args_is_help=True)
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(mcp_app, name="mcp")


def _target_spec(target: str) -> dict[str, str]:
    value = target.strip()
    if not value:
        raise typer.BadParameter("target cannot be blank")
    try:
        ipaddress.ip_address(value)
        return {"type": "ip", "value": value}
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return {"type": "cidr", "value": value}
    except ValueError:
        pass
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.query
        ):
            raise typer.BadParameter(
                "URL scope must be http(s), have a hostname, and contain no credentials, query, or fragment"
            )
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise typer.BadParameter("invalid URL port") from exc
        if parsed_port is not None and not 1 <= parsed_port <= 65535:
            raise typer.BadParameter("invalid URL port")
        return {"type": "url", "value": value}
    domain = value.rstrip(".").lower()
    if len(domain) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain
    ):
        raise typer.BadParameter("target must be an IP, CIDR, domain name, or http(s) URL")
    return {"type": "domain", "value": domain}


def _make_gateway(
    scope_file: Path, public_key: Path, audit_db: Path, principal_id: str = "cli-operator"
) -> tuple[MCPGateway, AuditLog]:
    return create_gateway(scope_file, public_key, audit_db, principal_id=principal_id, role="operator")


def _invoke_engagement(
    manifest: ScopeManifest,
    gateway: MCPGateway,
    audit: AuditLog,
    *,
    reports_dir: Path,
    checkpoint_db: Path,
    target: str | None,
    reviewer_id: str,
    approve_simulation: bool,
) -> dict[str, Any]:
    approvals = ApprovalStore(audit)
    checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
    with SqliteSaver.from_conn_string(str(checkpoint_db)) as saver:
        saver.setup()
        graph = build_graph(gateway, audit, approvals, saver, reports_dir)
        config = {"configurable": {"thread_id": manifest.engagement_id}}
        result = graph.invoke(initial_state(manifest, target), config=config)
        if result.get("__interrupt__"):
            prompt = "Approve one additional offline fixture-only demonstration step?"
            approved = approve_simulation or typer.confirm(prompt, default=False)
            if approved:
                token, expires_at = approvals.issue(manifest.engagement_id, reviewer_id)
                console.print(f"Approval recorded for [bold]{reviewer_id}[/bold] (expires {expires_at.isoformat()}).")
                decision = {"approved": True, "approval_token": token, "reviewer_id": reviewer_id}
            else:
                decision = {"approved": False, "reviewer_id": reviewer_id}
            result = graph.invoke(Command(resume=decision), config=config)
        return cast(dict[str, Any], result)


@app.command()
def init(
    target: str = typer.Option(
        "192.0.2.0/24", "--target", help="Authorized example target. Default is an RFC 5737 documentation-only network."
    ),
    engagement_id: str | None = typer.Option(None, "--engagement-id", help="Stable ID; defaults to a random ID."),
    scope_file: Path = typer.Option(Path("scope.yaml"), "--scope", "--scope-file"),
    private_key: Path = typer.Option(Path("scope-signing-key.pem"), "--private-key"),
    public_key: Path = typer.Option(Path("scope-signing-key.pub"), "--public-key"),
) -> None:
    """Create an Ed25519 keypair and sign a short-lived mock-only scope."""
    show_banner()
    for path in (scope_file, private_key, public_key):
        if path.exists():
            raise typer.BadParameter(f"refusing to overwrite existing file: {path}")
    target_spec = _target_spec(target)
    generate_keypair(private_key, public_key)
    now = datetime.now(UTC)
    data = {
        "engagement_id": engagement_id or f"demo-{uuid.uuid4().hex[:12]}",
        "authorized_targets": [target_spec],
        "excluded_targets": [],
        "allowed_tool_categories": ["recon", "scanning", "reporting"],
        "prohibited_actions": [
            "dos",
            "credential_attack",
            "destructive_exploit",
            "exploitation",
            "shell_execution",
            "live_scanning",
        ],
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(days=7)).isoformat(),
        "mode": "mock_only",
    }
    manifest = write_signed_manifest(data, scope_file, private_key)
    console.print(f"Signed mock-only scope [bold]{manifest.engagement_id}[/bold] for [bold]{target}[/bold].")
    console.print(
        f"Scope: {scope_file.resolve()} | Public key: {public_key.resolve()} | Private key: {private_key.resolve()}"
    )
    console.print("Keep the private signing key private. This prototype will never contact the target.")


@tools_app.command("list")
def tools_list() -> None:
    """List built-in deterministic fixtures."""
    from sentinel.registry.loader import ToolRegistry

    table = Table(title="Built-in mock-only tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Category")
    table.add_column("Purpose")
    for tool in ToolRegistry.load().list():
        table.add_row(tool.name, tool.category, tool.description)
    console.print(table)


@tools_app.command("info")
def tools_info(tool_name: str = typer.Argument(...)) -> None:
    """Show the fixed safety metadata for one fixture tool."""
    from sentinel.registry.loader import ToolRegistry

    try:
        tool = ToolRegistry.load().get(tool_name)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print_json(tool.model_dump_json(indent=2))


@app.command()
def engage(
    scope_file: Path = typer.Option(Path("scope.yaml"), "--scope"),
    public_key: Path = typer.Option(Path("scope-signing-key.pub"), "--public-key"),
    audit_db: Path = typer.Option(Path("sentinel-audit.sqlite3"), "--audit-db"),
    checkpoint_db: Path = typer.Option(Path("sentinel-checkpoints.sqlite3"), "--checkpoint-db"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    target: str | None = typer.Option(None, "--target", help="Optional target inside the signed scope."),
    reviewer_id: str = typer.Option("local-operator", "--reviewer-id"),
    approve_simulation: bool = typer.Option(
        False, "--approve-simulation", help="Explicitly approve one additional fixture-only step."
    ),
) -> None:
    """Run a LangGraph workflow over static fixtures, guarded by signed scope."""
    show_banner()
    manifest = load_verified_manifest(scope_file, public_key)
    gateway, audit = _make_gateway(scope_file, public_key, audit_db)
    try:
        result = _invoke_engagement(
            manifest,
            gateway,
            audit,
            reports_dir=reports_dir,
            checkpoint_db=checkpoint_db,
            target=target,
            reviewer_id=reviewer_id,
            approve_simulation=approve_simulation,
        )
    except PermissionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Workflow phase: [bold]{result.get('phase', 'unknown')}[/bold]")
    if result.get("report_paths"):
        for kind, path in result["report_paths"].items():
            console.print(f"{kind}: {path}")
    else:
        console.print("The workflow did not produce a report.")


@app.command()
def resume(
    engagement_id: str = typer.Argument(..., help="Engagement ID used as the workflow thread ID."),
    scope_file: Path = typer.Option(Path("scope.yaml"), "--scope"),
    public_key: Path = typer.Option(Path("scope-signing-key.pub"), "--public-key"),
    audit_db: Path = typer.Option(Path("sentinel-audit.sqlite3"), "--audit-db"),
    checkpoint_db: Path = typer.Option(Path("sentinel-checkpoints.sqlite3"), "--checkpoint-db"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
    reviewer_id: str = typer.Option("local-operator", "--reviewer-id"),
    approve_simulation: bool = typer.Option(
        False, "--approve-simulation", help="Explicitly approve one additional fixture-only step."
    ),
) -> None:
    """Resume a paused fixture-only workflow after local operator approval."""
    show_banner()
    manifest = load_verified_manifest(scope_file, public_key)
    if manifest.engagement_id != engagement_id:
        raise typer.BadParameter("engagement ID does not match the signed scope")
    gateway, audit = _make_gateway(scope_file, public_key, audit_db)
    approvals = ApprovalStore(audit)
    with SqliteSaver.from_conn_string(str(checkpoint_db)) as saver:
        saver.setup()
        graph = build_graph(gateway, audit, approvals, saver, reports_dir)
        config = {"configurable": {"thread_id": engagement_id}}
        state = graph.get_state(config)
        if not state.next:
            raise typer.BadParameter("no paused workflow is available for this engagement")
        if tuple(state.next) != ("approval_gate",):
            raise typer.BadParameter("workflow is paused at an unexpected step")
        if state.values.get("engagement_id") != engagement_id or state.values.get("scope") != manifest.model_dump(
            mode="json"
        ):
            raise typer.BadParameter("saved workflow state does not match the verified scope")
        if not approve_simulation and not typer.confirm(
            "Approve the pending offline fixture-only step?", default=False
        ):
            result = graph.invoke(Command(resume={"approved": False, "reviewer_id": reviewer_id}), config=config)
        else:
            token, expires_at = approvals.issue(engagement_id, reviewer_id)
            console.print(f"Approval token issued for {reviewer_id}; expires {expires_at.isoformat()}.")
            result = graph.invoke(
                Command(resume={"approved": True, "approval_token": token, "reviewer_id": reviewer_id}), config=config
            )
    console.print(f"Workflow phase: [bold]{result.get('phase', 'unknown')}[/bold]")
    for kind, path in result.get("report_paths", {}).items():
        console.print(f"{kind}: {path}")


@audit_app.command("verify")
def audit_verify(audit_db: Path = typer.Option(Path("sentinel-audit.sqlite3"), "--db", "--audit-db")) -> None:
    """Verify hash links and contents in the local audit log."""
    ok, message = AuditLog(audit_db).verify()
    console.print(message, style="green" if ok else "red")
    if not ok:
        raise typer.Exit(code=1)


@audit_app.command("list")
def audit_list(
    audit_db: Path = typer.Option(Path("sentinel-audit.sqlite3"), "--db", "--audit-db"),
    engagement_id: str | None = typer.Option(None, "--engagement-id"),
) -> None:
    """Print audit events as JSON; optionally filter by engagement."""
    console.print_json(json.dumps(AuditLog(audit_db).list_events(engagement_id), indent=2))


@mcp_app.command("serve")
def mcp_serve() -> None:
    """Serve only signed-scope-checked offline fixtures over local MCP stdio."""
    from sentinel.mcp_gateway.server import main

    main()


@mcp_app.command("status")
def mcp_status() -> None:
    """Describe the local, fixture-only MCP transport."""
    console.print("MCP transport: local stdio, started only by `sentinel mcp serve`.")
    console.print("Backend: built-in static fixtures; network and subprocess execution are not implemented.")


@app.command("report")
def report(
    engagement_id: str = typer.Argument(...),
    output_format: Literal["md", "json", "sarif"] = typer.Option("md", "--format"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports-dir"),
) -> None:
    """Read a report bundle created by a completed simulation."""
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", engagement_id).strip(".-") or "engagement"
    suffix = {"md": ".md", "json": ".json", "sarif": ".sarif.json"}[output_format]
    report_path = reports_dir / f"{safe_id}{suffix}"
    if not report_path.is_file():
        raise typer.BadParameter(f"report not found: {report_path}")
    content = report_path.read_text(encoding="utf-8")
    if output_format in {"json", "sarif"}:
        console.print_json(content)
    else:
        console.print(content, markup=False)


@app.command()
def version() -> None:
    console.print(f"SENTINEL {__version__} · mock-only")


def main() -> None:
    app()
