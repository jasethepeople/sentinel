from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli.app import app

runner = CliRunner()


def test_cli_init_engage_report_and_audit(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    private_key = tmp_path / "scope-signing-key.pem"
    public_key = tmp_path / "scope-signing-key.pub"
    initialized = runner.invoke(
        app,
        [
            "init",
            "--engagement-id",
            "cli-test-001",
            "--scope",
            str(scope),
            "--private-key",
            str(private_key),
            "--public-key",
            str(public_key),
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    audit_db = tmp_path / "audit.sqlite3"
    checkpoint_db = tmp_path / "checkpoints.sqlite3"
    reports = tmp_path / "reports"
    engaged = runner.invoke(
        app,
        [
            "engage",
            "--scope",
            str(scope),
            "--public-key",
            str(public_key),
            "--audit-db",
            str(audit_db),
            "--checkpoint-db",
            str(checkpoint_db),
            "--reports-dir",
            str(reports),
            "--approve-simulation",
        ],
    )
    assert engaged.exit_code == 0, engaged.output
    assert "Workflow phase: completed" in engaged.output
    assert (reports / "cli-test-001.json").is_file()
    displayed = runner.invoke(app, ["report", "cli-test-001", "--format", "json", "--reports-dir", str(reports)])
    assert displayed.exit_code == 0, displayed.output
    verified = runner.invoke(app, ["audit", "verify", "--db", str(audit_db)])
    assert verified.exit_code == 0, verified.output


def test_cli_lists_tools_and_reports_mcp_status() -> None:
    assert runner.invoke(app, ["tools", "list"]).exit_code == 0
    assert runner.invoke(app, ["tools", "info", "simulate_asset_inventory"]).exit_code == 0
    assert runner.invoke(app, ["mcp", "status"]).exit_code == 0
    assert runner.invoke(app, ["version"]).exit_code == 0


def test_cli_refuses_to_overwrite_key_or_scope_files(tmp_path: Path) -> None:
    for name in ("scope.yaml", "scope-signing-key.pem", "scope-signing-key.pub"):
        (tmp_path / name).write_text("existing", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "init",
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--private-key",
            str(tmp_path / "scope-signing-key.pem"),
            "--public-key",
            str(tmp_path / "scope-signing-key.pub"),
        ],
    )
    assert result.exit_code != 0
    assert "refusing to overwrite" in result.output


def test_cli_rejects_out_of_scope_target(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    private_key = tmp_path / "scope-signing-key.pem"
    public_key = tmp_path / "scope-signing-key.pub"
    init = runner.invoke(
        app, ["init", "--scope", str(scope), "--private-key", str(private_key), "--public-key", str(public_key)]
    )
    assert init.exit_code == 0, init.output
    result = runner.invoke(
        app,
        [
            "engage",
            "--scope",
            str(scope),
            "--public-key",
            str(public_key),
            "--target",
            "example.invalid",
            "--approve-simulation",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--audit-db",
            str(tmp_path / "audit.sqlite3"),
            "--checkpoint-db",
            str(tmp_path / "checkpoints.sqlite3"),
        ],
    )
    assert result.exit_code != 0
    assert "outside" in result.output or "not in" in result.output
