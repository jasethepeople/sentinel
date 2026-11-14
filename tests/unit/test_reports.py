from __future__ import annotations

import json
from pathlib import Path

from sentinel.agents.report import build_report, build_sarif, write_bundle


def test_report_bundle_is_explicitly_synthetic(tmp_path: Path) -> None:
    report = build_report("demo-123", "example.org", [], {"mode": "mock_only"})
    paths = write_bundle(report, tmp_path)
    assert all(Path(path).is_file() for path in paths.values())
    saved = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert saved["mode"] == "mock_only"
    assert saved["findings"] == []
    assert "Synthetic demonstration only" in Path(paths["markdown"]).read_text(encoding="utf-8")
    assert build_sarif(report)["runs"][0]["results"] == []


def test_report_filename_sanitizes_engagement_id(tmp_path: Path) -> None:
    report = build_report("../../unsafe id", "example.org", [], {})
    paths = write_bundle(report, tmp_path)
    assert all(Path(path).parent == tmp_path.resolve() for path in paths.values())
