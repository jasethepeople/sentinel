from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_report(
    engagement_id: str, target: str, fixtures: list[dict[str, Any]], analysis: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "target": target,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "mock_only",
        "notice": "Synthetic demonstration only. No target was contacted, scanned, validated, or tested.",
        "fixture_results": fixtures,
        "analysis": analysis,
        "findings": [],
    }


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SENTINEL mock-only",
                        "informationUri": "https://github.com/jasethepeople/sentinel",
                        "rules": [],
                    }
                },
                "results": [],
                "properties": {
                    "sentinelMode": "mock_only",
                    "notice": report["notice"],
                    "fixtureCount": len(report["fixture_results"]),
                },
            }
        ],
    }


def write_bundle(report: dict[str, Any], output_dir: Path) -> dict[str, str]:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", report["engagement_id"]).strip(".-") or "engagement"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{safe_id}.json"
    markdown_path = output_dir / f"{safe_id}.md"
    sarif_path = output_dir / f"{safe_id}.sarif.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(
        "# SENTINEL mock-only report\n\n"
        f"> **Synthetic demonstration only.** {report['notice']}\n\n"
        f"- Engagement: `{report['engagement_id']}`\n"
        f"- Scope target: `{report['target']}`\n"
        f"- Generated: {report['generated_at']}\n"
        f"- Fixture records: {len(report['fixture_results'])}\n\n"
        "## Fixture output\n\n"
        "The data below is bundled sample content, not observations about the target.\n\n"
        "```json\n" + json.dumps(report["fixture_results"], indent=2, sort_keys=True) + "\n```\n",
        encoding="utf-8",
    )
    sarif_path.write_text(json.dumps(build_sarif(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "json": str(json_path.resolve()),
        "markdown": str(markdown_path.resolve()),
        "sarif": str(sarif_path.resolve()),
    }
