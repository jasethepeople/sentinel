from __future__ import annotations

from pathlib import Path

from sentinel.config import Settings


def test_settings_defaults_are_local_files(tmp_path: Path) -> None:
    settings = Settings()
    assert settings.scope_file.name == "scope.yaml"
    assert settings.public_key_file.name == "scope-signing-key.pub"
    assert settings.audit_db.name == "sentinel-audit.sqlite3"
    custom = Settings(scope_file=tmp_path / "custom.yaml", registry_dir=tmp_path)
    assert custom.scope_file == tmp_path / "custom.yaml"
    assert custom.registry_dir == tmp_path
