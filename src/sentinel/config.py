from pathlib import Path

from pydantic import BaseModel, ConfigDict


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_file: Path = Path("scope.yaml")
    public_key_file: Path = Path("scope-signing-key.pub")
    audit_db: Path = Path("sentinel-audit.sqlite3")
    registry_dir: Path | None = None
