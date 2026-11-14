# Installation and operation

## Local install

Requirements: Python 3.12 or 3.13 and `uv`.

```bash
uv sync --locked --extra dev
uv run sentinel init
uv run sentinel tools list
uv run sentinel engage --scope scope.yaml --approve-simulation
uv run sentinel report ENGAGEMENT_ID --format json
uv run sentinel audit verify --db sentinel-audit.sqlite3
```

Replace `ENGAGEMENT_ID` with the ID printed by `sentinel init`. The default signed target is the documentation-only `192.0.2.0/24` range. `init` refuses to overwrite existing scope or key files. The private key is created with owner-only permissions and is excluded from Git. Store it separately and back it up securely.

To pause for a prompt before the extra fixture, omit `--approve-simulation`. If the process is interrupted at the prompt, resume with `sentinel resume ENGAGEMENT_ID --scope scope.yaml --public-key scope-signing-key.pub --checkpoint-db sentinel-checkpoints.sqlite3`. Declining writes a report without the extra fixture.

## Python package

```bash
uv build
bash scripts/audit-dependencies.sh
```

`uv build` produces an sdist and wheel under `dist/`. `scripts/build-binary.sh` creates a one-file PyInstaller executable for the current OS/CPU. Release automation builds Linux and macOS artifacts from a version tag.

## Docker (optional)

Docker is not required by the test suite. The image packages the simulator; it does not contain security tools. Runtime Compose configuration has `network_mode: none`, a read-only root filesystem, no Linux capabilities, and a writable named volume only at `/data`.

```bash
docker compose build
docker compose run --rm sentinel init --scope /data/scope.yaml --private-key /data/scope-signing-key.pem --public-key /data/scope-signing-key.pub
docker compose run --rm sentinel tools list
docker compose run --rm sentinel engage --scope /data/scope.yaml --public-key /data/scope-signing-key.pub --audit-db /data/audit.sqlite3 --checkpoint-db /data/checkpoints.sqlite3 --reports-dir /data/reports --approve-simulation
```

Docker was not available in the build environment, so the Compose runtime has not been executed here. The Python test and packaging workflows do not require Docker.

## MCP

`sentinel mcp serve` starts a stdio server in the current process. Point a trusted local MCP client at that command and set `SENTINEL_SCOPE_FILE`, `SENTINEL_PUBLIC_KEY`, and `SENTINEL_AUDIT_DB` as needed. No TCP listener or remote MCP transport is provided.
