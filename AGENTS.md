# SENTINEL project rules

- This repository is intentionally **mock-only**. Never add live network access, scanner/exploit/credential tools, arbitrary command execution, remote MCP, or LLM-directed actions under the current product scope.
- Keep the gateway as the only fixture invocation path. Validate the signed, time-bounded scope and default-deny role policy on every call; exclusions override authorization; audit deny/allow/completion events.
- The registry must remain a fixed allowlist with empty user-supplied tool parameters and the in-process fixture backend. Treat targets as labels for fixtures, never as endpoints to contact.
- Human approval may unlock only the extra synthetic fixture step. Keep approval tokens single-use, expiring, and bound to reviewer plus engagement.
- Every report and README must say that outputs are synthetic and no target was contacted or tested.
- Before committing or releasing, run `uv run ruff check --no-respect-gitignore .`, `uv run mypy src/sentinel`, `uv run pytest --cov=sentinel`, `bash scripts/audit-dependencies.sh`, and `uv build`.
