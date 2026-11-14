# Contributing

Use Python 3.12 or 3.13 and `uv`.

```bash
uv sync --locked --extra dev
uv run ruff check --no-respect-gitignore .
uv run mypy src/sentinel
uv run pytest --cov=sentinel
bash scripts/audit-dependencies.sh
uv build
```

Changes must preserve the mock-only safety boundary in `AGENTS.md` and `SAFETY.md`. Add tests for policy changes, audit behavior, scope parsing, and user-visible commands. Do not add external service calls or code-execution paths. CI runs the same checks on pushes and pull requests.
