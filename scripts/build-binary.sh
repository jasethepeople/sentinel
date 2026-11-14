#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

uv run pyinstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name sentinel \
  --paths "$ROOT/src" \
  --add-data "$ROOT/src/sentinel/registry/tools:sentinel/registry/tools" \
  --add-data "$ROOT/src/sentinel/security/policies/default.json:sentinel/security/policies" \
  --distpath "$ROOT/dist/bin" \
  --workpath "$ROOT/build/pyinstaller" \
  --specpath "$ROOT/build/specs" \
  "$ROOT/src/sentinel/__main__.py"
