"""Parse project Python files without writing __pycache__ files."""
from __future__ import annotations

import ast
from pathlib import Path


# Folders that hold third-party code or build artifacts and are not part of
# our own source tree. The local venv must be skipped or we'd end up parsing
# every dependency's source file too.
EXCLUDE_PARTS = {".venv", "venv", "env", "__pycache__", "node_modules", ".git"}


def _included(path: Path) -> bool:
    return not any(part in EXCLUDE_PARTS for part in path.parts)


def main() -> int:
    roots = [Path("backend"), Path("agent"), Path("scripts")]
    files = [
        path
        for root in roots
        for path in root.rglob("*.py")
        if _included(path)
    ]
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print(f"parsed {len(files)} python files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
