"""Parse project Python files without writing __pycache__ files."""
from __future__ import annotations

import ast
from pathlib import Path


def main() -> int:
    roots = [Path("backend"), Path("agent"), Path("scripts")]
    files = [path for root in roots for path in root.rglob("*.py")]
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print(f"parsed {len(files)} python files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
