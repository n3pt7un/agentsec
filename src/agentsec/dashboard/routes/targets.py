"""Target discovery endpoint."""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi import APIRouter, Query

router = APIRouter(prefix="/api/targets", tags=["targets"])

# Project root = src/agentsec/dashboard/routes/../../../../../../  (up 5 levels from this file)
_project_root = Path(__file__).parents[4]
_default_targets_dir = str(_project_root / "tests" / "targets")


@router.get("")
async def list_targets(
    directory: str = Query(
        default=_default_targets_dir, description="Directory to scan for harnesses"
    ),  # noqa: E501
) -> dict:
    """Discover available target harness files."""
    targets_dir = Path(directory)
    if not targets_dir.exists():  # noqa: ASYNC240
        return {"targets": []}

    targets = []
    for path in sorted(targets_dir.glob("*_harness.py")):  # noqa: ASYNC240
        builder = _find_builder(path)
        if builder:
            targets.append(
                {
                    "path": str(path),
                    "name": path.stem,
                    "builder": builder,
                }
            )
    return {"targets": targets}


def _find_builder(path: Path) -> str | None:
    """Find a build_* function in a Python file without executing it fully."""
    try:
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("build_"):
                return node.name
    except Exception:
        pass
    return None
