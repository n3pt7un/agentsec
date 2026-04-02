"""Shared utilities for loading target graphs and creating adapters."""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def find_project_root(path: Path) -> Path | None:
    """Walk up from *path* looking for a pyproject.toml or .git directory."""
    for parent in [path, *path.parents]:
        if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
            return parent
    return None


def load_graph(
    target: str,
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
):
    """Dynamically import a target module and return its compiled graph.

    Looks for any callable starting with ``build_`` and invokes it, or
    falls back to a ``graph`` module attribute.

    Args:
        target: Path to a Python file containing a graph builder.
        vulnerable: Pass vulnerable flag to fixture builders.
        live: Use a real LLM via OpenRouter for target agents.
        target_model: OpenRouter model ID for live mode.

    Returns:
        A compiled graph object.

    Raises:
        ValueError: When no graph can be found in the target module.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise ValueError(f"Target file not found: {target}")

    spec = importlib.util.spec_from_file_location("_target", str(target_path))
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load module from: {target}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["_target"] = module

    project_root = find_project_root(target_path)
    if project_root and str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    spec.loader.exec_module(module)

    for attr_name in sorted(dir(module)):
        if attr_name.startswith("build_") and callable(getattr(module, attr_name)):
            builder = getattr(module, attr_name)
            sig = inspect.signature(builder)
            kwargs: dict = {}
            if "live" in sig.parameters:
                kwargs["live"] = live
            if "target_model" in sig.parameters:
                kwargs["target_model"] = target_model
            if "vulnerable" in sig.parameters:
                kwargs["vulnerable"] = vulnerable
            return builder(**kwargs)

    graph = getattr(module, "graph", None)
    if graph is not None:
        return graph

    raise ValueError(f"No build_* function or 'graph' attribute found in {target}")


def make_adapter(adapter_name: str, graph):
    """Create an adapter instance from its name.

    Args:
        adapter_name: Adapter identifier (currently only "langgraph").
        graph: A compiled graph object.

    Returns:
        An adapter instance.

    Raises:
        ValueError: If the adapter name is unknown.
    """
    if adapter_name != "langgraph":
        raise ValueError(f"Unknown adapter: {adapter_name}. Supported: langgraph")

    from agentsec.adapters.langgraph import LangGraphAdapter

    return LangGraphAdapter(graph)
