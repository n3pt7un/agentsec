# Semantic Agent Targeting — Design Spec

**Date:** 2026-04-03
**Status:** Approved

## Problem

All probes currently select their target via `agents[0]` — the first node returned by `graph_view.nodes`. This is positionally accidental: `agents[0]` happens to be the entry-point in most fixtures, but that breaks on any graph compiled in a different order. Worse, probes that conceptually need a node with tools (ASI02, ASI04, ASI05) or an orchestrator (ASI07) silently attack the wrong node instead of skipping with a clear signal.

## Goals

1. Every probe attacks the semantically correct agent for its attack type.
2. When no suitable agent exists, the probe returns `FindingStatus.SKIPPED` with a clear `"no suitable target"` message — no silent fallback to `agents[0]`.
3. Entry-point probes are robust across different graph build orders.
4. Orchestrator detection distinguishes LLM-driven routing from deterministic Python conditionals.

## Changes to `AgentInfo`

Add two new fields to `AgentInfo` in `src/agentsec/adapters/base.py`:

```python
is_entry_point: bool = False
# True if this node is directly reachable from __start__

routing_type: Literal["llm", "deterministic", "unknown"] = "unknown"
# Set only for nodes that have conditional outbound edges.
# "llm"           – routing function contains actual LLM call expressions
# "deterministic" – routing function is pure Python (no LLM calls detected)
# "unknown"       – node has no conditional edges, or detection inconclusive
```

`"unknown"` is the safe default — probes that care about this field always check explicitly.

## Changes to `LangGraphAdapter.discover()`

In `src/agentsec/adapters/langgraph.py`:

**Entry point detection:** After building the edge map, collect all nodes that appear as targets of `__start__` edges:

```python
entry_point_names: set[str] = {
    tgt for src, tgt in [(e.source, e.target) for e in graph_view.edges]
    if src == "__start__" and tgt not in _INTERNAL_NODES
}
```

Set `is_entry_point=True` on any `AgentInfo` whose `name` is in `entry_point_names`.

**Routing type detection:** After building `AgentInfo` list, iterate `builder.branches` (a `defaultdict[str, dict[str, BranchSpec]]`). For each `(node_name, branch_dict)` pair, inspect the routing function with the `_detect_routing_type()` helper (see below) and update the matching `AgentInfo.routing_type`.

**`_detect_routing_type(fn) -> Literal["llm", "deterministic", "unknown"]`**

Uses `inspect.getsource()` + `ast.parse()` to walk the function AST. Returns `"llm"` if the AST contains a `Call` node where the function is an attribute-access expression (`ast.Attribute`) on an object whose name contains `llm`, `model`, `chain`, or `agent` (case-insensitive). Returns `"deterministic"` if source is available but no such calls are found. Returns `"unknown"` if source inspection fails (compiled, lambda, etc.).

Keyword-in-source-text is explicitly rejected — `hallucination_check`'s routing function mentions "LLM" in a docstring but routes deterministically.

## New Helpers on `BaseProbe`

Add four static methods to `BaseProbe` in `src/agentsec/core/probe_base.py`:

```python
@staticmethod
def _select_entry_point(agents: list[AgentInfo]) -> AgentInfo | None:
    """First agent with is_entry_point=True, or first agent overall."""
    ep = [a for a in agents if a.is_entry_point]
    return ep[0] if ep else (agents[0] if agents else None)

@staticmethod
def _select_tool_agent(agents: list[AgentInfo]) -> AgentInfo | None:
    """First agent with at least one tool, or None."""
    for a in agents:
        if a.tools:
            return a
    return None

@staticmethod
def _select_orchestrator(agents: list[AgentInfo]) -> AgentInfo | None:
    """Best candidate orchestrator, or None.

    Priority:
    1. LLM-router with most downstream agents
    2. Any node with conditional edges (routing_type != "unknown") with most downstream
    3. None — no conditional-edge nodes detected
    """
    llm_routers = [a for a in agents if a.routing_type == "llm"]
    if llm_routers:
        return max(llm_routers, key=lambda a: len(a.downstream_agents))
    conditional = [a for a in agents if a.routing_type in ("llm", "deterministic")]
    if conditional:
        return max(conditional, key=lambda a: len(a.downstream_agents))
    return None

@staticmethod
def _select_worker(agents: list[AgentInfo]) -> AgentInfo | None:
    """First non-entry-point agent, or None if only one agent exists."""
    workers = [a for a in agents if not a.is_entry_point]
    return workers[0] if workers else None
```

Also add a shared skip factory to `BaseProbe`:

```python
def _no_target_finding(self, reason: str) -> Finding:
    """Return a SKIPPED finding when no suitable agent is available."""
    meta = self.metadata()
    return Finding(
        probe_id=meta.id,
        probe_name=meta.name,
        category=meta.category,
        severity=meta.default_severity,
        status=FindingStatus.SKIPPED,
        title=f"{meta.name} — no suitable target",
        description=reason,
        remediation=self.remediation(),
    )
```

## Targeting Strategy Per Probe

| Probe | Selector | If None → |
|---|---|---|
| ASI01-INDIRECT-INJECT | `_select_entry_point` | always found |
| ASI01-ROLE-CONFUSION | `_select_entry_point` | always found |
| ASI02-PARAM-INJECTION | `_select_tool_agent` | SKIPPED |
| ASI02-TOOL-CHAIN-ABUSE | `_select_tool_agent` | SKIPPED |
| ASI03-CRED-EXTRACTION | `_select_entry_point` | always found |
| ASI03-IMPERSONATION | `_select_entry_point` | always found |
| ASI04-TOOL-POISONING | `_select_tool_agent` | SKIPPED |
| ASI04-DEPENDENCY-INJECT | `_select_tool_agent` | SKIPPED |
| ASI05-CODE-INJECTION | `_select_tool_agent` | fall to `_select_entry_point` |
| ASI05-SANDBOX-ESCAPE | `_select_tool_agent` | fall to `_select_entry_point` |
| ASI06-MEMORY-POISON | `_select_entry_point` | already skips on no memory |
| ASI06-CONTEXT-LEAK | `_select_entry_point` | already skips on no memory |
| ASI07-MSG-TAMPER | `_select_worker` | SKIPPED |
| ASI07-ORCHESTRATOR-HIJACK | `_select_orchestrator` | SKIPPED |
| ASI08-CASCADE-TRIGGER | `_select_entry_point` | always found |
| ASI08-RESOURCE-EXHAUST | `_select_entry_point` | always found |
| ASI09-AUTHORITY-SPOOF | `_select_entry_point` | always found |
| ASI09-CONFIRMATION-BYPASS | `_select_entry_point` | always found |
| ASI10-OBJECTIVE-DIVERGE | `_select_entry_point` | always found |
| ASI10-COVERT-EXFIL | `_select_tool_agent` | fall to `_select_entry_point` |

ASI05 and ASI10-COVERT-EXFIL prefer a tool agent (code execution / exfil tool) but still have a meaningful attack against an entry point, so they fall through rather than skip.

## Skip vs. Fallback Policy

- **Always skip** (return `_no_target_finding()`): ASI02, ASI04, ASI07-MSG-TAMPER, ASI07-ORCHESTRATOR-HIJACK. These probes are meaningless against the wrong node type.
- **Fall to entry point**: ASI05, ASI10-COVERT-EXFIL. The attack is still valid even without tools.
- **Already handled**: ASI06 skips when no memory store is found.
- **No skip needed**: All other entry-point probes — `_select_entry_point` always returns something (falls back to `agents[0]` internally only when no node is explicitly marked).

## Files Changed

| File | Change |
|---|---|
| `src/agentsec/adapters/base.py` | Add `is_entry_point`, `routing_type` to `AgentInfo` |
| `src/agentsec/adapters/langgraph.py` | Populate new fields in `discover()`; add `_detect_routing_type()` |
| `src/agentsec/core/probe_base.py` | Add four selector statics + `_no_target_finding()` |
| All 20 probe files | Replace `agents[0]` with appropriate selector |
| `tests/test_adapters/test_langgraph.py` | Tests for `is_entry_point` and `routing_type` population |
| `tests/test_core/test_probe_base.py` | Tests for the four selector helpers |

## Out of Scope

- Adapter-level filtering methods (`adapter.entry_points()`, etc.) — probes filter the raw list themselves, keeping the adapter interface minimal.
- Multi-root fan-in graphs: `_select_entry_point` returns the first entry point alphabetically when multiple exist; this is deterministic and good enough for attack targeting.
- Persisting routing type as graph metadata — runtime detection is sufficient.
