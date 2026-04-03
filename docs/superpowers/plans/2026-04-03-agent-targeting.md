# Semantic Agent Targeting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace blind `agents[0]` targeting in all 20 probes with semantic selection based on `is_entry_point`, `tools`, and `routing_type` — and skip with an honest finding when no suitable target exists.

**Architecture:** Add two fields to `AgentInfo` (`is_entry_point`, `routing_type`), populate them in `LangGraphAdapter.discover()` using edge analysis + AST-based routing function inspection, then add four static selector helpers and a `_no_target_finding()` factory to `BaseProbe`. Each probe calls the appropriate selector and skips or falls through based on the policy in the spec.

**Tech Stack:** Python 3.12 / Pydantic v2 / `ast` stdlib / pytest + pytest-asyncio / `uv run pytest`

---

## File Map

| File | Change |
|---|---|
| `src/agentsec/adapters/base.py` | Add `is_entry_point: bool`, `routing_type: Literal[...]` to `AgentInfo` |
| `src/agentsec/adapters/langgraph.py` | Populate new fields in `discover()`; add module-level `_detect_routing_type()` |
| `src/agentsec/core/probe_base.py` | Add `_select_entry_point`, `_select_tool_agent`, `_select_orchestrator`, `_select_worker`, `_no_target_finding` |
| `src/agentsec/probes/asi01_*/indirect_inject.py` | `agents[0]` → `_select_entry_point` |
| `src/agentsec/probes/asi01_*/role_confusion.py` | same |
| `src/agentsec/probes/asi02_*/param_injection.py` | `agents[0]` → `_select_tool_agent`, skip if None |
| `src/agentsec/probes/asi02_*/tool_chain_abuse.py` | same |
| `src/agentsec/probes/asi03_*/cred_extraction.py` | `agents[0]` → `_select_entry_point` |
| `src/agentsec/probes/asi03_*/impersonation.py` | same |
| `src/agentsec/probes/asi04_*/tool_poisoning.py` | `agents[0]` → `_select_tool_agent`, skip if None |
| `src/agentsec/probes/asi04_*/dependency_inject.py` | same |
| `src/agentsec/probes/asi05_*/code_injection.py` | `agents[0]` → `_select_tool_agent` else `_select_entry_point` |
| `src/agentsec/probes/asi05_*/sandbox_escape.py` | same |
| `src/agentsec/probes/asi06_*/memory_poison.py` | `agents[0]` → `_select_entry_point` (skip logic unchanged) |
| `src/agentsec/probes/asi06_*/context_leak.py` | same |
| `src/agentsec/probes/asi07_*/msg_tamper.py` | `agents[0/1]` → `_select_worker`, skip if None |
| `src/agentsec/probes/asi07_*/orchestrator_hijack.py` | `agents[0]` → `_select_orchestrator`, skip if None |
| `src/agentsec/probes/asi08_*/cascade_trigger.py` | `agents[0]` → `_select_entry_point` |
| `src/agentsec/probes/asi08_*/resource_exhaust.py` | same |
| `src/agentsec/probes/asi09_*/authority_spoof.py` | `agents[0]` → `_select_entry_point` |
| `src/agentsec/probes/asi09_*/confirmation_bypass.py` | same |
| `src/agentsec/probes/asi10_*/objective_diverge.py` | `agents[0]` → `_select_entry_point` |
| `src/agentsec/probes/asi10_*/covert_exfil.py` | `agents[0]` → `_select_tool_agent` else `_select_entry_point` |
| `tests/test_adapters/test_langgraph.py` | Tests for `is_entry_point` and `routing_type` |
| `tests/test_core/test_probe_base.py` | Tests for four selector helpers |

---

## Task 1: Extend `AgentInfo` with `is_entry_point` and `routing_type`

**Files:**
- Modify: `src/agentsec/adapters/base.py`

- [ ] **Step 1: Add the two new fields**

Open `src/agentsec/adapters/base.py`. Replace the `AgentInfo` class body with:

```python
class AgentInfo(BaseModel):
    """Discovered agent in the target system."""

    name: str
    role: str | None = None
    tools: list[str] = Field(default_factory=list)
    downstream_agents: list[str] = Field(default_factory=list)
    is_entry_point: bool = False
    routing_type: Literal["llm", "deterministic", "unknown"] = "unknown"
```

Add `Literal` to the import at the top of the file:

```python
from typing import Literal
```

- [ ] **Step 2: Run existing adapter tests to confirm nothing broke**

```bash
uv run pytest tests/test_adapters/ -v
```

Expected: all existing tests pass (new fields have defaults so nothing breaks).

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/adapters/base.py
git commit -m "$(cat <<'EOF'
ENH: add is_entry_point and routing_type fields to AgentInfo

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Populate new fields in `LangGraphAdapter.discover()`

**Files:**
- Modify: `src/agentsec/adapters/langgraph.py`
- Test: `tests/test_adapters/test_langgraph.py`

- [ ] **Step 1: Write failing tests**

Read `tests/test_adapters/test_langgraph.py` to find the right class, then add:

```python
@pytest.mark.asyncio
async def test_entry_point_detected(supervisor_crew_graph):
    adapter = LangGraphAdapter(graph=supervisor_crew_graph)
    agents = await adapter.discover()
    entry_points = [a for a in agents if a.is_entry_point]
    assert len(entry_points) >= 1, "At least one entry point should be detected"
    # supervisor_crew: __start__ -> supervisor
    assert entry_points[0].name == "supervisor"

@pytest.mark.asyncio
async def test_routing_type_deterministic(email_graph):
    adapter = LangGraphAdapter(graph=email_graph)
    agents = await adapter.discover()
    # email_automation: quality_check has a conditional edge with pure Python routing
    qc = next((a for a in agents if a.name == "quality_check"), None)
    assert qc is not None
    assert qc.routing_type in ("deterministic", "unknown")  # not "llm"
```

Check the existing test file to find the fixture names for supervisor and email graphs and adjust accordingly.

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/test_adapters/test_langgraph.py -k "entry_point or routing_type" -v
```

Expected: both fail — `is_entry_point` is always `False`, `routing_type` is always `"unknown"`.

- [ ] **Step 3: Add `_detect_routing_type()` module-level helper**

Add this function near the top of `src/agentsec/adapters/langgraph.py`, after the imports:

```python
import ast
import inspect


def _detect_routing_type(fn) -> str:
    """Detect whether a routing function makes LLM calls.

    Uses AST inspection — not source keyword search — to find Call nodes
    where the callee is an attribute access on an object whose name
    contains 'llm', 'model', 'chain', or 'agent' (case-insensitive).

    Returns:
        "llm"           if LLM call expressions are found in the AST
        "deterministic" if source is available but no LLM calls found
        "unknown"       if source cannot be retrieved (compiled, lambda, etc.)
    """
    try:
        source = inspect.getsource(fn)
        tree = ast.parse(source)
    except (OSError, TypeError, IndentationError):
        return "unknown"

    _LLM_NAMES = frozenset({"llm", "model", "chain", "agent"})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                # e.g. self.llm.invoke(...) or model.predict(...)
                obj = func.value
                # Walk the object chain to find a matching name
                while isinstance(obj, ast.Attribute):
                    if obj.attr.lower() in _LLM_NAMES:
                        return "llm"
                    obj = obj.value
                if isinstance(obj, ast.Name) and obj.id.lower() in _LLM_NAMES:
                    return "llm"

    return "deterministic"
```

- [ ] **Step 4: Update `discover()` to populate `is_entry_point`**

Inside `discover()`, before the `agents: list[AgentInfo] = []` line, add:

```python
# Collect nodes directly reachable from __start__
entry_point_names: set[str] = {
    e.target
    for e in graph_view.edges
    if e.source == "__start__" and e.target not in _INTERNAL_NODES
}
```

Then when constructing each `AgentInfo`, set `is_entry_point`:

```python
agents.append(
    AgentInfo(
        name=node_id,
        role=role,
        tools=tools,
        downstream_agents=edge_map.get(node_id, []),
        is_entry_point=node_id in entry_point_names,
    )
)
```

- [ ] **Step 5: Update `discover()` to populate `routing_type`**

After `self._agents = agents`, but before `return agents`, add:

```python
# Populate routing_type for nodes with conditional edges
if hasattr(self.graph, "builder") and hasattr(self.graph.builder, "branches"):
    for node_name, branch_dict in self.graph.builder.branches.items():
        for branch_spec in branch_dict.values():
            fn = getattr(branch_spec.path, "func", branch_spec.path)
            rtype = _detect_routing_type(fn)
            for agent in self._agents:
                if agent.name == node_name:
                    agent.routing_type = rtype
                    break
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
uv run pytest tests/test_adapters/ -v
```

Expected: all adapter tests pass including the two new ones.

- [ ] **Step 7: Commit**

```bash
git add src/agentsec/adapters/langgraph.py tests/test_adapters/test_langgraph.py
git commit -m "$(cat <<'EOF'
ENH: populate is_entry_point and routing_type in LangGraphAdapter.discover()

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add selector helpers and `_no_target_finding()` to `BaseProbe`

**Files:**
- Modify: `src/agentsec/core/probe_base.py`
- Test: `tests/test_core/test_probe_base.py`

- [ ] **Step 1: Write failing tests**

Read `tests/test_core/test_probe_base.py` to understand the fixture style, then add a new test class:

```python
from agentsec.adapters.base import AgentInfo


class TestProbeSelectors:
    def _make_agents(self):
        return [
            AgentInfo(name="classify", is_entry_point=True, tools=[]),
            AgentInfo(name="retrieve", is_entry_point=False, tools=["vector_search"]),
            AgentInfo(name="draft", is_entry_point=False, tools=[]),
            AgentInfo(
                name="router",
                is_entry_point=False,
                tools=[],
                routing_type="llm",
                downstream_agents=["worker_a", "worker_b", "worker_c"],
            ),
        ]

    def test_select_entry_point_returns_entry_point(self):
        from agentsec.core.probe_base import BaseProbe
        agents = self._make_agents()
        result = BaseProbe._select_entry_point(agents)
        assert result.name == "classify"

    def test_select_entry_point_falls_back_to_first(self):
        from agentsec.core.probe_base import BaseProbe
        agents = [AgentInfo(name="only", is_entry_point=False, tools=[])]
        result = BaseProbe._select_entry_point(agents)
        assert result.name == "only"

    def test_select_entry_point_empty_returns_none(self):
        from agentsec.core.probe_base import BaseProbe
        assert BaseProbe._select_entry_point([]) is None

    def test_select_tool_agent_returns_agent_with_tools(self):
        from agentsec.core.probe_base import BaseProbe
        agents = self._make_agents()
        result = BaseProbe._select_tool_agent(agents)
        assert result.name == "retrieve"

    def test_select_tool_agent_returns_none_if_no_tools(self):
        from agentsec.core.probe_base import BaseProbe
        agents = [
            AgentInfo(name="a", tools=[]),
            AgentInfo(name="b", tools=[]),
        ]
        assert BaseProbe._select_tool_agent(agents) is None

    def test_select_orchestrator_prefers_llm_router(self):
        from agentsec.core.probe_base import BaseProbe
        agents = self._make_agents()
        result = BaseProbe._select_orchestrator(agents)
        assert result.name == "router"

    def test_select_orchestrator_returns_none_when_no_conditional_edges(self):
        from agentsec.core.probe_base import BaseProbe
        agents = [
            AgentInfo(name="a", routing_type="unknown"),
            AgentInfo(name="b", routing_type="unknown"),
        ]
        assert BaseProbe._select_orchestrator(agents) is None

    def test_select_worker_returns_non_entry_agent(self):
        from agentsec.core.probe_base import BaseProbe
        agents = self._make_agents()
        result = BaseProbe._select_worker(agents)
        assert result.name == "retrieve"

    def test_select_worker_returns_none_if_only_entry_points(self):
        from agentsec.core.probe_base import BaseProbe
        agents = [AgentInfo(name="only", is_entry_point=True, tools=[])]
        assert BaseProbe._select_worker(agents) is None
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/test_core/test_probe_base.py::TestProbeSelectors -v
```

Expected: `AttributeError: type object 'BaseProbe' has no attribute '_select_entry_point'`.

- [ ] **Step 3: Add helpers to `BaseProbe`**

In `src/agentsec/core/probe_base.py`, add the following imports at the top (after existing imports):

```python
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from agentsec.adapters.base import AgentInfo
```

Then add these static methods to `BaseProbe` (after the `_run_detection` method):

```python
@staticmethod
def _select_entry_point(agents: list) -> "AgentInfo | None":
    """First agent with is_entry_point=True, or first agent overall if none marked."""
    ep = [a for a in agents if a.is_entry_point]
    if ep:
        return ep[0]
    return agents[0] if agents else None

@staticmethod
def _select_tool_agent(agents: list) -> "AgentInfo | None":
    """First agent with at least one tool, or None."""
    for a in agents:
        if a.tools:
            return a
    return None

@staticmethod
def _select_orchestrator(agents: list) -> "AgentInfo | None":
    """Best orchestrator candidate based on routing_type and out-degree.

    Priority:
      1. LLM-router with most downstream agents
      2. Any node with deterministic conditional edges (most downstreams)
      3. None — no conditional-edge nodes found
    """
    llm_routers = [a for a in agents if a.routing_type == "llm"]
    if llm_routers:
        return max(llm_routers, key=lambda a: len(a.downstream_agents))
    conditional = [a for a in agents if a.routing_type == "deterministic"]
    if conditional:
        return max(conditional, key=lambda a: len(a.downstream_agents))
    return None

@staticmethod
def _select_worker(agents: list) -> "AgentInfo | None":
    """First non-entry-point agent, or None if every agent is an entry point."""
    workers = [a for a in agents if not a.is_entry_point]
    return workers[0] if workers else None

def _no_target_finding(self, reason: str) -> "Finding":
    """Return a SKIPPED finding when no suitable agent is available for this probe."""
    from agentsec.core.finding import Finding, FindingStatus

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

- [ ] **Step 4: Run tests to confirm they pass**

```bash
uv run pytest tests/test_core/test_probe_base.py -v
```

Expected: all tests including the new `TestProbeSelectors` class pass.

- [ ] **Step 5: Commit**

```bash
git add src/agentsec/core/probe_base.py tests/test_core/test_probe_base.py
git commit -m "$(cat <<'EOF'
ENH: add semantic agent selector helpers to BaseProbe

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Update entry-point probes (ASI01, ASI03, ASI06, ASI08, ASI09, ASI10-OBJECTIVE-DIVERGE)

**Files:** 12 probe files — every probe that uses `agents[0]` and targets the entry point.

For each probe, the change is identical in structure. Find every occurrence of:
- `agents[0]` used as the attack target
- `agents[0].name` used as `target_agent`

Replace with `self._select_entry_point(agents)` and `.name`. There is no skip — `_select_entry_point` always returns something.

- [ ] **Step 1: Update `asi01_goal_hijack/indirect_inject.py`**

Find the lines:
```python
agent = agents[0] if agents else None
```
and later:
```python
target_agent = agents[0].name if agents else "default"
```

Replace both:
```python
agent = self._select_entry_point(agents)
```
```python
target_agent = agent.name if agent else "default"
```

Then wherever `agents[0]` appears after that point as the attack target, replace with `agent` (for the AgentInfo object) or `agent.name` (for the string name).

- [ ] **Step 2: Update `asi01_goal_hijack/role_confusion.py`** — same pattern.

- [ ] **Step 3: Update `asi03_identity_abuse/cred_extraction.py`** — same pattern.

- [ ] **Step 4: Update `asi03_identity_abuse/impersonation.py`**

This probe has 3 uses of `agents[N]`. Replace all three:
```python
agent = agents[0] if agents else None          # → self._select_entry_point(agents)
target_agent = agents[0].name if agents else …  # → agent.name if agent else …
# any other agents[0] reference                 # → agent / agent.name
```

- [ ] **Step 5: Update `asi06_memory_manipulation/memory_poison.py`** — same pattern (skip logic for no-memory stays untouched; only the target selection line changes).

- [ ] **Step 6: Update `asi06_memory_manipulation/context_leak.py`** — same pattern.

- [ ] **Step 7: Update `asi08_cascading_failures/cascade_trigger.py`** — same pattern.

- [ ] **Step 8: Update `asi08_cascading_failures/resource_exhaust.py`** — same pattern.

- [ ] **Step 9: Update `asi09_trust_exploitation/authority_spoof.py`** — same pattern.

- [ ] **Step 10: Update `asi09_trust_exploitation/confirmation_bypass.py`** — same pattern.

- [ ] **Step 11: Update `asi10_rogue_agent/objective_diverge.py`** — same pattern.

- [ ] **Step 12: Run probe tests for these categories**

```bash
uv run pytest tests/test_probes/test_asi01.py tests/test_probes/test_asi03.py \
  tests/test_probes/test_asi06.py tests/test_probes/test_asi08.py \
  tests/test_probes/test_asi09.py tests/test_probes/test_asi10.py -v
```

Expected: all pass.

- [ ] **Step 13: Commit**

```bash
git add \
  src/agentsec/probes/asi01_goal_hijack/ \
  src/agentsec/probes/asi03_identity_abuse/ \
  src/agentsec/probes/asi06_memory_manipulation/ \
  src/agentsec/probes/asi08_cascading_failures/ \
  src/agentsec/probes/asi09_trust_exploitation/ \
  src/agentsec/probes/asi10_rogue_agent/objective_diverge.py
git commit -m "$(cat <<'EOF'
ENH: use _select_entry_point targeting in ASI01/03/06/08/09/10 probes

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update tool-agent probes (ASI02, ASI04) — skip if no tools

**Files:** `param_injection.py`, `tool_chain_abuse.py`, `tool_poisoning.py`, `dependency_inject.py`

Pattern for all four:

```python
agents = await adapter.discover()

# OLD:
# if not any(a.tools for a in agents):
#     return self._skipped_finding(...)
# target_agent = agents[0].name

# NEW:
target = self._select_tool_agent(agents)
if target is None:
    return self._no_target_finding(
        "No agent with registered tools found — parameter injection requires a tool-using agent."
    )
target_agent = target.name
```

The existing `_skipped_finding` calls that check for tools can be replaced entirely with `_no_target_finding`.

- [ ] **Step 1: Update `asi02_tool_misuse/param_injection.py`**

Find the `agents[0]` target line and any existing "no tools" skip logic. Replace with:

```python
target = self._select_tool_agent(agents)
if target is None:
    return self._no_target_finding(
        "No agent with registered tools found — parameter injection requires a tool-using agent."
    )
target_agent = target.name
```

- [ ] **Step 2: Update `asi02_tool_misuse/tool_chain_abuse.py`** — same pattern with message:
```
"No agent with registered tools found — tool chain abuse requires at least one tool-using agent."
```

- [ ] **Step 3: Update `asi04_supply_chain/tool_poisoning.py`** — same pattern with message:
```
"No agent with registered tools found — supply chain poisoning requires a tool-using agent."
```

- [ ] **Step 4: Update `asi04_supply_chain/dependency_inject.py`** — same pattern with message:
```
"No agent with registered tools found — dependency injection requires a tool-using agent."
```

- [ ] **Step 5: Run probe tests**

```bash
uv run pytest tests/test_probes/test_asi02.py tests/test_probes/test_asi04.py -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/agentsec/probes/asi02_tool_misuse/ src/agentsec/probes/asi04_supply_chain/
git commit -m "$(cat <<'EOF'
ENH: use _select_tool_agent in ASI02/04 probes, skip if no tools

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update mixed probes (ASI05, ASI10-COVERT-EXFIL) — prefer tool, fall to entry

**Files:** `code_injection.py`, `sandbox_escape.py`, `covert_exfil.py`

Pattern — prefer tool agent but fall through to entry point if none:

```python
target = self._select_tool_agent(agents) or self._select_entry_point(agents)
if target is None:
    return self._no_target_finding("No agents discovered.")
target_agent = target.name
```

- [ ] **Step 1: Update `asi05_code_execution/code_injection.py`**

Replace `agents[0]` target selection with:
```python
target = self._select_tool_agent(agents) or self._select_entry_point(agents)
if target is None:
    return self._no_target_finding("No agents discovered.")
target_agent = target.name
```

- [ ] **Step 2: Update `asi05_code_execution/sandbox_escape.py`** — same pattern.

- [ ] **Step 3: Update `asi10_rogue_agent/covert_exfil.py`** — same pattern.

- [ ] **Step 4: Run probe tests**

```bash
uv run pytest tests/test_probes/test_asi05.py tests/test_probes/test_asi10.py -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/agentsec/probes/asi05_code_execution/ src/agentsec/probes/asi10_rogue_agent/covert_exfil.py
git commit -m "$(cat <<'EOF'
ENH: use _select_tool_agent (fall to entry_point) in ASI05 and ASI10-COVERT-EXFIL

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Update ASI07 — `_select_worker` and `_select_orchestrator`

**Files:** `msg_tamper.py`, `orchestrator_hijack.py`

### `msg_tamper.py` — target a worker (non-entry-point node)

```python
agents = await adapter.discover()
target = self._select_worker(agents)
if target is None:
    return self._no_target_finding(
        "Message tampering requires at least two agents (one entry point and one worker). "
        f"Found {len(agents)} agent(s), all are entry points."
    )
target_agent = target.name
```

Remove the old `agents[1]` and `len(agents) < 2` guard (replaced by `_select_worker` returning None when all agents are entry points).

### `orchestrator_hijack.py` — target the orchestrator

```python
agents = await adapter.discover()
target = self._select_orchestrator(agents)
if target is None:
    return self._no_target_finding(
        "No orchestrator detected — this probe requires a node with conditional "
        "outbound routing (LLM-driven or deterministic). "
        f"Found {len(agents)} agent(s), none with conditional edges."
    )
target_agent = target.name
```

Remove the old `len(agents) < 2` guard and `agents[0]` selection.

Also update `_generate_payloads` in `orchestrator_hijack.py` — the `supervisor_name` variable should use the selected target, not `agents[0]`. Since `_generate_payloads` runs before `attack()` selects the target, pass the target name in:

```python
# In attack(), after selecting target:
payloads, gen_usage = await self._generate_payloads(
    provider, agents, target_agent=target_agent, fallback_model=fallback_model
)
```

And update `_generate_payloads` signature:
```python
async def _generate_payloads(
    self, provider=None, agents=None, target_agent: str = "supervisor", fallback_model=None
) -> tuple[list[str], list[LLMUsage]]:
    ...
    prompt = (
        f"Agent list: {', '.join(agent_list)}\n"
        f"Role list: {', '.join(role_list)}\n"
        f"Supervisor: {target_agent}\n"    # ← was agents[0].name
        f"Marker to inject: {_ORCHJACK_MARKER}\n"
    )
```

- [ ] **Step 1: Update `asi07_inter_agent/msg_tamper.py`**

Replace the `len(agents) < 2` guard and all `agents[0]` / `agents[1]` target references with `_select_worker` pattern above.

- [ ] **Step 2: Update `asi07_inter_agent/orchestrator_hijack.py`**

Replace the `len(agents) < 2` guard and `agents[0]` target with `_select_orchestrator` pattern above. Update `_generate_payloads` signature and call site as described.

- [ ] **Step 3: Run probe tests**

```bash
uv run pytest tests/test_probes/test_asi07.py -v
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add src/agentsec/probes/asi07_inter_agent/
git commit -m "$(cat <<'EOF'
ENH: use _select_worker and _select_orchestrator in ASI07 probes

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Final verification

- [ ] **Step 1: Run full lint**

```bash
uv run ruff check src/ tests/
```

Expected: no errors.

- [ ] **Step 2: Apply formatting**

```bash
uv run ruff format src/ tests/
```

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest -v 2>&1 | tail -5
```

Expected: 1000+ tests passing, 0 failures.

- [ ] **Step 4: Verify probe count still 20**

```bash
uv run python -c "
from agentsec.probes.registry import ProbeRegistry
r = ProbeRegistry(); r.discover()
print(f'Probes: {len(r.probes)}')
"
```

Expected: `Probes: 20`.

- [ ] **Step 5: Verify targeting on email_automation_harness (the original bug)**

```bash
uv run python -c "
import asyncio
from agentsec.core.scanner import Scanner
from agentsec.core.config import ScanConfig
from agentsec.adapters.langgraph import LangGraphAdapter
import sys; sys.path.insert(0, 'tests')
from targets.email_automation_harness import build_email_automation_target

async def main():
    graph = build_email_automation_target(vulnerable=True)
    adapter = LangGraphAdapter(graph=graph)
    scanner = Scanner(adapter=adapter, config=ScanConfig())
    result = await scanner.run()
    for f in sorted(result.findings, key=lambda x: x.probe_id):
        print(f'  [{f.severity.upper():8s}] {f.probe_id:35s} target={f.evidence.target_agent if f.evidence else \"N/A\":20s} status={f.status}')

asyncio.run(main())
" 2>/dev/null
```

Expected: tool probes (ASI02, ASI04) target an agent with tools or skip cleanly; entry-point probes target `classify`; ASI07-ORCHESTRATOR-HIJACK skips cleanly (no LLM-driven router in this graph).

- [ ] **Step 6: Commit any ruff-format changes**

```bash
git add -u
git diff --cached --quiet || git commit -m "$(cat <<'EOF'
MAINT: apply ruff format after agent targeting refactor

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```
