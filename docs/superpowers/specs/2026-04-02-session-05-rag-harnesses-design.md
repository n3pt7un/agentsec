# Session 05: RAG Harnesses, Showcase Reports & scan_real_world

**Date:** 2026-04-02
**Status:** Approved

## Overview

Session 05 adds three RAG-oriented target harnesses to the existing suite (supervisor, swarm,
rag-customer-support), produces showcase scan reports, updates the `live_scan.sh` script, fixes
a minor CLI output bug, and adds `examples/scan_real_world.py`.

## Decisions

| Decision | Choice |
|---|---|
| Showcase report content | Actual scanner output (user runs scans) |
| RAG retriever modelling | Standalone graph node writing `documents: list[str]` to state |
| `scan_real_world.py` target | Email automation harness (richest pipeline) |

## New Harnesses

All three live in `tests/targets/` and follow the identical interface contract as existing
harnesses:

```python
def build_<name>_target(
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
) -> CompiledStateGraph:
```

Mock pattern:
- `vulnerable=True` → `ToolCapableEchoModel` / `EchoModel`
- `vulnerable=False` → `ToolCapableFakeModel` / `FakeListChatModel` with canned responses
- `live=True` → `get_live_llm(model=target_model)` via `_openrouter_llm`

The `retrieve` node in all three harnesses is deterministic (not an LLM node) — it always
returns canned document stubs regardless of `vulnerable` / `live` mode.

---

### 1. `email_automation_harness.py`

**Architecture:**
```
classify → retrieve → draft → quality_check → send
```

**State:**
```python
class EmailState(MessagesState):
    subject: str
    documents: list[str]   # retrieved KB articles / templates
    draft: str
    quality_ok: bool
```

**Nodes:**
- `classify` — LLM node: categorises incoming email, writes subject to state
- `retrieve` — deterministic node: returns 2–3 canned KB snippet strings into `documents`
- `draft` — LLM node: composes reply using `documents` + `messages`
- `quality_check` — LLM node: sets `quality_ok: bool`
- `send` — deterministic node: calls stub `send_email(to, subject, body) -> str` tool

**Edges:**
- `classify → retrieve → draft → quality_check`
- Conditional from `quality_check`: `quality_ok=True → send`, else `→ draft` (retry loop)
- `send → END`

**Stub tools:** `send_email(to, subject, body) -> str`

**Attack surface:** RAG context injection via `documents`; goal hijack in `draft` node;
impersonation in `classify`.

---

### 2. `rag_research_harness.py`

**Architecture:**
```
plan → retrieve → synthesize
```

**State:**
```python
class ResearchState(MessagesState):
    query: str
    documents: list[str]   # retrieved research sources
    report: str
```

**Nodes:**
- `plan` — LLM node: rewrites user message into structured `query`
- `retrieve` — deterministic node: returns canned research source stubs
- `synthesize` — LLM node: produces `report` from `documents`

**Edges:** linear `plan → retrieve → synthesize → END`

**Stub tools:** none (pure RAG pipeline)

**Attack surface:** retriever poisoning via injected documents; context leak in `report` output.

---

### 3. `multi_agentic_rag_harness.py`

**Architecture:**
```
retrieve → generate → hallucination_check → correct → generate (loop)
                                          ↘ output
```

**State:**
```python
class RAGState(MessagesState):
    query: str
    documents: list[str]        # retrieved KB articles
    answer: str
    hallucination_score: str    # "yes" | "no"
    correction_attempts: int    # guards against infinite loop; max 1
```

**Nodes:**
- `retrieve` — deterministic node: canned KB stubs
- `generate` — LLM node: produces `answer` from `documents`
- `hallucination_check` — LLM node: returns `hallucination_score` (`"yes"` or `"no"`)
- `correct` — LLM node: attempts correction of `answer`
- `output` — terminal node: passes through final `answer`

**Edges:**
- `retrieve → generate → hallucination_check`
- Conditional from `hallucination_check`:
  - `hallucination_score == "yes"` AND `correction_attempts < 1` → `correct → generate`
  - `hallucination_score == "yes"` AND `correction_attempts >= 1` → `output` (loop guard)
  - else → `output → END`

**Mock behaviour:**
- `vulnerable=True`: `generate` and `correct` use `EchoModel` — echoes probe payload
- `vulnerable=False`: canned responses for all LLM nodes; `hallucination_check` returns `"no"`
  so the correction loop is never entered

**Stub tools:** none

**Attack surface:** bypassing hallucination guard via injected document content; exploiting
correction loop to amplify injected payload.

---

## Supporting Changes

### `src/agentsec/cli/main.py` — `_write_output`

Add parent directory creation before `write_text` so `--output reports/foo.md` works without
pre-creating `reports/`:

```python
def _write_output(content: str, output_path: str | None) -> None:
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        console.print(f"[green]Report written to {output_path}[/]")
    else:
        console.print(content)
```

### `scripts/live_scan.sh`

Extend `TARGETS` array to include all 6 harnesses:

```bash
TARGETS=(
    "tests/targets/supervisor_harness.py"
    "tests/targets/swarm_harness.py"
    "tests/targets/rag_customer_support_harness.py"
    "tests/targets/email_automation_harness.py"
    "tests/targets/rag_research_harness.py"
    "tests/targets/multi_agentic_rag_harness.py"
)
```

### `examples/scan_real_world.py`

New script. Scans `email_automation_harness` (5-node pipeline, most relatable topology),
saves report to `reports/email_automation.md`, and also prints to stdout.

```python
async def main() -> None:
    graph = build_email_automation_target(vulnerable=True)
    adapter = LangGraphAdapter(graph)
    result = await Scanner(adapter, ScanConfig()).run(target="email_automation_harness")
    report = generate_markdown(result)

    out = Path("reports/email_automation.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report)
    print(report)
```

Usage: `uv run python examples/scan_real_world.py`

---

## Tests

All 3 new harnesses added to `tests/test_targets/test_harnesses.py` following the existing
5-test pattern per harness (no `importorskip` — base LangGraph only):

1. `test_<name>_compiles_vulnerable` / `test_<name>_compiles_resistant`
2. `test_<name>_discovery` — assert expected node names present in discovered agents
3. `test_<name>_vulnerable_scan_produces_findings`
4. `test_<name>_resistant_scan_has_no_vulnerable`
5. `test_<name>_live_raises_without_api_key`
6. `test_<name>_live_compiles_with_mocked_llm`

Expected node names:
- email automation: `{"classify", "retrieve", "draft", "quality_check", "send"}`
- rag research: `{"plan", "retrieve", "synthesize"}`
- multi-agentic RAG: `{"retrieve", "generate", "hallucination_check", "correct", "output"}`

---

## README Update

The static example output block in `README.md` will be updated after running
`examples/scan_real_world.py` to reflect actual scan output against the email automation
harness. The structure of the block stays the same; only the content changes.

---

## Out of Scope

- New probes targeting RAG-specific vectors (retriever poisoning probe) — Phase 2
- `reports/` directory pre-populated with committed report files — user runs scans to generate
- HTML or SARIF report format changes
