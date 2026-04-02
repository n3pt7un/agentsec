# Session 05: RAG Harnesses, Showcase Reports & scan_real_world — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three RAG-oriented target harnesses, fix a CLI output bug, update the live scan script, and add `examples/scan_real_world.py`.

**Architecture:** Each harness follows the existing `build_<name>_target(*, vulnerable, live, target_model)` contract. A deterministic `retrieve` node writes `documents: list[str]` into typed state; downstream LLM nodes read from it. Vulnerable harnesses use `EchoModel`; resistant ones use `FakeListChatModel` with canned responses that contain no probe markers.

**Tech Stack:** LangGraph (base only — no `langgraph_supervisor`/`langgraph_swarm`), `langchain-core`, `pytest`, `pytest-asyncio`, `uv`.

---

## File Map

| Action | Path | Responsibility |
|--------|------|---------------|
| Modify | `src/agentsec/cli/main.py:109-115` | Fix `_write_output` to create parent dirs |
| Modify | `tests/test_cli/test_main.py` | Add test for `_write_output` mkdir behaviour |
| Create | `tests/targets/email_automation_harness.py` | 5-node email pipeline harness |
| Create | `tests/targets/rag_research_harness.py` | 3-node research RAG harness |
| Create | `tests/targets/multi_agentic_rag_harness.py` | 5-node hallucination-check harness |
| Modify | `tests/test_targets/test_harnesses.py` | Append tests for all 3 new harnesses |
| Create | `examples/scan_real_world.py` | Demo script scanning email harness, saves to `reports/` |
| Modify | `scripts/live_scan.sh` | Extend TARGETS array to all 6 harnesses |

---

## Task 1: Fix `_write_output` — create parent directories

**Files:**
- Modify: `src/agentsec/cli/main.py:109-115`
- Modify: `tests/test_cli/test_main.py`

- [ ] **Step 1: Write the failing test**

  Add to `tests/test_cli/test_main.py` inside the `TestScanCommand` class (or as a standalone function after the class):

  ```python
  def test_write_output_creates_missing_parent_directory(tmp_path):
      from agentsec.cli.main import _write_output

      output_file = tmp_path / "reports" / "subdir" / "test.md"
      assert not output_file.parent.exists()
      _write_output("# test content", str(output_file))
      assert output_file.exists()
      assert output_file.read_text() == "# test content"
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```bash
  uv run pytest tests/test_cli/test_main.py::test_write_output_creates_missing_parent_directory -v
  ```

  Expected: FAIL — `FileNotFoundError` because `reports/subdir/` doesn't exist.

- [ ] **Step 3: Fix `_write_output`**

  In `src/agentsec/cli/main.py`, replace lines 109–115:

  ```python
  def _write_output(content: str, output_path: str | None) -> None:
      """Write content to a file or stdout."""
      if output_path:
          p = Path(output_path)
          p.parent.mkdir(parents=True, exist_ok=True)
          p.write_text(content)
          console.print(f"[green]Report written to {output_path}[/]")
      else:
          console.print(content)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```bash
  uv run pytest tests/test_cli/test_main.py::test_write_output_creates_missing_parent_directory -v
  ```

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/agentsec/cli/main.py tests/test_cli/test_main.py
  git commit -m "BUG: create parent directories in _write_output before writing report"
  ```

---

## Task 2: Email automation harness

**Files:**
- Create: `tests/targets/email_automation_harness.py`
- Modify: `tests/test_targets/test_harnesses.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/test_targets/test_harnesses.py` (after the customer-support section):

  ```python
  # ---------------------------------------------------------------------------
  # Email automation harness (no importorskip — base LangGraph only)
  # ---------------------------------------------------------------------------


  def test_email_automation_compiles_vulnerable():
      from tests.targets.email_automation_harness import build_email_automation_target

      graph = build_email_automation_target(vulnerable=True)
      assert graph is not None


  def test_email_automation_compiles_resistant():
      from tests.targets.email_automation_harness import build_email_automation_target

      graph = build_email_automation_target(vulnerable=False)
      assert graph is not None


  @pytest.mark.asyncio
  async def test_email_automation_discovery():
      from tests.targets.email_automation_harness import build_email_automation_target

      adapter = LangGraphAdapter(build_email_automation_target(vulnerable=True))
      agents = await adapter.discover()
      names = {a.name for a in agents}
      assert {"classify", "retrieve", "draft", "quality_check", "send"} <= names


  @pytest.mark.asyncio
  async def test_email_automation_vulnerable_scan_produces_findings():
      from tests.targets.email_automation_harness import build_email_automation_target

      adapter = LangGraphAdapter(build_email_automation_target(vulnerable=True))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="email_automation_harness")
      assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  @pytest.mark.asyncio
  async def test_email_automation_resistant_scan_has_no_vulnerable():
      from tests.targets.email_automation_harness import build_email_automation_target

      adapter = LangGraphAdapter(build_email_automation_target(vulnerable=False))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="email_automation_harness")
      assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  def test_email_automation_live_raises_without_api_key(monkeypatch):
      monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
      from tests.targets.email_automation_harness import build_email_automation_target

      with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
          build_email_automation_target(live=True)


  def test_email_automation_live_compiles_with_mocked_llm(monkeypatch):
      monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
      with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
          from tests.targets.email_automation_harness import build_email_automation_target

          graph = build_email_automation_target(live=True)
          assert graph is not None
          mock_cls.assert_called_once()
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "email_automation" -v
  ```

  Expected: FAIL — `ModuleNotFoundError: No module named 'tests.targets.email_automation_harness'`.

- [ ] **Step 3: Create the harness**

  Create `tests/targets/email_automation_harness.py`:

  ```python
  """Harness for the email automation architecture.

  Recreates a multi-node email pipeline:
      classify → retrieve → draft → quality_check → send

  A standalone retrieve node writes KB articles into state as
  ``documents: list[str]``. LLM nodes process messages downstream.

  Usage:
      uv run agentsec scan --adapter langgraph --target tests/targets/email_automation_harness.py
  """

  from __future__ import annotations

  from typing import Any

  from langchain_core.language_models import BaseChatModel, FakeListChatModel
  from langchain_core.messages import AIMessage
  from langchain_core.tools import tool
  from langgraph.graph import END, MessagesState, StateGraph
  from langgraph.graph.state import CompiledStateGraph

  from tests.fixtures.utils import EchoModel
  from tests.targets._openrouter_llm import get_live_llm


  # ---------------------------------------------------------------------------
  # State
  # ---------------------------------------------------------------------------


  class EmailState(MessagesState):
      """State for the email automation graph."""

      subject: str
      documents: list[str]
      draft: str
      quality_ok: bool


  # ---------------------------------------------------------------------------
  # Canned responses for resistant mode
  # ---------------------------------------------------------------------------

  _CLASSIFY_RESPONSES = ["Billing inquiry received. Routing to billing knowledge base."]
  _DRAFT_RESPONSES = ["Thank you for contacting support. We have processed your request."]
  _QUALITY_RESPONSES = ["The draft response is clear and directly addresses the inquiry."]

  _KB_ARTICLES = [
      "KB001: For billing issues, verify the account and check recent transactions.",
      "KB002: Standard refund policy allows refunds within 30 days of purchase.",
      "KB003: Escalation procedure: if unresolved after 2 attempts, escalate to tier-2.",
  ]


  # ---------------------------------------------------------------------------
  # Stub tools
  # ---------------------------------------------------------------------------


  @tool
  def send_email(to: str, subject: str, body: str) -> str:
      """Send an email reply to a customer."""
      return f"Email sent to {to} with subject '{subject}'."


  # ---------------------------------------------------------------------------
  # Builder
  # ---------------------------------------------------------------------------


  def build_email_automation_target(
      *,
      vulnerable: bool = True,
      live: bool = False,
      target_model: str | None = None,
  ) -> CompiledStateGraph:
      """Build an email automation graph with classify/retrieve/draft/quality_check/send.

      Args:
          vulnerable: When live=False, controls whether EchoModel (True)
              or FakeListChatModel (False) is used. Ignored when live=True.
          live: Use a real LLM via OpenRouter. Requires OPENROUTER_API_KEY.
          target_model: OpenRouter model ID for live mode. Defaults to env var
              AGENTSEC_TARGET_MODEL or "openai/gpt-4.1-nano".

      Returns:
          A compiled LangGraph StateGraph.
      """
      if live:
          shared: BaseChatModel = get_live_llm(model=target_model)
          classify_llm: BaseChatModel = shared
          draft_llm: BaseChatModel = shared
          quality_llm: BaseChatModel = shared
      elif vulnerable:
          classify_llm = EchoModel()
          draft_llm = EchoModel()
          quality_llm = EchoModel()
      else:
          classify_llm = FakeListChatModel(responses=_CLASSIFY_RESPONSES)
          draft_llm = FakeListChatModel(responses=_DRAFT_RESPONSES)
          quality_llm = FakeListChatModel(responses=_QUALITY_RESPONSES)

      def classify(state: EmailState) -> dict[str, Any]:
          """Classify incoming email and extract subject for routing."""
          response = classify_llm.invoke(state["messages"])
          return {"messages": [response], "subject": "Customer Inquiry"}

      def retrieve(state: EmailState) -> dict[str, Any]:
          """Retrieve relevant KB articles for the classified email category."""
          return {"documents": _KB_ARTICLES}

      def draft(state: EmailState) -> dict[str, Any]:
          """Draft a reply using retrieved KB documents and conversation context."""
          response = draft_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          return {"messages": [response], "draft": content}

      def quality_check(state: EmailState) -> dict[str, Any]:
          """Check whether the draft reply meets quality standards."""
          response = quality_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          ok = "reject" not in content.lower()
          return {"messages": [response], "quality_ok": ok}

      def send(state: EmailState) -> dict[str, Any]:
          """Send the approved draft reply to the customer."""
          subject = state.get("subject") or "Re: Your inquiry"
          body = state.get("draft") or ""
          result = f"Email sent to customer@example.com with subject '{subject}'."
          return {"messages": [AIMessage(content=result)]}

      send.tools = [send_email]  # type: ignore[attr-defined]

      def route_quality(state: EmailState) -> str:
          """Route to send if quality passes, otherwise back to draft."""
          return "send" if state.get("quality_ok", False) else "draft"

      graph = StateGraph(EmailState)
      graph.add_node("classify", classify)
      graph.add_node("retrieve", retrieve)
      graph.add_node("draft", draft)
      graph.add_node("quality_check", quality_check)
      graph.add_node("send", send)

      graph.set_entry_point("classify")
      graph.add_edge("classify", "retrieve")
      graph.add_edge("retrieve", "draft")
      graph.add_edge("draft", "quality_check")
      graph.add_conditional_edges(
          "quality_check",
          route_quality,
          {"send": "send", "draft": "draft"},
      )
      graph.add_edge("send", END)

      return graph.compile()
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "email_automation" -v
  ```

  Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/targets/email_automation_harness.py tests/test_targets/test_harnesses.py
  git commit -m "FEAT: add email automation RAG harness with classify/retrieve/draft pipeline"
  ```

---

## Task 3: RAG research harness

**Files:**
- Create: `tests/targets/rag_research_harness.py`
- Modify: `tests/test_targets/test_harnesses.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/test_targets/test_harnesses.py` (after the email automation section):

  ```python
  # ---------------------------------------------------------------------------
  # RAG research harness (no importorskip — base LangGraph only)
  # ---------------------------------------------------------------------------


  def test_rag_research_compiles_vulnerable():
      from tests.targets.rag_research_harness import build_rag_research_target

      graph = build_rag_research_target(vulnerable=True)
      assert graph is not None


  def test_rag_research_compiles_resistant():
      from tests.targets.rag_research_harness import build_rag_research_target

      graph = build_rag_research_target(vulnerable=False)
      assert graph is not None


  @pytest.mark.asyncio
  async def test_rag_research_discovery():
      from tests.targets.rag_research_harness import build_rag_research_target

      adapter = LangGraphAdapter(build_rag_research_target(vulnerable=True))
      agents = await adapter.discover()
      names = {a.name for a in agents}
      assert {"plan", "retrieve", "synthesize"} <= names


  @pytest.mark.asyncio
  async def test_rag_research_vulnerable_scan_produces_findings():
      from tests.targets.rag_research_harness import build_rag_research_target

      adapter = LangGraphAdapter(build_rag_research_target(vulnerable=True))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="rag_research_harness")
      assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  @pytest.mark.asyncio
  async def test_rag_research_resistant_scan_has_no_vulnerable():
      from tests.targets.rag_research_harness import build_rag_research_target

      adapter = LangGraphAdapter(build_rag_research_target(vulnerable=False))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="rag_research_harness")
      assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  def test_rag_research_live_raises_without_api_key(monkeypatch):
      monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
      from tests.targets.rag_research_harness import build_rag_research_target

      with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
          build_rag_research_target(live=True)


  def test_rag_research_live_compiles_with_mocked_llm(monkeypatch):
      monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
      with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
          from tests.targets.rag_research_harness import build_rag_research_target

          graph = build_rag_research_target(live=True)
          assert graph is not None
          mock_cls.assert_called_once()
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "rag_research" -v
  ```

  Expected: FAIL — `ModuleNotFoundError: No module named 'tests.targets.rag_research_harness'`.

- [ ] **Step 3: Create the harness**

  Create `tests/targets/rag_research_harness.py`:

  ```python
  """Harness for the RAG research agent architecture.

  Recreates a minimal research pipeline:
      plan → retrieve → synthesize

  A standalone retrieve node writes research sources into state as
  ``documents: list[str]``. The synthesize node produces a report.

  Usage:
      uv run agentsec scan --adapter langgraph --target tests/targets/rag_research_harness.py
  """

  from __future__ import annotations

  from typing import Any

  from langchain_core.language_models import BaseChatModel, FakeListChatModel
  from langgraph.graph import END, MessagesState, StateGraph
  from langgraph.graph.state import CompiledStateGraph

  from tests.fixtures.utils import EchoModel
  from tests.targets._openrouter_llm import get_live_llm


  # ---------------------------------------------------------------------------
  # State
  # ---------------------------------------------------------------------------


  class ResearchState(MessagesState):
      """State for the RAG research graph."""

      query: str
      documents: list[str]
      report: str


  # ---------------------------------------------------------------------------
  # Canned responses for resistant mode
  # ---------------------------------------------------------------------------

  _PLAN_RESPONSES = ["Structured search query: recent advances in renewable energy storage."]
  _SYNTHESIZE_RESPONSES = [
      "Based on the retrieved sources, renewable energy storage has seen significant "
      "improvements in battery density and grid integration over the past decade."
  ]

  _RESEARCH_SOURCES = [
      "Source 1 (2024): Lithium-ion battery energy density reached 350 Wh/kg in lab conditions.",
      "Source 2 (2024): Grid-scale storage deployments increased 40% year-over-year.",
      "Source 3 (2023): Solid-state batteries show promise for 2x capacity improvement by 2027.",
  ]


  # ---------------------------------------------------------------------------
  # Builder
  # ---------------------------------------------------------------------------


  def build_rag_research_target(
      *,
      vulnerable: bool = True,
      live: bool = False,
      target_model: str | None = None,
  ) -> CompiledStateGraph:
      """Build a research RAG graph with plan/retrieve/synthesize nodes.

      Args:
          vulnerable: When live=False, controls whether EchoModel (True)
              or FakeListChatModel (False) is used. Ignored when live=True.
          live: Use a real LLM via OpenRouter. Requires OPENROUTER_API_KEY.
          target_model: OpenRouter model ID for live mode. Defaults to env var
              AGENTSEC_TARGET_MODEL or "openai/gpt-4.1-nano".

      Returns:
          A compiled LangGraph StateGraph.
      """
      if live:
          shared: BaseChatModel = get_live_llm(model=target_model)
          plan_llm: BaseChatModel = shared
          synthesize_llm: BaseChatModel = shared
      elif vulnerable:
          plan_llm = EchoModel()
          synthesize_llm = EchoModel()
      else:
          plan_llm = FakeListChatModel(responses=_PLAN_RESPONSES)
          synthesize_llm = FakeListChatModel(responses=_SYNTHESIZE_RESPONSES)

      def plan(state: ResearchState) -> dict[str, Any]:
          """Rewrite the user request into a structured search query."""
          response = plan_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          return {"messages": [response], "query": content}

      def retrieve(state: ResearchState) -> dict[str, Any]:
          """Retrieve relevant research sources for the structured query."""
          return {"documents": _RESEARCH_SOURCES}

      def synthesize(state: ResearchState) -> dict[str, Any]:
          """Synthesize a research report from the retrieved documents."""
          response = synthesize_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          return {"messages": [response], "report": content}

      graph = StateGraph(ResearchState)
      graph.add_node("plan", plan)
      graph.add_node("retrieve", retrieve)
      graph.add_node("synthesize", synthesize)

      graph.set_entry_point("plan")
      graph.add_edge("plan", "retrieve")
      graph.add_edge("retrieve", "synthesize")
      graph.add_edge("synthesize", END)

      return graph.compile()
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "rag_research" -v
  ```

  Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/targets/rag_research_harness.py tests/test_targets/test_harnesses.py
  git commit -m "FEAT: add RAG research harness with plan/retrieve/synthesize pipeline"
  ```

---

## Task 4: Multi-agentic RAG harness

**Files:**
- Create: `tests/targets/multi_agentic_rag_harness.py`
- Modify: `tests/test_targets/test_harnesses.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/test_targets/test_harnesses.py` (after the rag_research section):

  ```python
  # ---------------------------------------------------------------------------
  # Multi-agentic RAG harness (no importorskip — base LangGraph only)
  # ---------------------------------------------------------------------------


  def test_multi_agentic_rag_compiles_vulnerable():
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      graph = build_multi_agentic_rag_target(vulnerable=True)
      assert graph is not None


  def test_multi_agentic_rag_compiles_resistant():
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      graph = build_multi_agentic_rag_target(vulnerable=False)
      assert graph is not None


  @pytest.mark.asyncio
  async def test_multi_agentic_rag_discovery():
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      adapter = LangGraphAdapter(build_multi_agentic_rag_target(vulnerable=True))
      agents = await adapter.discover()
      names = {a.name for a in agents}
      assert {"retrieve", "generate", "hallucination_check", "correct", "output"} <= names


  @pytest.mark.asyncio
  async def test_multi_agentic_rag_vulnerable_scan_produces_findings():
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      adapter = LangGraphAdapter(build_multi_agentic_rag_target(vulnerable=True))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="multi_agentic_rag_harness")
      assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  @pytest.mark.asyncio
  async def test_multi_agentic_rag_resistant_scan_has_no_vulnerable():
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      adapter = LangGraphAdapter(build_multi_agentic_rag_target(vulnerable=False))
      scanner = Scanner(adapter, ScanConfig())
      result = await scanner.run(target="multi_agentic_rag_harness")
      assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)


  def test_multi_agentic_rag_live_raises_without_api_key(monkeypatch):
      monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
      from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

      with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
          build_multi_agentic_rag_target(live=True)


  def test_multi_agentic_rag_live_compiles_with_mocked_llm(monkeypatch):
      monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
      with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
          from tests.targets.multi_agentic_rag_harness import build_multi_agentic_rag_target

          graph = build_multi_agentic_rag_target(live=True)
          assert graph is not None
          mock_cls.assert_called_once()
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "multi_agentic_rag" -v
  ```

  Expected: FAIL — `ModuleNotFoundError: No module named 'tests.targets.multi_agentic_rag_harness'`.

- [ ] **Step 3: Create the harness**

  Create `tests/targets/multi_agentic_rag_harness.py`:

  ```python
  """Harness for the multi-agentic RAG architecture with hallucination checking.

  Recreates a RAG pipeline with error-correction loop:
      retrieve → generate → hallucination_check → (correct → generate | output)

  The loop guard is enforced in the Python routing function via a
  ``correction_attempts`` counter in state (max 1 retry). The hallucination
  check is an LLM node that returns "yes" or "no"; the routing decision is
  made entirely by Python, not by prompting.

  Usage:
      uv run agentsec scan --adapter langgraph --target tests/targets/multi_agentic_rag_harness.py
  """

  from __future__ import annotations

  from typing import Any

  from langchain_core.language_models import BaseChatModel, FakeListChatModel
  from langchain_core.messages import AIMessage
  from langgraph.graph import END, MessagesState, StateGraph
  from langgraph.graph.state import CompiledStateGraph

  from tests.fixtures.utils import EchoModel
  from tests.targets._openrouter_llm import get_live_llm


  # ---------------------------------------------------------------------------
  # State
  # ---------------------------------------------------------------------------


  class RAGState(MessagesState):
      """State for the multi-agentic RAG graph."""

      query: str
      documents: list[str]
      answer: str
      hallucination_score: str  # "yes" | "no"
      correction_attempts: int  # loop guard; max 1


  # ---------------------------------------------------------------------------
  # Canned responses for resistant mode
  # ---------------------------------------------------------------------------

  _GENERATE_RESPONSES = [
      "Based on the retrieved documents, the answer is: renewable energy storage capacity "
      "has increased significantly due to advances in lithium-ion technology."
  ]
  _HALLUCINATION_RESPONSES = ["No hallucination detected. The answer is grounded in the sources."]
  _CORRECT_RESPONSES = [
      "Corrected answer: renewable energy storage improvements are well-documented "
      "in recent literature."
  ]

  _KB_ARTICLES = [
      "Article 1: Battery storage capacity improved 35% between 2020 and 2024.",
      "Article 2: Grid-scale deployments now cover 15% of peak demand in target regions.",
      "Article 3: Thermal energy storage is emerging as a complement to electrochemical storage.",
  ]


  # ---------------------------------------------------------------------------
  # Builder
  # ---------------------------------------------------------------------------


  def build_multi_agentic_rag_target(
      *,
      vulnerable: bool = True,
      live: bool = False,
      target_model: str | None = None,
  ) -> CompiledStateGraph:
      """Build a multi-agentic RAG graph with hallucination checking and correction loop.

      Args:
          vulnerable: When live=False, controls whether EchoModel (True)
              or FakeListChatModel (False) is used. Ignored when live=True.
          live: Use a real LLM via OpenRouter. Requires OPENROUTER_API_KEY.
          target_model: OpenRouter model ID for live mode. Defaults to env var
              AGENTSEC_TARGET_MODEL or "openai/gpt-4.1-nano".

      Returns:
          A compiled LangGraph StateGraph.
      """
      if live:
          shared: BaseChatModel = get_live_llm(model=target_model)
          generate_llm: BaseChatModel = shared
          hallucination_llm: BaseChatModel = shared
          correct_llm: BaseChatModel = shared
      elif vulnerable:
          generate_llm = EchoModel()
          hallucination_llm = EchoModel()
          correct_llm = EchoModel()
      else:
          generate_llm = FakeListChatModel(responses=_GENERATE_RESPONSES)
          hallucination_llm = FakeListChatModel(responses=_HALLUCINATION_RESPONSES)
          correct_llm = FakeListChatModel(responses=_CORRECT_RESPONSES)

      def retrieve(state: RAGState) -> dict[str, Any]:
          """Retrieve relevant KB articles for the user query."""
          content = state["messages"][-1].content if state["messages"] else ""
          query = content if isinstance(content, str) else str(content)
          return {"documents": _KB_ARTICLES, "query": query}

      def generate(state: RAGState) -> dict[str, Any]:
          """Generate an answer from the retrieved documents."""
          response = generate_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          return {"messages": [response], "answer": content}

      def hallucination_check(state: RAGState) -> dict[str, Any]:
          """Check whether the generated answer is grounded in the retrieved documents."""
          response = hallucination_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          score = "yes" if content.strip().lower().startswith("yes") else "no"
          return {"messages": [response], "hallucination_score": score}

      def correct(state: RAGState) -> dict[str, Any]:
          """Attempt to correct a hallucinated answer using the source documents."""
          response = correct_llm.invoke(state["messages"])
          content = response.content if isinstance(response.content, str) else str(response.content)
          attempts = state.get("correction_attempts") or 0
          return {"messages": [response], "answer": content, "correction_attempts": attempts + 1}

      def output(state: RAGState) -> dict[str, Any]:
          """Emit the final answer as the terminal message."""
          answer = state.get("answer") or ""
          return {"messages": [AIMessage(content=answer)]}

      def route_hallucination(state: RAGState) -> str:
          """Route to correction if hallucination detected (max 1 attempt), else output.

          The loop guard is enforced here in Python — NOT in any LLM prompt.
          """
          attempts = state.get("correction_attempts") or 0
          if state.get("hallucination_score", "no") == "yes" and attempts < 1:
              return "correct"
          return "output"

      graph = StateGraph(RAGState)
      graph.add_node("retrieve", retrieve)
      graph.add_node("generate", generate)
      graph.add_node("hallucination_check", hallucination_check)
      graph.add_node("correct", correct)
      graph.add_node("output", output)

      graph.set_entry_point("retrieve")
      graph.add_edge("retrieve", "generate")
      graph.add_edge("generate", "hallucination_check")
      graph.add_conditional_edges(
          "hallucination_check",
          route_hallucination,
          {"correct": "correct", "output": "output"},
      )
      graph.add_edge("correct", "generate")
      graph.add_edge("output", END)

      return graph.compile()
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```bash
  uv run pytest tests/test_targets/test_harnesses.py -k "multi_agentic_rag" -v
  ```

  Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/targets/multi_agentic_rag_harness.py tests/test_targets/test_harnesses.py
  git commit -m "FEAT: add multi-agentic RAG harness with hallucination check and correction loop"
  ```

---

## Task 5: `examples/scan_real_world.py`

**Files:**
- Create: `examples/scan_real_world.py`

- [ ] **Step 1: Create the script**

  Create `examples/scan_real_world.py`:

  ```python
  #!/usr/bin/env python3
  """Scan a real-world LangGraph pipeline and save the report.

  Builds the email automation harness (classify → retrieve → draft →
  quality_check → send) and runs all agentsec probes against it.
  Report is written to reports/email_automation.md and also printed to stdout.

  No API keys required — the harness uses a deterministic echo model.
  No optional dependencies required — base LangGraph only (uv sync is enough).

  Usage:
      uv run python examples/scan_real_world.py
  """

  from __future__ import annotations

  import asyncio
  from pathlib import Path

  from agentsec.adapters.langgraph import LangGraphAdapter
  from agentsec.core.config import ScanConfig
  from agentsec.core.scanner import Scanner
  from agentsec.reporters.markdown import generate_markdown
  from tests.targets.email_automation_harness import build_email_automation_target


  async def main() -> None:
      """Run the scan and save the report."""
      graph = build_email_automation_target(vulnerable=True)
      adapter = LangGraphAdapter(graph)
      config = ScanConfig()

      scanner = Scanner(adapter, config)
      result = await scanner.run(target="email_automation_harness")

      report = generate_markdown(result)

      out = Path("reports/email_automation.md")
      out.parent.mkdir(parents=True, exist_ok=True)
      out.write_text(report)

      print(report)
      print(f"\nReport saved to {out}")


  if __name__ == "__main__":
      asyncio.run(main())
  ```

- [ ] **Step 2: Run it to verify it works**

  ```bash
  uv run python examples/scan_real_world.py
  ```

  Expected: markdown report printed to stdout, `reports/email_automation.md` created.
  The report should show findings with `VULNERABLE` status (EchoModel echoes all probe markers).

- [ ] **Step 3: Commit**

  ```bash
  git add examples/scan_real_world.py reports/email_automation.md
  git commit -m "FEAT: add scan_real_world.py example scanning email automation harness"
  ```

---

## Task 6: Update `live_scan.sh`

**Files:**
- Modify: `scripts/live_scan.sh:25-30`

- [ ] **Step 1: Extend TARGETS array**

  In `scripts/live_scan.sh`, replace the `TARGETS` array:

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

- [ ] **Step 2: Verify the script is syntactically valid**

  ```bash
  bash -n scripts/live_scan.sh
  ```

  Expected: no output (no syntax errors).

- [ ] **Step 3: Commit**

  ```bash
  git add scripts/live_scan.sh
  git commit -m "MAINT: extend live_scan.sh to cover all 6 harnesses"
  ```

---

## Task 7: Full test suite

- [ ] **Step 1: Run the full suite**

  ```bash
  uv run pytest -x -v
  ```

  Expected: all tests PASS. If any fail, diagnose from the error output before changing code.

- [ ] **Step 2: Run lint**

  ```bash
  uv run ruff check src/ tests/ examples/
  ```

  Expected: no errors. Fix any reported issues before moving on.

- [ ] **Step 3: Commit lint fixes if needed**

  Only if Step 2 reported issues:

  ```bash
  git add -p   # stage only lint fixes
  git commit -m "MAINT: fix ruff lint issues in session 05 additions"
  ```
