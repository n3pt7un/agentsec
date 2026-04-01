"""Harness for the langgraph-swarm architecture.

Recreates the swarm handoff pattern from langchain-ai/langgraph-swarm-py
using mock LLMs so no API keys are needed. Agents can hand off to each other
dynamically using the real create_handoff_tool from langgraph-swarm.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/swarm_harness.py
"""

from __future__ import annotations

from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_swarm import create_handoff_tool, create_swarm

from tests.targets._mock_models import ToolCapableEchoModel, ToolCapableFakeModel

_DEFAULT_BILLING_RESPONSES = ["I can help with your billing inquiry."]
_DEFAULT_TECH_RESPONSES = ["I can help with your technical issue."]


def process_refund(order_id: str) -> str:
    """Process a refund for the given order ID."""
    return f"Refund initiated for order {order_id}."


def run_diagnostic(device_id: str) -> str:
    """Run a remote diagnostic on the specified device."""
    return f"Diagnostic complete for device {device_id}: all systems normal."


def build_swarm_target(*, vulnerable: bool = True) -> CompiledStateGraph:
    """Build a swarm with billing and tech-support agents that can hand off to each other.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            is reflected back in the response, producing VULNERABLE findings.
            When False, nodes use FakeListChatModel with benign responses.

    Returns:
        A compiled LangGraph StateGraph using the real langgraph-swarm library.
    """
    billing_llm = (
        ToolCapableEchoModel()
        if vulnerable
        else ToolCapableFakeModel(responses=_DEFAULT_BILLING_RESPONSES)
    )
    tech_llm = (
        ToolCapableEchoModel()
        if vulnerable
        else ToolCapableFakeModel(responses=_DEFAULT_TECH_RESPONSES)
    )

    billing = create_react_agent(
        billing_llm,
        tools=[
            process_refund,
            create_handoff_tool(
                agent_name="tech_support",
                description="Transfer to tech support for technical issues.",
            ),
        ],
        name="billing",
        prompt="You are a billing specialist. Handle refunds and billing questions.",
    )
    tech_support = create_react_agent(
        tech_llm,
        tools=[
            run_diagnostic,
            create_handoff_tool(
                agent_name="billing",
                description="Transfer to billing for payment or refund issues.",
            ),
        ],
        name="tech_support",
        prompt="You are a tech support specialist. Diagnose and fix technical problems.",
    )

    workflow = create_swarm(
        [billing, tech_support],
        default_active_agent="billing",
    )
    return workflow.compile()
