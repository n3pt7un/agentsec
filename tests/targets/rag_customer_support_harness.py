"""Harness for the multi-agent RAG customer support architecture.

Faithfully recreates the topology from ro-anderson/multi-agent-rag-customer-support
using mock LLMs and stub tools — no API keys or external services needed.

Architecture:
    primary_assistant routes to one of four specialist assistants
    (flight, car, hotel, excursion) based on the 'next' key in state.
    Each specialist handles domain bookings then routes back to primary
    or ends.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/rag_customer_support_harness.py
"""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.language_models import BaseChatModel, FakeListChatModel
from langchain_core.tools import tool
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel
from tests.targets._openrouter_llm import get_live_llm

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_Specialist = Literal[
    "flight_assistant",
    "car_assistant",
    "hotel_assistant",
    "excursion_assistant",
    "__end__",
]


class CustomerSupportState(MessagesState):
    """State for the customer support graph."""

    booking_context: dict[str, str]
    next: str  # routing target; nodes write this, router reads it via .get() for safety


# ---------------------------------------------------------------------------
# Default responses for resistant mode
# ---------------------------------------------------------------------------

_PRIMARY_RESPONSES = [
    "I'll connect you with the right specialist for your request.",
    "Let me route you to the appropriate assistant.",
    "I understand your request. Directing you to the right team.",
]
_FLIGHT_RESPONSES = ["I found 3 available flights matching your criteria."]
_CAR_RESPONSES = ["I found 2 available rental cars at your destination."]
_HOTEL_RESPONSES = ["I found 4 hotels available for your dates."]
_EXCURSION_RESPONSES = ["I found 5 exciting excursions at your destination."]


# ---------------------------------------------------------------------------
# Tool stubs — @tool-decorated so .name is set for LangGraphAdapter discovery
# ---------------------------------------------------------------------------


@tool
def search_flights(origin: str, destination: str, date: str) -> str:
    """Search for available flights between two cities on a given date."""
    return f"3 flights found from {origin} to {destination} on {date}."


@tool
def book_flight(flight_id: str, passenger_name: str) -> str:
    """Book a specific flight for a passenger."""
    return f"Flight {flight_id} booked for {passenger_name}. Confirmation: FL-001."


@tool
def search_cars(location: str, pickup_date: str) -> str:
    """Search for available rental cars at a location."""
    return f"2 rental cars available at {location} from {pickup_date}."


@tool
def reserve_car(car_id: str, driver_name: str) -> str:
    """Reserve a rental car for a driver."""
    return f"Car {car_id} reserved for {driver_name}. Confirmation: CR-001."


@tool
def search_hotels(location: str, checkin: str, checkout: str) -> str:
    """Search for available hotels at a location."""
    return f"4 hotels available in {location} from {checkin} to {checkout}."


@tool
def book_hotel(hotel_id: str, guest_name: str) -> str:
    """Book a hotel room for a guest."""
    return f"Hotel {hotel_id} booked for {guest_name}. Confirmation: HT-001."


@tool
def search_excursions(location: str, date: str) -> str:
    """Search for excursions and activities at a destination."""
    return f"5 excursions available in {location} on {date}."


@tool
def book_excursion(excursion_id: str, participant_name: str) -> str:
    """Book an excursion for a participant."""
    return f"Excursion {excursion_id} booked for {participant_name}. Confirmation: EX-001."


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_customer_support_target(
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
) -> CompiledStateGraph:
    """Build a 5-agent customer support graph with flight/car/hotel/excursion specialists.

    Faithfully recreates the topology from ro-anderson/multi-agent-rag-customer-support.

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
        shared_llm: BaseChatModel = get_live_llm(model=target_model)
        primary_llm: BaseChatModel = shared_llm
        flight_llm: BaseChatModel = shared_llm
        car_llm: BaseChatModel = shared_llm
        hotel_llm: BaseChatModel = shared_llm
        excursion_llm: BaseChatModel = shared_llm
    elif vulnerable:
        primary_llm = EchoModel()
        flight_llm = EchoModel()
        car_llm = EchoModel()
        hotel_llm = EchoModel()
        excursion_llm = EchoModel()
    else:
        primary_llm = FakeListChatModel(responses=_PRIMARY_RESPONSES)
        flight_llm = FakeListChatModel(responses=_FLIGHT_RESPONSES)
        car_llm = FakeListChatModel(responses=_CAR_RESPONSES)
        hotel_llm = FakeListChatModel(responses=_HOTEL_RESPONSES)
        excursion_llm = FakeListChatModel(responses=_EXCURSION_RESPONSES)

    def primary_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Primary assistant — routes user queries to the appropriate specialist."""
        response = primary_llm.invoke(state["messages"])
        return {
            "messages": [response],
            "next": "flight_assistant",
            "booking_context": dict(state.get("booking_context") or {}),
        }

    def flight_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Flight assistant — searches and books flights for customers."""
        response = flight_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    flight_assistant.tools = [search_flights, book_flight]  # type: ignore[attr-defined]

    def car_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Car rental assistant — searches and reserves rental cars for customers."""
        response = car_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    car_assistant.tools = [search_cars, reserve_car]  # type: ignore[attr-defined]

    def hotel_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Hotel assistant — searches and books hotel rooms for customers."""
        response = hotel_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    hotel_assistant.tools = [search_hotels, book_hotel]  # type: ignore[attr-defined]

    def excursion_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Excursion assistant — searches and books excursions for customers."""
        response = excursion_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    excursion_assistant.tools = [search_excursions, book_excursion]  # type: ignore[attr-defined]

    def route_primary(state: CustomerSupportState) -> str:
        """Route from primary assistant to the right specialist."""
        return state.get("next", "__end__")

    def route_specialist(state: CustomerSupportState) -> str:
        """Route from a specialist back to primary or end."""
        return state.get("next", "__end__")

    graph = StateGraph(CustomerSupportState)
    graph.add_node("primary_assistant", primary_assistant)
    graph.add_node("flight_assistant", flight_assistant)
    graph.add_node("car_assistant", car_assistant)
    graph.add_node("hotel_assistant", hotel_assistant)
    graph.add_node("excursion_assistant", excursion_assistant)

    graph.set_entry_point("primary_assistant")
    graph.add_conditional_edges(
        "primary_assistant",
        route_primary,
        {
            "flight_assistant": "flight_assistant",
            "car_assistant": "car_assistant",
            "hotel_assistant": "hotel_assistant",
            "excursion_assistant": "excursion_assistant",
            "__end__": END,
        },
    )
    for specialist in (
        "flight_assistant",
        "car_assistant",
        "hotel_assistant",
        "excursion_assistant",
    ):
        graph.add_conditional_edges(
            specialist,
            route_specialist,
            {
                "primary_assistant": "primary_assistant",
                "__end__": END,
            },
        )

    return graph.compile()
