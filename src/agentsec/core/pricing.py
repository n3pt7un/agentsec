"""Pricing table for LLM cost estimation."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import BaseModel

from agentsec.core.finding import LLMUsage

logger = logging.getLogger(__name__)

_DEFAULT_PRICING_FILE = Path("agentsec-pricing.yaml")


class ModelPricing(BaseModel):
    """Per-token pricing for a single model."""

    input_per_1m: float
    output_per_1m: float


class PricingTable(BaseModel):
    """Token pricing indexed by model identifier."""

    models: dict[str, ModelPricing] = {}

    @classmethod
    def load(cls, path: Path) -> PricingTable:
        """Load pricing from a YAML file. Returns an empty table if the file is absent."""
        if not path.exists():
            return cls()
        try:
            data = yaml.safe_load(path.read_text())
            return cls.model_validate(data or {})
        except Exception:
            logger.warning("Failed to load pricing file %s", path, exc_info=True)
            return cls()

    def compute_cost(self, usage_list: list[LLMUsage]) -> float:
        """Sum the cost of all LLM calls. Models not in the table contribute $0."""
        total = 0.0
        for u in usage_list:
            pricing = self.models.get(u.model)
            if pricing is None:
                continue
            total += u.input_tokens * pricing.input_per_1m / 1_000_000
            total += u.output_tokens * pricing.output_per_1m / 1_000_000
        return total


def load_pricing(
    pricing_data: dict | None = None,
    pricing_file: Path | None = None,
) -> PricingTable | None:
    """Load a PricingTable from inline data, an explicit file, or the default file.

    Returns None if no pricing source is available.
    """
    if pricing_data:
        return PricingTable.model_validate({"models": pricing_data})
    if pricing_file:
        return PricingTable.load(pricing_file)
    if _DEFAULT_PRICING_FILE.exists():
        return PricingTable.load(_DEFAULT_PRICING_FILE)
    return None
