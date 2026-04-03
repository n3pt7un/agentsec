"""Configuration models for agentsec scan runs."""

from enum import StrEnum

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class DetectionMode(StrEnum):
    """Strategy used by probes to decide whether a response is vulnerable."""

    MARKER_THEN_LLM = "marker_then_llm"
    LLM_ONLY = "llm_only"


class ScanConfig(BaseSettings):
    """Configuration for a scan run.

    All fields can be set via environment variables prefixed with AGENTSEC_.
    Example: AGENTSEC_VERBOSE=true
    """

    model_config = {"env_prefix": "AGENTSEC_", "env_file": ".env"}

    categories: list[str] | None = Field(
        default=None, description="OWASP categories to test (None = all)"
    )
    probes: list[str] | None = Field(
        default=None, description="Specific probe IDs to run (None = all)"
    )
    verbose: bool = False
    timeout_per_probe: int = Field(default=120, description="Max seconds per probe")
    smart: bool = Field(default=False, description="Use LLM for smart payloads and detection")
    llm_model: str = Field(
        default="anthropic/claude-sonnet-4.6", description="Model for payload generation"
    )
    openrouter_api_key: str | None = Field(
        default=None, description="OpenRouter API key for smart mode"
    )
    output_file: str | None = Field(default=None, description="Write findings to this file")
    output_format: str = Field(
        default="markdown", description="Report format: markdown, html, json, sarif"
    )
    detection_confidence_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Minimum LLM confidence to classify a response as vulnerable (smart mode only)",
    )
    fallback_llm_model: str | None = Field(
        default=None,
        description="Model used for Tier 3 payload generation if primary model refuses",
    )
    pricing_data: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description=(
            "Inline model pricing (input_per_1m / output_per_1m). "
            "Takes precedence over agentsec-pricing.yaml. "
            "Keys are model IDs."
        ),
    )
    detection_mode: DetectionMode = Field(
        default=DetectionMode.MARKER_THEN_LLM,
        description=(
            "Detection strategy: 'marker_then_llm' (default) runs a fast marker check "
            "first and falls back to LLM; 'llm_only' skips the marker check entirely. "
            "'llm_only' requires smart=True."
        ),
    )

    @model_validator(mode="after")
    def _validate_detection_mode(self) -> "ScanConfig":
        if self.detection_mode == DetectionMode.LLM_ONLY and not self.smart:
            raise ValueError(
                "detection_mode='llm_only' requires smart=True "
                "(an LLM provider must be configured)"
            )
        return self
