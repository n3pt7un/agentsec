"""Configuration models for agentsec scan runs."""

from pydantic import Field
from pydantic_settings import BaseSettings


class ScanConfig(BaseSettings):
    """Configuration for a scan run.

    All fields can be set via environment variables prefixed with AGENTSEC_.
    Example: AGENTSEC_VERBOSE=true
    """

    model_config = {"env_prefix": "AGENTSEC_"}

    categories: list[str] | None = Field(
        default=None, description="OWASP categories to test (None = all)"
    )
    probes: list[str] | None = Field(
        default=None, description="Specific probe IDs to run (None = all)"
    )
    verbose: bool = False
    timeout_per_probe: int = Field(default=120, description="Max seconds per probe")
    llm_provider: str = Field(
        default="anthropic", description="LLM provider for payload generation"
    )
    llm_model: str = Field(
        default="claude-sonnet-4-20250514", description="Model for payload generation"
    )
    output_file: str | None = Field(default=None, description="Write findings to this file")
    output_format: str = Field(
        default="markdown", description="Report format: markdown, html, json, sarif"
    )
