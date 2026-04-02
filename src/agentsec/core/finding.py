"""Core finding models for agentsec scan results."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Result status of a probe execution."""

    VULNERABLE = "vulnerable"
    RESISTANT = "resistant"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"


class OWASPCategory(StrEnum):
    """OWASP Top 10 for Agentic Applications (2026) categories."""

    ASI01 = "ASI01"  # Agent Goal Hijacking
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Identity & Privilege Abuse
    ASI04 = "ASI04"  # Supply Chain Vulnerabilities
    ASI05 = "ASI05"  # Output & Impact Control Failures
    ASI06 = "ASI06"  # Memory & Context Manipulation
    ASI07 = "ASI07"  # Multi-Agent Orchestration Exploitation
    ASI08 = "ASI08"  # Uncontrolled Autonomous Execution
    ASI09 = "ASI09"  # Human-Agent Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agent Behavior


class LLMUsage(BaseModel):
    """Token usage record for a single LLM API call."""

    model: str = Field(description="Full model identifier, e.g. 'anthropic/claude-sonnet-4-6'")
    role: Literal["payload", "detection"] = Field(
        description="payload = PayloadGenerator call; detection = VulnerabilityDetector call"
    )
    input_tokens: int
    output_tokens: int


class Evidence(BaseModel):
    """Concrete proof that a vulnerability exists."""

    attack_input: str = Field(description="The exact input/payload sent")
    target_agent: str = Field(description="Which agent received the attack")
    agent_response: str = Field(description="The agent's actual response")
    additional_context: str | None = Field(
        default=None, description="Extra details about the attack chain"
    )
    detection_method: Literal["marker", "llm"] = Field(
        default="marker",
        description="How vulnerability was detected: marker | llm",
    )


class Remediation(BaseModel):
    """Actionable fix for a vulnerability."""

    summary: str = Field(description="One-line description of the fix")
    code_before: str | None = Field(default=None, description="Vulnerable code pattern")
    code_after: str | None = Field(default=None, description="Fixed code pattern")
    architecture_note: str | None = Field(default=None, description="Architectural recommendation")
    references: list[str] = Field(default_factory=list, description="Links to OWASP/docs")


class FindingOverride(BaseModel):
    """Analyst-authored override for a single finding's automated status."""

    new_status: FindingStatus
    original_status: FindingStatus
    reason: str = Field(min_length=1, description="Required justification for the override")
    overridden_by: str = Field(default="analyst", description="Actor who applied the override")
    overridden_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    compliance_flag: Literal[True] = True


class Finding(BaseModel):
    """Result of a single probe execution."""

    probe_id: str
    probe_name: str
    category: OWASPCategory
    status: FindingStatus
    severity: Severity
    description: str = Field(description="What the probe tested")
    evidence: Evidence | None = Field(
        default=None,
        description=(
            "Interaction log: always populated when the probe ran "
            "(vulnerable or resistant). None only for skipped/error."
        ),
    )
    blast_radius: str | None = Field(
        default=None, description="What downstream components are affected"
    )
    remediation: Remediation
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int | None = Field(default=None, description="Probe execution time")
    tags: list[str] = Field(default_factory=list)
    override: FindingOverride | None = Field(
        default=None,
        description="Analyst override applied after automated scan. None = no override.",
    )
    llm_usage: list[LLMUsage] = Field(
        default_factory=list,
        description="Token usage records for all LLM calls made during this probe.",
    )
