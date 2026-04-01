"""Core finding models for agentsec scan results."""

from datetime import UTC, datetime
from enum import StrEnum

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


class Evidence(BaseModel):
    """Concrete proof that a vulnerability exists."""

    attack_input: str = Field(description="The exact input/payload sent")
    target_agent: str = Field(description="Which agent received the attack")
    agent_response: str = Field(description="The agent's actual response")
    additional_context: str | None = Field(
        default=None, description="Extra details about the attack chain"
    )


class Remediation(BaseModel):
    """Actionable fix for a vulnerability."""

    summary: str = Field(description="One-line description of the fix")
    code_before: str | None = Field(default=None, description="Vulnerable code pattern")
    code_after: str | None = Field(default=None, description="Fixed code pattern")
    architecture_note: str | None = Field(
        default=None, description="Architectural recommendation"
    )
    references: list[str] = Field(default_factory=list, description="Links to OWASP/docs")


class Finding(BaseModel):
    """Result of a single probe execution."""

    probe_id: str
    probe_name: str
    category: OWASPCategory
    status: FindingStatus
    severity: Severity
    description: str = Field(description="What the probe tested")
    evidence: Evidence | None = Field(
        default=None, description="Proof of vulnerability (None if resistant)"
    )
    blast_radius: str | None = Field(
        default=None, description="What downstream components are affected"
    )
    remediation: Remediation
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int | None = Field(default=None, description="Probe execution time")
    tags: list[str] = Field(default_factory=list)
