"""Defensive guardrails for agentsec.

Standalone protective components that implement the patterns recommended by
probe remediations. Usable without running a scan.
"""

from agentsec.guardrails.credential_isolator import CredentialIsolator
from agentsec.guardrails.input_boundary import InjectionDetectedError, InputBoundaryEnforcer

__all__ = ["CredentialIsolator", "InjectionDetectedError", "InputBoundaryEnforcer"]
