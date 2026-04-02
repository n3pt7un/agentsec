"""Markdown report generator for agentsec scan results."""

from __future__ import annotations

from datetime import UTC

from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.scanner import ScanResult

# Human-readable names for OWASP categories.
_CATEGORY_NAMES: dict[str, str] = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Supply Chain Vulnerabilities",
    "ASI05": "Output & Impact Control Failures",
    "ASI06": "Memory & Context Manipulation",
    "ASI07": "Multi-Agent Orchestration Exploitation",
    "ASI08": "Uncontrolled Autonomous Execution",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agent Behavior",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "\U0001f534",  # 🔴
    "high": "\U0001f7e0",  # 🟠
    "medium": "\U0001f7e1",  # 🟡
    "low": "\U0001f535",  # 🔵
    "info": "\u2139\ufe0f",  # ℹ️
}


def generate_markdown(result: ScanResult) -> str:
    """Generate a full markdown report from a ScanResult.

    Args:
        result: The scan result to render.

    Returns:
        A complete markdown string.
    """
    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────
    lines.append("# agentsec Scan Report\n")
    lines.append(f"**Target:** {result.target or 'unknown'}")
    lines.append(f"**Date:** {result.started_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Duration:** {_format_duration(result.duration_ms)}")
    vuln_count = result.vulnerable_count
    partial_count = sum(1 for f in result.findings if f.status == FindingStatus.PARTIAL)
    lines.append(
        f"**Probes run:** {result.total_probes} | "
        f"**Findings:** {vuln_count + partial_count} | "
        f"**Critical:** {result.critical_count} | "
        f"**High:** {_count_severity(result, Severity.HIGH)}"
    )

    # ── Detection mode ──────────────────────────────────────────────
    if result.smart:
        lines.append(
            f"**Detection:** Smart · confidence threshold: {result.detection_confidence_threshold} "
            f"· 3-tier payload retry"
        )
    else:
        lines.append("**Detection:** Offline (marker-only)")
    lines.append("")

    # ── Agents discovered ───────────────────────────────────────────
    if result.agents_discovered:
        lines.append("## Agents Discovered\n")
        lines.append("| Agent | Role | Tools | Downstream |")
        lines.append("|-------|------|-------|------------|")
        for agent in result.agents_discovered:
            tools = ", ".join(agent.tools) if agent.tools else "—"
            downstream = ", ".join(agent.downstream_agents) if agent.downstream_agents else "—"
            lines.append(f"| {agent.name} | {agent.role or '—'} | {tools} | {downstream} |")
        lines.append("")

    # ── Summary table ───────────────────────────────────────────────
    categories_seen = _categories_in_order(result)
    if categories_seen:
        lines.append("## Summary\n")
        lines.append("| Category | Probes | Vulnerable | Resistant |")
        lines.append("|----------|--------|------------|-----------|")
        for cat in categories_seen:
            cat_findings = [f for f in result.findings if f.category == cat]
            n_vuln = sum(
                1
                for f in cat_findings
                if f.status in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL)
            )
            n_resist = sum(1 for f in cat_findings if f.status == FindingStatus.RESISTANT)
            cat_label = f"{cat.value} {_CATEGORY_NAMES.get(cat.value, '')}"
            vuln_display = f"{n_vuln} \u26a0\ufe0f" if n_vuln else "0 \u2705"
            resist_display = f"{n_resist} \u2705" if n_resist else "0"
            lines.append(
                f"| {cat_label} | {len(cat_findings)} | {vuln_display} | {resist_display} |"
            )
        lines.append("")

    # ── Detailed findings ───────────────────────────────────────────
    actionable = [
        f for f in result.findings if f.status in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL)
    ]
    resistant_count = sum(1 for f in result.findings if f.status == FindingStatus.RESISTANT)

    if actionable:
        lines.append("## Findings\n")
        for finding in actionable:
            emoji = _SEVERITY_EMOJI.get(finding.severity.value, "")
            lines.append(f"### {emoji} {finding.severity.value.upper()}: {finding.probe_id}\n")
            lines.append(f"**{finding.probe_name}**\n")
            lines.append(f"{finding.description}\n")

            if finding.evidence:
                lines.append("#### Evidence\n")
                lines.append(f"- **Attack input:** `{finding.evidence.attack_input}`")
                lines.append(f"- **Target agent:** {finding.evidence.target_agent}")
                lines.append(f"- **Agent response:** `{finding.evidence.agent_response}`")
                if finding.evidence.additional_context:
                    lines.append(f"- **Context:** {finding.evidence.additional_context}")
                lines.append("")

            if finding.blast_radius:
                lines.append(f"**Blast radius:** {finding.blast_radius}\n")

            lines.append("#### Remediation\n")
            lines.append(f"{finding.remediation.summary}\n")
            if finding.remediation.code_before:
                lines.append("**Before:**")
                lines.append(f"```python\n{finding.remediation.code_before}\n```\n")
            if finding.remediation.code_after:
                lines.append("**After:**")
                lines.append(f"```python\n{finding.remediation.code_after}\n```\n")
            if finding.remediation.architecture_note:
                lines.append(f"> {finding.remediation.architecture_note}\n")
            lines.append("---\n")

    if resistant_count:
        lines.append(f"**{resistant_count} probe(s)** returned RESISTANT — no action needed.\n")

    return "\n".join(lines)


# ── Helpers ─────────────────────────────────────────────────────────


def _format_duration(ms: int) -> str:
    """Format milliseconds as human-friendly duration."""
    secs = ms / 1000
    if secs < 60:
        return f"{secs:.1f}s"
    minutes = int(secs // 60)
    remainder = secs % 60
    return f"{minutes}m {remainder:.0f}s"


def _count_severity(result: ScanResult, severity: Severity) -> int:
    """Count vulnerable findings of a given severity."""
    return sum(1 for f in result.vulnerabilities if f.severity == severity)


def _categories_in_order(result: ScanResult) -> list[OWASPCategory]:
    """Return unique categories in order of appearance."""
    seen: set[OWASPCategory] = set()
    ordered: list[OWASPCategory] = []
    for f in result.findings:
        if f.category not in seen:
            seen.add(f.category)
            ordered.append(f.category)
    return ordered
