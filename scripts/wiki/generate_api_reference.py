#!/usr/bin/env python3
"""Generate wiki/reference/API-*.md from module docstrings."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _header(name: str) -> str:
    return (
        "<!-- AUTO-GENERATED — do not edit directly. "
        "Re-run scripts/wiki/generate_api_reference.py -->\n\n"
        f"# {name}\n"
    )


def _class_section(cls) -> str:
    lines: list[str] = []
    doc = inspect.getdoc(cls) or ""
    lines.append(f"## `{cls.__name__}`\n")
    if doc:
        lines.append(doc + "\n")

    if hasattr(cls, "model_fields"):
        lines.append("### Fields\n")
        lines.append("| Field | Type | Default | Description |")
        lines.append("|-------|------|---------|-------------|")
        for field_name, field_info in cls.model_fields.items():
            annotation = field_info.annotation
            type_str = getattr(annotation, "__name__", str(annotation))
            default = field_info.default
            default_repr = repr(default)
            if "PydanticUndefined" in default_repr or default is inspect.Parameter.empty:
                default_str = "*(required)*"
            else:
                default_str = f"`{default_repr}`"
            desc = field_info.description or ""
            lines.append(f"| `{field_name}` | `{type_str}` | {default_str} | {desc} |")
        lines.append("")

    methods = [
        (name, obj)
        for name, obj in inspect.getmembers(cls, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]
    if methods:
        lines.append("### Methods\n")
        for method_name, method in methods:
            sig = str(inspect.signature(method))
            doc = inspect.getdoc(method) or ""
            lines.append(f"#### `{method_name}{sig}`\n")
            if doc:
                lines.append(doc + "\n")

    return "\n".join(lines)


def write_page(out_path: Path, content: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)
    print(f"Written {out_path}")


def generate_base_probe(wiki_ref: Path) -> None:
    from agentsec.core.probe_base import BaseProbe, ProbeMetadata
    content = _header("API: BaseProbe")
    content += "\nBase class and metadata for all agentsec probes. Source: `src/agentsec/core/probe_base.py`\n\n"
    content += _class_section(ProbeMetadata)
    content += "\n---\n\n"
    content += _class_section(BaseProbe)
    write_page(wiki_ref / "API-BaseProbe.md", content)


def generate_base_adapter(wiki_ref: Path) -> None:
    from agentsec.adapters.base import AbstractAdapter, AdapterCapabilities, AgentInfo
    content = _header("API: BaseAdapter")
    content += "\nAbstract adapter interface. Source: `src/agentsec/adapters/base.py`\n\n"
    content += _class_section(AgentInfo)
    content += "\n---\n\n"
    content += _class_section(AdapterCapabilities)
    content += "\n---\n\n"
    content += _class_section(AbstractAdapter)
    write_page(wiki_ref / "API-BaseAdapter.md", content)


def generate_finding(wiki_ref: Path) -> None:
    from agentsec.core.finding import (
        Evidence,
        Finding,
        FindingOverride,
        FindingStatus,
        LLMUsage,
        OWASPCategory,
        Remediation,
        Severity,
    )
    content = _header("API: Finding")
    content += "\nCore finding models. Source: `src/agentsec/core/finding.py`\n\n"
    for cls in (Severity, FindingStatus, OWASPCategory, LLMUsage, Evidence, Remediation, FindingOverride, Finding):
        content += _class_section(cls) + "\n---\n\n"
    write_page(wiki_ref / "API-Finding.md", content)


def generate_scan_config(wiki_ref: Path) -> None:
    from agentsec.core.config import DetectionMode, ScanConfig
    content = _header("API: ScanConfig")
    content += "\nScan configuration model. Source: `src/agentsec/core/config.py`\n\n"
    content += "All fields can be set via `AGENTSEC_<FIELD>` environment variables.\n\n"
    content += _class_section(DetectionMode)
    content += "\n---\n\n"
    content += _class_section(ScanConfig)
    write_page(wiki_ref / "API-ScanConfig.md", content)


def generate_llm_provider(wiki_ref: Path) -> None:
    from agentsec.llm.provider import ClassificationResult, LLMProvider, get_provider
    content = _header("API: LLMProvider")
    content += "\nLLM provider abstraction. Source: `src/agentsec/llm/provider.py`\n\n"
    content += _class_section(ClassificationResult)
    content += "\n---\n\n"
    content += _class_section(LLMProvider)
    content += "\n---\n\n"
    content += "## `get_provider(config: ScanConfig) -> LLMProvider`\n\n"
    content += (inspect.getdoc(get_provider) or "") + "\n"
    write_page(wiki_ref / "API-LLMProvider.md", content)


def generate_guardrails(wiki_ref: Path) -> None:
    from agentsec.guardrails.circuit_breaker import CircuitBreaker
    from agentsec.guardrails.credential_isolator import CredentialIsolator
    from agentsec.guardrails.execution_limiter import ExecutionLimiter
    from agentsec.guardrails.input_boundary import InputBoundaryEnforcer
    content = _header("API: Guardrails")
    content += "\nDefensive guardrail components. See [Guardrails usage guide](../using/Guardrails).\n\n"
    for cls in (InputBoundaryEnforcer, CredentialIsolator, CircuitBreaker, ExecutionLimiter):
        content += _class_section(cls) + "\n---\n\n"
    write_page(wiki_ref / "API-Guardrails.md", content)


def generate_reporters(wiki_ref: Path) -> None:
    from agentsec.reporters.json_report import generate_json
    from agentsec.reporters.markdown import generate_markdown
    from agentsec.reporters.sarif import generate_sarif
    content = _header("API: Reporters")
    content += "\nOutput format generators. Source: `src/agentsec/reporters/`\n\n"
    content += "Each reporter is a top-level function that accepts a `ScanResult` and returns a `str`.\n\n"
    for fn in (generate_markdown, generate_json, generate_sarif):
        sig = str(inspect.signature(fn))
        doc = inspect.getdoc(fn) or ""
        content += f"## `{fn.__name__}{sig}`\n\n{doc}\n\n---\n\n"
    write_page(wiki_ref / "API-Reporters.md", content)


def main() -> None:
    wiki_ref = Path(__file__).parent.parent.parent / "wiki" / "reference"
    generate_base_probe(wiki_ref)
    generate_base_adapter(wiki_ref)
    generate_finding(wiki_ref)
    generate_scan_config(wiki_ref)
    generate_llm_provider(wiki_ref)
    generate_guardrails(wiki_ref)
    generate_reporters(wiki_ref)
    print("API reference pages generated.")


if __name__ == "__main__":
    main()
