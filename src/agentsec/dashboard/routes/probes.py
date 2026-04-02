"""Probe listing endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from agentsec.probes.registry import ProbeRegistry

router = APIRouter(prefix="/api/probes", tags=["probes"])


@router.get("")
async def list_probes() -> dict:
    """List all registered probes with metadata."""
    registry = ProbeRegistry()
    registry.discover_probes()
    probes = []
    for meta in registry.list_all():
        probes.append(
            {
                "id": meta.id,
                "name": meta.name,
                "category": meta.category.value,
                "severity": meta.default_severity.value,
                "description": meta.description,
                "tags": meta.tags,
            }
        )
    return {"probes": probes}
