"""Override routes — allow analysts to manually override finding statuses."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agentsec.core.finding import FindingOverride, FindingStatus

router = APIRouter(prefix="/api/scans", tags=["overrides"])

_store = None


def configure(store) -> None:
    """Inject the store dependency from app lifespan."""
    global _store
    _store = store


class OverrideRequest(BaseModel):
    new_status: FindingStatus
    reason: str = Field(min_length=1)
    overridden_by: str = "analyst"


@router.post("/{scan_id}/findings/{probe_id}/override")
async def create_override(
    scan_id: str,
    probe_id: str,
    body: OverrideRequest,
) -> dict:
    """Apply or replace an analyst override on a specific finding."""
    result = _store.load(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    original = next((f for f in result.findings if f.probe_id == probe_id), None)
    if original is None:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {probe_id!r} not in scan {scan_id!r}",
        )

    override = FindingOverride(
        new_status=body.new_status,
        original_status=original.status,
        reason=body.reason,
        overridden_by=body.overridden_by,
    )
    updated = _store.apply_override(scan_id, probe_id, override)
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to persist override")

    updated_finding = next(f for f in updated.findings if f.probe_id == probe_id)
    return updated_finding.model_dump(mode="json")


@router.delete("/{scan_id}/findings/{probe_id}/override")
async def delete_override(
    scan_id: str,
    probe_id: str,
) -> dict:
    """Remove an analyst override, restoring the automated status."""
    result = _store.remove_override(scan_id, probe_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No override found for finding {probe_id!r} in scan {scan_id!r}",
        )
    return {"deleted": True, "scan_id": scan_id, "probe_id": probe_id}
